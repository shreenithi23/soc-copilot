import time
import os
import uuid
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

from app.config import settings
from app.database import record_eval_run, get_eval_runs, get_eval_run_by_id, delete_chat_session
from app.threat_intel import extract_iocs, lookup_ioc
from app.siem_parser import (
    normalize_severity, 
    parse_splunk_log, 
    parse_elastic_ecs_log, 
    parse_qradar_leef,
    parse_sentinel_log,
    parse_wazuh_log
)
from app.llm_engine import process_soc_query

logger = logging.getLogger("aegis.langsmith_eval")

BENCHMARK_VERSION = "1.0.0"
DATASET_NAME = "SOC-Copilot-Multi-SIEM-Threat-Intel-v1"

# ======================================================================
# 1. Standard SOC Evaluation Benchmark Definitions
# ======================================================================

EVALUATION_BENCHMARK = [
    {
        "id": "eval-01",
        "name": "IOC Extraction & Dissection",
        "category": "threat_intel",
        "description": "Verifies that public C2 IPs, malicious hashes, and phishing domains are reliably extracted from raw logs while excluding internal RFC1918 addresses.",
        "inputs": {
            "log_text": "Alert on internal host 10.0.1.20 contacting external C2 at 185.220.101.5 with payload hash 44d88612fea8a8f36de82e1278abb02f over update-microsoft-cloud.top"
        },
        "outputs": {
            "expected_ips": ["185.220.101.5"],
            "expected_hashes": ["44d88612fea8a8f36de82e1278abb02f"],
            "expected_domains": ["update-microsoft-cloud.top"],
            "excluded_internal_ips": ["10.0.1.20"]
        }
    },
    {
        "id": "eval-02",
        "name": "Multi-SIEM Severity Normalization",
        "category": "siem_parsing",
        "description": "Ensures source-specific severity representations from Splunk, Elastic, Sentinel, QRadar, and Wazuh normalize accurately to standard levels.",
        "inputs": {
            "sources": [
                {"siem": "Splunk", "raw": {"urgency": "critical", "signature": "Teardrop Attack"}},
                {"siem": "QRadar", "raw": "LEEF:2.0|IBM|QRadar|7.4|SecurityAlert|sev=8\tsrc=10.0.1.50\tdst=194.26.29.112"},
                {"siem": "Elastic", "raw": {"event": {"severity": 3, "category": "network"}, "message": "High flow"}},
                {"siem": "Sentinel", "raw": {"AlertSeverity": "High", "Tactics": "CredentialAccess"}},
                {"siem": "Wazuh", "raw": {"rule": {"level": 10, "description": "Shadow copy deleted"}}}
            ]
        },
        "outputs": {
            "expected_severities": {
                "Splunk": "CRITICAL",
                "QRadar": "HIGH",
                "Elastic": "MEDIUM",
                "Sentinel": "HIGH",
                "Wazuh": "CRITICAL"
            }
        }
    },
    {
        "id": "eval-03",
        "name": "VirusTotal Threat Scoring & Engine Consensus",
        "category": "threat_intel",
        "description": "Validates schema integrity, engine count thresholds (>40 engines = Malicious), and reputation score logic for threat indicators.",
        "inputs": {
            "indicator": "185.220.101.5",
            "ioc_type": "ip",
            "malicious_threshold": 40
        },
        "outputs": {
            "required_fields": [
                "indicator", "ioc_type", "malicious_count", "suspicious_count",
                "harmless_count", "undetected_count", "reputation", "tags"
            ],
            "expected_malicious_threshold": 40,
            "expected_min_reputation_negative": True
        }
    },
    {
        "id": "eval-04",
        "name": "Multi-Turn Conversational Memory Retention",
        "category": "memory",
        "description": "Executes a multi-turn investigation in an isolated session, evaluating conversational recall of compromised assets and cross-session isolation.",
        "inputs": {
            "turn_1": "Incident update: isolated server 172.31.99.88 was accessed by user test_sec_user42.",
            "turn_2": "What was the isolated server and affected user account we just noted?"
        },
        "outputs": {
            "expected_entities": ["172.31.99.88", "test_sec_user42"],
            "session_isolation_required": True
        }
    },
    {
        "id": "eval-05",
        "name": "QRadar LEEF Parsing Fidelity",
        "category": "siem_parsing",
        "description": "Evaluates IBM QRadar LEEF 1.0 and 2.0 parsing fidelity, attribute reordering, custom delimiters, and edge-case handling.",
        "inputs": {
            "primary_sample": "LEEF:2.0|IBM|QRadar|7.4|LateralMovement|sev=9\tsrc=10.0.1.50\tdst=194.26.29.112\tusr=jdoe\tmsg=Pass-the-hash detected",
            "edge_cases": [
                {
                    "name": "LEEF 1.0 Reordered & Tab Delimited",
                    "line": "LEEF:1.0|IBM|QRadar|7.3|AuthFail|usr=admin\tsev=7\tsrc=172.16.0.5\tdst=10.0.0.1\tmsg=Brute force",
                    "expected_src": "172.16.0.5",
                    "expected_dst": "10.0.0.1",
                    "expected_sev": "HIGH",
                    "expected_user": "admin"
                },
                {
                    "name": "LEEF Missing Optional Fields",
                    "line": "LEEF:2.0|IBM|QRadar|7.4|DNSAnomaly|sev=5\tsrc=10.0.2.1\tdst=8.8.8.8",
                    "expected_src": "10.0.2.1",
                    "expected_dst": "8.8.8.8",
                    "expected_sev": "MEDIUM",
                    "expected_user": None
                }
            ]
        },
        "outputs": {
            "expected_src": "10.0.1.50",
            "expected_dst": "194.26.29.112",
            "expected_sev": "CRITICAL",
            "expected_user": "jdoe",
            "expected_alert_name": "LateralMovement"
        }
    }
]

# ======================================================================
# 2. Deterministic Code-Based Evaluators
# ======================================================================

def compute_f1(extracted_set: set, expected_set: set) -> Tuple[float, float, float]:
    """Computes precision, recall, and F1 score for indicator sets."""
    if not extracted_set and not expected_set:
        return 1.0, 1.0, 1.0
    if not extracted_set or not expected_set:
        return 0.0, 0.0, 0.0
    
    tp = len(extracted_set & expected_set)
    precision = tp / len(extracted_set) if len(extracted_set) > 0 else 0.0
    recall = tp / len(expected_set) if len(expected_set) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return round(precision, 4), round(recall, 4), round(f1, 4)


def evaluate_ioc_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Executes and evaluates Test 1: IOC Extraction & Dissection."""
    start_t = time.time()
    input_text = case["inputs"]["log_text"]
    expected = case["outputs"]

    extracted = extract_iocs(input_text)
    latency_ms = round((time.time() - start_t) * 1000, 2)

    ext_ips = set(ip.strip() for ip in extracted.get("ips", []))
    ext_hashes = set(h.lower().strip() for h in extracted.get("hashes", []))
    ext_domains = set(d.lower().strip() for d in extracted.get("domains", []))

    exp_ips = set(ip.strip() for ip in expected["expected_ips"])
    exp_hashes = set(h.lower().strip() for h in expected["expected_hashes"])
    exp_domains = set(d.lower().strip() for d in expected["expected_domains"])
    excluded_ips = set(ip.strip() for ip in expected.get("excluded_internal_ips", []))

    # Internal IPs must NOT be in extracted public IPs
    internal_leaked = bool(ext_ips & excluded_ips)

    p_ip, r_ip, f1_ip = compute_f1(ext_ips, exp_ips)
    p_hash, r_hash, f1_hash = compute_f1(ext_hashes, exp_hashes)
    p_dom, r_dom, f1_dom = compute_f1(ext_domains, exp_domains)

    macro_f1 = round((f1_ip + f1_hash + f1_dom) / 3.0, 4)
    passed = (macro_f1 >= 1.0) and not internal_leaked

    details = (
        f"IP F1: {f1_ip} (P={p_ip}, R={r_ip}) | "
        f"Hash F1: {f1_hash} (P={p_hash}, R={r_hash}) | "
        f"Domain F1: {f1_dom} (P={p_dom}, R={r_dom}) | "
        f"Internal IP Filtered: {not internal_leaked}"
    )

    return {
        "id": case["id"],
        "name": case["name"],
        "category": case["category"],
        "status": "PASSED" if passed else "FAILED",
        "latency_ms": latency_ms,
        "metrics": {
            "f1_score": macro_f1,
            "ip_f1": f1_ip,
            "hash_f1": f1_hash,
            "domain_f1": f1_dom,
            "internal_filtered": not internal_leaked
        },
        "actual_output": {
            "ips": list(ext_ips),
            "hashes": list(ext_hashes),
            "domains": list(ext_domains)
        },
        "expected_output": {
            "ips": list(exp_ips),
            "hashes": list(exp_hashes),
            "domains": list(exp_domains)
        },
        "details": details
    }


def evaluate_severity_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Executes and evaluates Test 2: Multi-SIEM Severity Normalization using real parsers."""
    start_t = time.time()
    sources = case["inputs"]["sources"]
    expected_map = case["outputs"]["expected_severities"]

    per_source_results = {}
    mismatches = []

    for item in sources:
        siem = item["siem"]
        raw = item["raw"]
        norm_sev = "UNKNOWN"

        try:
            if siem == "Splunk":
                res = parse_splunk_log(raw)
                norm_sev = res.get("severity")
            elif siem == "QRadar":
                res = parse_qradar_leef(raw)
                norm_sev = res.get("severity")
            elif siem == "Elastic":
                res = parse_elastic_ecs_log(raw)
                norm_sev = res.get("severity")
            elif siem == "Sentinel":
                res = parse_sentinel_log(raw)
                norm_sev = res.get("severity")
            elif siem == "Wazuh":
                res = parse_wazuh_log(raw)
                norm_sev = res.get("severity")
        except Exception as e:
            norm_sev = f"ERROR: {str(e)}"

        expected_sev = expected_map.get(siem)
        is_correct = (norm_sev == expected_sev)
        per_source_results[siem] = {
            "normalized": norm_sev,
            "expected": expected_sev,
            "correct": is_correct
        }
        if not is_correct:
            mismatches.append(f"{siem} got '{norm_sev}', expected '{expected_sev}'")

    latency_ms = round((time.time() - start_t) * 1000, 2)
    correct_count = sum(1 for v in per_source_results.values() if v["correct"])
    accuracy = round(correct_count / len(sources), 4)
    passed = (accuracy == 1.0)

    details = (
        f"Correct: {correct_count}/{len(sources)} sources (Accuracy: {int(accuracy * 100)}%). "
        + (f"Mismatches: {', '.join(mismatches)}" if mismatches else "All 5 SIEM sources normalized accurately.")
    )

    return {
        "id": case["id"],
        "name": case["name"],
        "category": case["category"],
        "status": "PASSED" if passed else "FAILED",
        "latency_ms": latency_ms,
        "metrics": {
            "accuracy": accuracy,
            "correct_sources": correct_count,
            "total_sources": len(sources)
        },
        "actual_output": {k: v["normalized"] for k, v in per_source_results.items()},
        "expected_output": expected_map,
        "details": details
    }


def evaluate_vt_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Executes and evaluates Test 3: VirusTotal Threat Scoring & Engine Consensus."""
    start_t = time.time()
    indicator = case["inputs"]["indicator"]
    ioc_type = case["inputs"]["ioc_type"]
    threshold = case["inputs"]["malicious_threshold"]
    required_fields = case["outputs"]["required_fields"]

    vt_res = lookup_ioc(indicator, ioc_type)
    latency_ms = round((time.time() - start_t) * 1000, 2)

    # 1. Field presence validation
    missing_fields = [f for f in required_fields if f not in vt_res]
    fields_valid = len(missing_fields) == 0

    # 2. Engine counts validation (must be non-negative ints)
    mal_count = vt_res.get("malicious_count", 0)
    susp_count = vt_res.get("suspicious_count", 0)
    counts_valid = isinstance(mal_count, int) and mal_count >= 0 and isinstance(susp_count, int) and susp_count >= 0

    # 3. Threshold enforcement validation: high engine detections must reflect high-severity reputation
    threshold_met = mal_count >= threshold
    reputation = vt_res.get("reputation", 0)
    reputation_valid = (reputation < 0) if threshold_met else True

    passed = fields_valid and counts_valid and threshold_met and reputation_valid

    details = (
        f"Engines: {mal_count} malicious, {susp_count} suspicious | "
        f"Reputation: {reputation} | "
        f"Fields Verified: {len(required_fields) - len(missing_fields)}/{len(required_fields)} | "
        f"Threshold (>= {threshold}): {'MET' if threshold_met else 'NOT MET'}"
    )

    return {
        "id": case["id"],
        "name": case["name"],
        "category": case["category"],
        "status": "PASSED" if passed else "FAILED",
        "latency_ms": latency_ms,
        "metrics": {
            "malicious_engines": mal_count,
            "reputation": reputation,
            "threshold_met": threshold_met,
            "schema_fidelity": 1.0 if fields_valid else 0.0
        },
        "actual_output": {
            "malicious_count": mal_count,
            "reputation": reputation,
            "tags": vt_res.get("tags", []),
            "source": vt_res.get("source", "VirusTotal v3")
        },
        "expected_output": {
            "min_malicious_count": threshold,
            "negative_reputation_expected": True
        },
        "details": details
    }


def evaluate_memory_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes and evaluates Test 4: Multi-Turn Conversational Memory Recall.
    Uses actual application pipeline with an isolated session, verifies entity recall,
    and conducts a negative isolation test against another session.
    """
    start_t = time.time()
    session_a = f"eval-session-{uuid.uuid4().hex[:12]}"
    session_b = f"eval-session-{uuid.uuid4().hex[:12]}"
    
    turn_1 = case["inputs"]["turn_1"]
    turn_2 = case["inputs"]["turn_2"]
    expected_entities = case["outputs"]["expected_entities"]

    try:
        # Turn 1 in Session A
        resp_turn1 = process_soc_query(session_id=session_a, user_query=turn_1)

        # Turn 2 in Session A (requires recall of compromised host and user from Turn 1)
        resp_turn2 = process_soc_query(session_id=session_a, user_query=turn_2)
        reply_content_a = resp_turn2.get("content", "")

        # Check entity recall
        recalled_entities = [ent for ent in expected_entities if ent.lower() in reply_content_a.lower()]
        recall_ratio = len(recalled_entities) / len(expected_entities) if expected_entities else 0.0

        # Negative test: Session B query must NOT leak Session A's information
        resp_session_b = process_soc_query(session_id=session_b, user_query="What was the isolated server and affected user account we just noted?")
        reply_content_b = resp_session_b.get("content", "")
        leaked_to_b = any(ent.lower() in reply_content_b.lower() for ent in expected_entities)

        passed = (recall_ratio >= 1.0) and not leaked_to_b

        details = (
            f"Recalled: {recalled_entities}/{expected_entities} (Recall: {int(recall_ratio * 100)}%) | "
            f"Session Isolation Verified: {not leaked_to_b}"
        )
    except Exception as e:
        passed = False
        recalled_entities = []
        recall_ratio = 0.0
        leaked_to_b = False
        details = f"Memory evaluation pipeline error: {str(e)}"
    finally:
        # Teardown test sessions cleanly
        delete_chat_session(session_a)
        delete_chat_session(session_b)

    latency_ms = round((time.time() - start_t) * 1000, 2)

    return {
        "id": case["id"],
        "name": case["name"],
        "category": case["category"],
        "status": "PASSED" if passed else "FAILED",
        "latency_ms": latency_ms,
        "metrics": {
            "entity_recall": recall_ratio,
            "session_isolation": 1.0 if not leaked_to_b else 0.0
        },
        "actual_output": {
            "recalled_entities": recalled_entities,
            "cross_session_leak": leaked_to_b
        },
        "expected_output": {
            "expected_entities": expected_entities,
            "cross_session_leak": False
        },
        "details": details
    }


def evaluate_leef_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Executes and evaluates Test 5: QRadar LEEF Parsing Fidelity across primary and edge cases."""
    start_t = time.time()
    primary_sample = case["inputs"]["primary_sample"]
    expected_primary = case["outputs"]
    edge_cases = case["inputs"].get("edge_cases", [])

    # Evaluate primary sample
    parsed = parse_qradar_leef(primary_sample)
    primary_checks = [
        ("src_ip", parsed.get("src_ip"), expected_primary["expected_src"]),
        ("dest_ip", parsed.get("dest_ip"), expected_primary["expected_dst"]),
        ("severity", parsed.get("severity"), expected_primary["expected_sev"]),
        ("user", parsed.get("user"), expected_primary["expected_user"]),
        ("alert_name", parsed.get("alert_name"), expected_primary["expected_alert_name"])
    ]

    primary_passed = all(actual == expected for _, actual, expected in primary_checks)

    # Evaluate edge cases
    edge_results = []
    for ec in edge_cases:
        p = parse_qradar_leef(ec["line"])
        ec_passed = (
            p.get("src_ip") == ec["expected_src"] and
            p.get("dest_ip") == ec["expected_dst"] and
            p.get("severity") == ec["expected_sev"] and
            p.get("user") == ec["expected_user"]
        )
        edge_results.append(ec_passed)

    edge_passed = all(edge_results) if edge_results else True
    passed = primary_passed and edge_passed

    latency_ms = round((time.time() - start_t) * 1000, 2)

    details = (
        f"Primary LEEF: {'PASS' if primary_passed else 'FAIL'} "
        f"(src={parsed.get('src_ip')}, dst={parsed.get('dest_ip')}, sev={parsed.get('severity')}, user={parsed.get('user')}) | "
        f"Edge Cases ({len(edge_cases)}): {'ALL PASS' if edge_passed else 'FAIL'}"
    )

    return {
        "id": case["id"],
        "name": case["name"],
        "category": case["category"],
        "status": "PASSED" if passed else "FAILED",
        "latency_ms": latency_ms,
        "metrics": {
            "primary_fidelity": 1.0 if primary_passed else 0.0,
            "edge_cases_fidelity": 1.0 if edge_passed else 0.0
        },
        "actual_output": {
            "src_ip": parsed.get("src_ip"),
            "dest_ip": parsed.get("dest_ip"),
            "severity": parsed.get("severity"),
            "user": parsed.get("user"),
            "alert_name": parsed.get("alert_name")
        },
        "expected_output": expected_primary,
        "details": details
    }


# ======================================================================
# 3. LangSmith SDK Experiment Runner & Synchronization
# ======================================================================

def target_runner(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """Target execution function dispatched by LangSmith evaluate()."""
    case_id = inputs.get("case_id")
    if case_id == "eval-01":
        return extract_iocs(inputs.get("log_text", ""))
    elif case_id == "eval-02":
        results = {}
        for item in inputs.get("sources", []):
            siem = item["siem"]
            raw = item["raw"]
            if siem == "Splunk": results[siem] = parse_splunk_log(raw).get("severity")
            elif siem == "QRadar": results[siem] = parse_qradar_leef(raw).get("severity")
            elif siem == "Elastic": results[siem] = parse_elastic_ecs_log(raw).get("severity")
            elif siem == "Sentinel": results[siem] = parse_sentinel_log(raw).get("severity")
            elif siem == "Wazuh": results[siem] = parse_wazuh_log(raw).get("severity")
        return results
    elif case_id == "eval-03":
        return lookup_ioc(inputs.get("indicator", ""), inputs.get("ioc_type", "ip"))
    elif case_id == "eval-04":
        s_id = f"eval-run-{uuid.uuid4().hex[:8]}"
        try:
            process_soc_query(session_id=s_id, user_query=inputs.get("turn_1", ""))
            r2 = process_soc_query(session_id=s_id, user_query=inputs.get("turn_2", ""))
            return {"reply": r2.get("content", "")}
        finally:
            delete_chat_session(s_id)
    elif case_id == "eval-05":
        return parse_qradar_leef(inputs.get("primary_sample", ""))
    return {}


def sync_langsmith_dataset_and_experiment(eval_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Interacts with the real LangSmith platform via SDK:
    - Creates or retrieves versioned dataset `SOC-Copilot-Multi-SIEM-Threat-Intel-v1`
    - Ensures standard benchmark examples are present without duplicates
    - Runs official evaluate() experiment
    - Captures authentic experiment ID, experiment name, and URL
    """
    if not settings.is_langsmith_configured():
        return {
            "sync_status": "NOT_CONFIGURED",
            "experiment_name": None,
            "experiment_url": None,
            "error_details": "LANGCHAIN_API_KEY is not configured in environment."
        }

    try:
        from langsmith import Client, evaluate
        
        # Configure client with environment settings
        client = Client(
            api_key=settings.LANGCHAIN_API_KEY,
            api_url=settings.LANGCHAIN_ENDPOINT
        )

        # 1. Dataset Management: create or retrieve
        dataset = None
        if client.has_dataset(dataset_name=DATASET_NAME):
            dataset = client.read_dataset(dataset_name=DATASET_NAME)
        else:
            dataset = client.create_dataset(
                dataset_name=DATASET_NAME,
                description="SOC Copilot Multi-SIEM telemetry parsing, VirusTotal threat intelligence, and conversational memory benchmark.",
                metadata={"benchmark_version": BENCHMARK_VERSION, "project": settings.LANGCHAIN_PROJECT}
            )

        # 2. Populate examples if dataset is newly created or empty
        existing_examples = list(client.list_examples(dataset_id=dataset.id, limit=10))
        if len(existing_examples) < len(EVALUATION_BENCHMARK):
            existing_case_ids = {
                (ex.inputs.get("case_id")) for ex in existing_examples if isinstance(ex.inputs, dict)
            }
            inputs_list = []
            outputs_list = []
            metadata_list = []
            for item in EVALUATION_BENCHMARK:
                if item["id"] not in existing_case_ids:
                    inputs_with_meta = dict(item["inputs"])
                    inputs_with_meta["case_id"] = item["id"]
                    inputs_list.append(inputs_with_meta)
                    outputs_list.append(item["outputs"])
                    metadata_list.append({
                        "case_id": item["id"],
                        "name": item["name"],
                        "category": item["category"],
                        "version": BENCHMARK_VERSION
                    })
            if inputs_list:
                client.create_examples(
                    inputs=inputs_list,
                    outputs=outputs_list,
                    metadata=metadata_list,
                    dataset_id=dataset.id
                )

        # 3. Define LangSmith custom evaluator matching benchmark cases
        def benchmark_evaluator(run, example):
            case_id = (example.inputs or {}).get("case_id")
            actual = run.outputs or {}
            expected = example.outputs or {}

            if case_id == "eval-01":
                ext_ips = set(actual.get("ips", []))
                exp_ips = set(expected.get("expected_ips", []))
                p, r, f1 = compute_f1(ext_ips, exp_ips)
                return {"key": "benchmark_score", "score": f1, "comment": f"IOC Precision={p:.2f}, Recall={r:.2f}, F1={f1:.2f}"}

            elif case_id == "eval-02":
                expected_sevs = expected.get("expected_severities", {})
                correct = sum(1 for k, v in expected_sevs.items() if actual.get(k) == v)
                score = correct / len(expected_sevs) if expected_sevs else 0.0
                return {"key": "benchmark_score", "score": score, "comment": f"SIEM Normalization Accuracy: {score * 100:.0f}%"}

            elif case_id == "eval-03":
                mal_count = actual.get("malicious_count", 0)
                threshold = expected.get("expected_malicious_threshold", 40)
                score = 1.0 if mal_count >= threshold else 0.0
                return {"key": "benchmark_score", "score": score, "comment": f"VT Malicious engines: {mal_count} (>= {threshold})"}

            elif case_id == "eval-04":
                content = actual.get("reply", "")
                exp_ents = expected.get("expected_entities", [])
                recalled = sum(1 for e in exp_ents if e.lower() in content.lower())
                score = recalled / len(exp_ents) if exp_ents else 0.0
                return {"key": "benchmark_score", "score": score, "comment": f"Memory Recall: {recalled}/{len(exp_ents)} entities"}

            elif case_id == "eval-05":
                matches = (
                    actual.get("src_ip") == expected.get("expected_src") and
                    actual.get("dest_ip") == expected.get("expected_dst") and
                    actual.get("severity") == expected.get("expected_sev")
                )
                score = 1.0 if matches else 0.0
                return {"key": "benchmark_score", "score": score, "comment": f"QRadar LEEF Field Accuracy: {matches}"}

            return {"key": "benchmark_score", "score": 1.0, "comment": "Evaluated successfully"}

        # 4. Run genuine LangSmith Experiment
        experiment_results = evaluate(
            target_runner,
            data=DATASET_NAME,
            evaluators=[benchmark_evaluator],
            experiment_prefix=f"aegis-benchmark-v{BENCHMARK_VERSION.replace('.', '')}",
            description="SOC Copilot End-to-End Pipeline Verification",
            metadata={
                "benchmark_version": BENCHMARK_VERSION,
                "project": settings.LANGCHAIN_PROJECT,
                "dataset": DATASET_NAME,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            client=client,
            blocking=True,
            max_concurrency=1
        )

        exp_name = getattr(experiment_results, "experiment_name", f"aegis-benchmark-{int(time.time())}")
        exp_url = getattr(experiment_results, "url", None)
        if not exp_url and hasattr(experiment_results, "experiment_id"):
            exp_url = f"https://smith.langchain.com/o/default/datasets/{dataset.id}/experiments/{experiment_results.experiment_id}"

        return {
            "sync_status": "SYNCED",
            "experiment_name": exp_name,
            "experiment_url": exp_url,
            "error_details": None
        }

    except Exception as e:
        logger.warning(f"LangSmith experiment execution or sync failed: {e}")
        return {
            "sync_status": "FAILED",
            "experiment_name": None,
            "experiment_url": None,
            "error_details": f"Remote LangSmith operation failed: {str(e)[:250]}"
        }


# ======================================================================
# 4. Primary Public Pipeline Evaluation API
# ======================================================================

def run_langsmith_evaluation(sync_remote: bool = True) -> Dict[str, Any]:
    """
    Runs the complete SOC Copilot evaluation benchmark:
    1. Executes deterministic evaluators across all 5 benchmark cases
    2. Measures aggregate metrics (Accuracy, Latency, Passed/Failed counts)
    3. Traces and executes real LangSmith dataset and experiment run if configured
    4. Persists the complete report to local SQLite
    5. Returns truthful, structured report with live LangSmith experiment URL or failure reason
    """
    start_total_t = time.time()
    results = []
    
    # Execute Test 1: IOC Extraction
    results.append(evaluate_ioc_case(EVALUATION_BENCHMARK[0]))
    
    # Execute Test 2: Multi-SIEM Severity Normalization
    results.append(evaluate_severity_case(EVALUATION_BENCHMARK[1]))
    
    # Execute Test 3: VirusTotal Threat Scoring
    results.append(evaluate_vt_case(EVALUATION_BENCHMARK[2]))
    
    # Execute Test 4: Multi-Turn Memory Recall
    results.append(evaluate_memory_case(EVALUATION_BENCHMARK[3]))
    
    # Execute Test 5: QRadar LEEF Parsing Fidelity
    results.append(evaluate_leef_case(EVALUATION_BENCHMARK[4]))

    total_latency_ms = round((time.time() - start_total_t) * 1000, 2)
    total_tests = len(results)
    passed_count = sum(1 for r in results if r["status"] == "PASSED")
    accuracy_score = round((passed_count / total_tests) * 100.0, 1)
    avg_latency_ms = round(total_latency_ms / total_tests, 2)

    # Category breakdown metrics
    cat_counts = {}
    for r in results:
        cat = r["category"]
        if cat not in cat_counts:
            cat_counts[cat] = {"total": 0, "passed": 0}
        cat_counts[cat]["total"] += 1
        if r["status"] == "PASSED":
            cat_counts[cat]["passed"] += 1

    aggregate_metrics = {
        "accuracy_score": accuracy_score,
        "total_tests": total_tests,
        "passed_count": passed_count,
        "failed_count": total_tests - passed_count,
        "avg_latency_ms": avg_latency_ms,
        "total_latency_ms": total_latency_ms,
        "categories": {
            cat: {
                "accuracy": round((v["passed"] / v["total"]) * 100.0, 1),
                "passed": v["passed"],
                "total": v["total"]
            }
            for cat, v in cat_counts.items()
        }
    }

    # Remote LangSmith Synchronization
    remote_sync = {
        "sync_status": "NOT_CONFIGURED",
        "experiment_name": None,
        "experiment_url": None,
        "error_details": None
    }
    if sync_remote:
        remote_sync = sync_langsmith_dataset_and_experiment(results)

    now_utc = datetime.now(timezone.utc)
    now_str = now_utc.strftime("%Y-%m-%d %H:%M UTC")

    eval_id = f"eval-{uuid.uuid4().hex[:12]}"
    eval_data = {
        "id": eval_id,
        "run_id": eval_id,
        "run_name": f"Aegis SOC Benchmark - {now_str}",
        "dataset_name": DATASET_NAME,
        "benchmark_version": BENCHMARK_VERSION,
        "test_cases_count": total_tests,
        "passed_count": passed_count,
        "accuracy_score": accuracy_score,
        "avg_latency_ms": avg_latency_ms,
        "results": results,
        "aggregate_metrics": aggregate_metrics,
        "experiment_name": remote_sync.get("experiment_name"),
        "experiment_url": remote_sync.get("experiment_url"),
        "sync_status": remote_sync.get("sync_status", "NOT_CONFIGURED"),
        "error_details": remote_sync.get("error_details"),
        "completed_at": now_utc.isoformat(),
        "created_at": now_utc.isoformat(),
        # Backwards compatibility flags
        "langsmith_synced": (remote_sync.get("sync_status") == "SYNCED")
    }

    # Store in local SQLite evaluation history
    record_eval_run(eval_data)

    return eval_data
