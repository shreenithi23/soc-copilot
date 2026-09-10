import unittest
import os
import tempfile
from pathlib import Path

# Set test environment
os.environ["DATABASE_PATH"] = "test_soc.db"

from app.database import init_db, insert_logs, query_logs, get_stats, add_chat_message, get_session_history
from app.siem_parser import (
    parse_splunk_log,
    parse_elastic_ecs_log,
    parse_sentinel_log,
    parse_qradar_leef,
    parse_wazuh_log,
    ingest_dataset_content,
    normalize_severity
)
from app.threat_intel import extract_iocs, lookup_ioc
from app.llm_engine import process_soc_query
from app.langsmith_eval import run_langsmith_evaluation
from app.seed_data import generate_multi_siem_seed_logs

class TestSOCCopilot(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_01_severity_normalization(self):
        self.assertEqual(normalize_severity("CRITICAL"), "CRITICAL")
        self.assertEqual(normalize_severity("critical"), "CRITICAL")
        self.assertEqual(normalize_severity("High"), "HIGH")
        self.assertEqual(normalize_severity("9"), "CRITICAL")
        self.assertEqual(normalize_severity("1"), "LOW")
        self.assertEqual(normalize_severity("info"), "INFORMATIONAL")

    def test_02_multi_siem_parsing(self):
        # Splunk KV
        splunk_kv = "09/10/2026 sourcetype=cisco:asa src=10.0.0.1 dest=185.220.101.5 user=admin signature=Malware action=blocked"
        sp = parse_splunk_log(splunk_kv)
        self.assertEqual(sp["siem_source"], "Splunk")
        self.assertEqual(sp["src_ip"], "10.0.0.1")
        self.assertEqual(sp["dest_ip"], "185.220.101.5")

        # Elastic ECS
        ecs_json = {
            "@timestamp": "2026-09-10T12:00:00Z",
            "event": {"action": "dns_query", "severity": 6},
            "source": {"ip": "10.0.1.20", "port": 5353},
            "destination": {"ip": "1.1.1.1", "port": 53},
            "dns": {"question": {"name": "update-microsoft-cloud.top"}},
            "user": {"name": "jdoe"}
        }
        el = parse_elastic_ecs_log(ecs_json)
        self.assertEqual(el["siem_source"], "Elastic")
        self.assertEqual(el["domain"], "update-microsoft-cloud.top")
        self.assertEqual(el["severity"], "HIGH")

        # Sentinel
        sentinel_json = {
            "TimeGenerated": "2026-09-10T12:00:00Z",
            "AlertName": "Phishing Click",
            "AlertSeverity": "High",
            "SourceIP": "45.33.32.156",
            "CompromisedEntity": "alice@corp.com"
        }
        sen = parse_sentinel_log(sentinel_json)
        self.assertEqual(sen["siem_source"], "Sentinel")
        self.assertEqual(sen["src_ip"], "45.33.32.156")
        self.assertEqual(sen["user"], "alice@corp.com")

        # QRadar LEEF
        leef = "LEEF:2.0|IBM|QRadar|7.4|PassTheHash|sev=9\tsrc=10.0.4.15\tdst=194.26.29.112\tusr=Administrator"
        qr = parse_qradar_leef(leef)
        self.assertEqual(qr["siem_source"], "QRadar")
        self.assertEqual(qr["src_ip"], "10.0.4.15")
        self.assertEqual(qr["dest_ip"], "194.26.29.112")
        self.assertEqual(qr["severity"], "CRITICAL")

        # Wazuh
        wazuh_json = {
            "rule": {"id": 5710, "level": 8, "description": "SSH Brute-force success"},
            "agent": {"name": "srv01"},
            "data": {"srcip": "45.33.32.156", "dstuser": "root"}
        }
        wz = parse_wazuh_log(wazuh_json)
        self.assertEqual(wz["siem_source"], "Wazuh")
        self.assertEqual(wz["src_ip"], "45.33.32.156")
        self.assertEqual(wz["user"], "root")

    def test_03_ioc_extraction_and_threat_intel(self):
        text = "Observed traffic to 185.220.101.5 and 10.0.0.1 with hash 44d88612fea8a8f36de82e1278abb02f and domain update-microsoft-cloud.top"
        iocs = extract_iocs(text)
        self.assertIn("185.220.101.5", iocs["ips"])
        self.assertNotIn("10.0.0.1", iocs["ips"]) # RFC1918 private IP should be excluded
        self.assertIn("44d88612fea8a8f36de82e1278abb02f", iocs["hashes"])
        self.assertIn("update-microsoft-cloud.top", iocs["domains"])

        # Threat Intel Lookup
        intel = lookup_ioc("185.220.101.5", "ip")
        self.assertGreater(intel["malicious_count"], 0)
        self.assertEqual(intel["ioc_type"], "ip")

    def test_04_database_and_seed_data(self):
        count = generate_multi_siem_seed_logs()
        self.assertGreater(count, 0)

        stats = get_stats()
        self.assertGreaterEqual(stats["total_logs"], count)
        self.assertGreater(stats["critical_alerts"], 0)

        logs = query_logs(siem_source="Splunk", limit=5)
        self.assertGreater(len(logs["logs"]), 0)

    def test_05_conversational_memory_pipeline(self):
        session_id = "test-session-soc-01"
        turn1 = process_soc_query(session_id, "What critical alerts were reported for user victim_jdoe?")
        self.assertIn("content", turn1)
        self.assertEqual(turn1["session_id"], session_id)

        # Multi-turn check
        turn2 = process_soc_query(session_id, "What IP addresses were contacted during that incident?")
        self.assertIn("content", turn2)

        history = get_session_history(session_id)
        self.assertGreaterEqual(len(history), 4) # 2 user turns + 2 assistant turns

    def test_06_langsmith_evaluation_suite(self):
        eval_run = run_langsmith_evaluation()
        self.assertEqual(eval_run["accuracy_score"], 100.0)
        self.assertEqual(eval_run["passed_count"], 5)
        self.assertGreater(eval_run["avg_latency_ms"], 0)

if __name__ == "__main__":
    unittest.main()
