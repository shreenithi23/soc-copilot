import json
import os
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.config import settings
from app.database import (
    get_recent_security_logs,
    query_logs,
    get_session_history,
    add_chat_message,
    get_or_create_session
)
from app.threat_intel import extract_iocs, batch_enrich_iocs, lookup_ioc

# LangChain imports
# pyrefly: ignore [missing-import]
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage

# Senior SOC Analyst System Prompt
SYSTEM_PROMPT = """You are the Lead Cybersecurity Incident Responder and Threat Hunting Copilot for a multi-tenant Security Operations Center (SOC).
You have real-time access to security logs from multiple SIEM tools:
- Splunk (CIM / KV / WinEventLog)
- Elastic / ELK (Elastic Common Schema ECS)
- Microsoft Sentinel (Azure SecurityAlert & Syslog)
- IBM QRadar (LEEF Format)
- Wazuh / OSSEC (Host IDS alerts)
- Real-time Threat Intelligence from VirusTotal v3 (IP, Domain, and Hash reputation)

Your responsibilities:
1. Retain context across multi-turn user questions (remember previously identified IOCs, compromised hosts, or alert timelines).
2. Correlate alerts across multiple SIEM tools to reconstruct the cyber attack chain (Initial Access -> Execution -> Persistence -> Lateral Movement -> Command & Control -> Impact).
3. Map every detected threat to the MITRE ATT&CK Framework (include Technique IDs like T1059, T1078, T1071).
4. Correlate with VirusTotal threat intelligence: highlight malicious engine detection ratios (e.g. 68/72 engines flagged) and threat categories.
5. Provide actionable, prioritized Incident Response (IR) steps: Immediate Containment, Eradication, and Defensive Hardening rules (e.g., Sigma, firewall rules, YARA).
6. Format your output with clear markdown headings, bullet points, code blocks for queries/commands, and threat severity badges [CRITICAL], [HIGH], [MEDIUM], [LOW].
"""

def build_soc_context(user_query: str) -> Dict[str, Any]:
    """Retrieve relevant SIEM logs and VirusTotal threat intel for context grounding."""
    # 1. Extract IOCs from query
    query_iocs = extract_iocs(user_query)
    
    # 2. Search logs related to query or fetch top critical/high security events
    relevant_logs = []
    if any([query_iocs["ips"], query_iocs["hashes"], query_iocs["domains"]]):
        search_term = (query_iocs["ips"] + query_iocs["hashes"] + query_iocs["domains"])[0]
        log_res = query_logs(search=search_term, limit=15)
        relevant_logs = log_res["logs"]
    
    if len(relevant_logs) < 5:
        # Augment with top high-severity events
        recent = get_recent_security_logs(limit=15)
        existing_ids = {l["id"] for l in relevant_logs}
        for r in recent:
            if r["id"] not in existing_ids:
                relevant_logs.append(r)
            if len(relevant_logs) >= 15:
                break

    # 3. Extract IOCs from the logs as well
    log_text_blob = " ".join([
        f"{l.get('src_ip', '')} {l.get('dest_ip', '')} {l.get('file_hash', '')} {l.get('domain', '')} {l.get('raw_log', '')}"
        for l in relevant_logs
    ])
    combined_iocs = extract_iocs(user_query + " " + log_text_blob)
    
    # 4. Enrich IOCs with VirusTotal
    enriched_intel = batch_enrich_iocs(combined_iocs)

    return {
        "logs": relevant_logs,
        "threat_intel": enriched_intel,
        "query_iocs": query_iocs
    }

def format_context_for_llm(context: Dict[str, Any]) -> str:
    """Format logs and threat intelligence into structured LLM context string."""
    lines = []
    lines.append("=== INGESTED MULTI-SIEM SECURITY LOGS ===")
    for idx, log in enumerate(context["logs"][:10], 1):
        lines.append(
            f"[{idx}] SIEM: {log.get('siem_source')} | Severity: {log.get('severity')} | Alert: {log.get('alert_name')} "
            f"| Time: {log.get('timestamp')} | Src: {log.get('src_ip')}:{log.get('src_port')} -> Dest: {log.get('dest_ip')}:{log.get('dest_port')} "
            f"| User: {log.get('user')} | Hash: {log.get('file_hash')} | Domain: {log.get('domain')}"
        )

    lines.append("\n=== VIRUSTOTAL REAL-TIME THREAT INTELLIGENCE ===")
    intel = context["threat_intel"]
    for ip, info in intel.get("ips", {}).items():
        if info.get("malicious_count", 0) > 0:
            lines.append(f"- IP {ip}: MALICIOUS (VT Detections: {info['malicious_count']}/{info['malicious_count'] + info['harmless_count'] + info['undetected_count']}) Tags: {', '.join(info.get('tags', []))}")

    for h, info in intel.get("hashes", {}).items():
        if info.get("malicious_count", 0) > 0:
            lines.append(f"- Hash {h}: MALICIOUS (VT Detections: {info['malicious_count']}) Engines: {list(info.get('engine_details', {}).values())[:3]}")

    for d, info in intel.get("domains", {}).items():
        if info.get("malicious_count", 0) > 0:
            lines.append(f"- Domain {d}: MALICIOUS (VT Detections: {info['malicious_count']}) Tags: {', '.join(info.get('tags', []))}")

    return "\n".join(lines)

def generate_heuristic_soc_response(user_query: str, history: List[Dict[str, Any]], context: Dict[str, Any]) -> str:
    """Intelligent fallback SOC reasoning engine when Gemini API key is not configured."""
    logs = context["logs"]
    intel = context["threat_intel"]
    
    malicious_ips = [ip for ip, info in intel.get("ips", {}).items() if info.get("malicious_count", 0) > 0]
    malicious_hashes = [h for h, info in intel.get("hashes", {}).items() if info.get("malicious_count", 0) > 0]
    malicious_domains = [d for d, info in intel.get("domains", {}).items() if info.get("malicious_count", 0) > 0]

    siem_sources = list(set([l.get("siem_source") for l in logs if l.get("siem_source")]))
    critical_alerts = [l for l in logs if l.get("severity") in ("CRITICAL", "HIGH")]

    resp = []
    resp.append("### 🛡️ SOC Incident Analysis & Threat Assessment\n")
    resp.append(f"**SIEM Telemetry Analyzed:** `{', '.join(siem_sources) if siem_sources else 'Multi-SIEM'}` | **Correlated Events:** `{len(logs)}` | **High/Critical Alerts:** `{len(critical_alerts)}`\n")

    # Conversation context reflection
    user_msgs = [m["content"] for m in history if m.get("role") == "user"]
    if user_msgs:
        prior_context = " | ".join(user_msgs)
        resp.append(f"> **Context Memory:** Continuing investigation retaining session conversation context: *\"{prior_context}\"*\n")

    # Threat Intelligence Findings
    resp.append("#### 🚨 VirusTotal Threat Intelligence Matches")
    if malicious_ips or malicious_hashes or malicious_domains:
        for ip in malicious_ips:
            info = intel["ips"][ip]
            resp.append(f"- **Host/C2 IP:** `{ip}` — 🔴 **{info['malicious_count']}/{info['malicious_count']+info['harmless_count']+info['undetected_count']} Security Vendors flagged as Malicious** (Tags: `{', '.join(info.get('tags', []))}`)")
        for h in malicious_hashes:
            info = intel["hashes"][h]
            resp.append(f"- **Malware Hash:** `{h}` — 🔴 **{info['malicious_count']} Security Vendors Flagged** (Known payload signature: `{list(info.get('engine_details', {}).values())[:2]}`)")
        for d in malicious_domains:
            info = intel["domains"][d]
            resp.append(f"- **Malicious Domain:** `{d}` — 🔴 **{info['malicious_count']} Security Vendors Flagged** (Tags: `{', '.join(info.get('tags', []))}`)")
    else:
        resp.append("- *No high-confidence public malicious indicators matched in the active query window. Baseline traffic inspection ongoing.*")

    # SIEM Findings & Kill Chain
    resp.append("\n#### 🔍 Correlated SIEM Attack Path")
    for idx, alert in enumerate(critical_alerts[:4], 1):
        resp.append(
            f"**Step {idx} [{alert.get('siem_source')} - {alert.get('severity')}]:** `{alert.get('alert_name')}`\n"
            f"- **Entity Involved:** User `{alert.get('user') or 'SYSTEM'}` | Source `{alert.get('src_ip') or 'N/A'}` ➔ Destination `{alert.get('dest_ip') or 'N/A'}`\n"
            f"- **Raw Evidence:** `{alert.get('raw_log')[:140]}...`"
        )

    # MITRE ATT&CK Matrix Mapping
    resp.append("\n#### 🗺️ MITRE ATT&CK Mapping")
    resp.append("| Phase | Technique ID | Technique Name | Detection SIEM |")
    resp.append("| :--- | :--- | :--- | :--- |")
    resp.append("| **Initial Access** | `T1566.002` | Spearphishing Link | Sentinel / Wazuh |")
    resp.append("| **Execution** | `T1059.001` | PowerShell Malicious Script | Splunk WinEventLog |")
    resp.append("| **Credential Access** | `T1003.001` | LSASS Memory Dump (Mimikatz) | Elastic ECS / Sysmon |")
    resp.append("| **Lateral Movement** | `T1550.002` | Pass the Hash | Splunk / QRadar LEEF |")
    resp.append("| **Command & Control** | `T1071.001` | Web Protocols / C2 Beaconing | QRadar / Suricata |")

    # Containment & Remediation Playbook
    resp.append("\n#### ⚡ Recommended SOC Containment Actions")
    if malicious_ips:
        resp.append(f"1. **Firewall Blocklist:** Immediately drop all ingress/egress connections to `{', '.join(malicious_ips)}` across perimeter firewalls.")
    else:
        resp.append("1. **Host Isolation:** Isolate affected workstation/server endpoints pending forensic image acquisition.")
    resp.append("2. **Credential Revocation:** Reset Kerberos/NTLM ticket sessions and enforce password reset with MFA re-enrollment for impacted accounts.")
    resp.append("3. **EDR Process Termination:** Invalidate active PowerShell child processes spawned under `wmiprvse.exe` or `svchost.exe`.")
    resp.append("4. **SIEM Threat Hunt Rule:** Deploy alert rule for cross-subnet SMB (TCP 445) and WinRM (TCP 5985) traffic.")

    resp.append("\n> [!TIP]\n> *Note: For autonomous reasoning powered by Gemini 2.5 Flash, ensure your `GEMINI_API_KEY` is configured in the Settings panel.*")

    return "\n".join(resp)

def process_soc_query(
    session_id: str,
    user_query: str,
    override_api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Main orchestration entrypoint:
    1. Manages conversational memory in SQLite
    2. Builds grounded context with SIEM logs & VirusTotal intel
    3. Executes LangChain pipeline with Gemini API or fallback
    4. Records response to SQLite session memory
    """
    session_id = get_or_create_session(session_id)
    start_time = time.time()

    # Step 1: Build context from SQLite logs & VirusTotal
    context = build_soc_context(user_query)

    # Step 2: Retrieve multi-turn conversation memory
    history = get_session_history(session_id, limit=10)

    # Step 3: Check for Gemini API key
    gemini_key = override_api_key or settings.GEMINI_API_KEY

    assistant_reply = ""
    model_name = "Gemini Flash (LangChain)" if gemini_key else "SOC Heuristic Reasoner"
    trace_id = f"trace-{int(time.time()*1000)}"

    if gemini_key:
        try:
            # pyrefly: ignore [missing-import]
            from langchain_google_genai import ChatGoogleGenerativeAI
            
            # Setup LangSmith tracing if key is configured
            if settings.LANGCHAIN_API_KEY:
                os.environ["LANGCHAIN_TRACING_V2"] = "true"
                os.environ["LANGCHAIN_API_KEY"] = settings.LANGCHAIN_API_KEY
                os.environ["LANGCHAIN_PROJECT"] = settings.LANGCHAIN_PROJECT

            model_name = "Gemini 3.6 Flash (LangChain)"
            llm = ChatGoogleGenerativeAI(
                model="gemini-3.6-flash",
                google_api_key=gemini_key,
                temperature=0.2,
                max_output_tokens=2048
            )

            # Assemble conversation messages with SQLite memory history
            messages = [SystemMessage(content=SYSTEM_PROMPT)]
            
            # Grounding context
            grounded_context_str = format_context_for_llm(context)
            context_injection = (
                f"Use the following real-time SIEM logs and VirusTotal threat intelligence to answer the SOC query:\n\n"
                f"{grounded_context_str}\n\n"
            )
            messages.append(SystemMessage(content=context_injection))

            # Add previous turns from memory
            for h in history[-6:]:
                if h["role"] == "user":
                    messages.append(HumanMessage(content=h["content"]))
                elif h["role"] == "assistant":
                    messages.append(AIMessage(content=h["content"]))

            # Add current user prompt
            messages.append(HumanMessage(content=user_query))

            # Run LangChain model
            response = llm.invoke(messages)
            if isinstance(response.content, list):
                text_parts = []
                for part in response.content:
                    if isinstance(part, dict) and "text" in part:
                        text_parts.append(part["text"])
                    elif isinstance(part, str):
                        text_parts.append(part)
                assistant_reply = "\n".join(text_parts)
            else:
                assistant_reply = str(response.content)
        except Exception as e:
            print(f"[Gemini LangChain Error] {e}")
            assistant_reply = generate_heuristic_soc_response(user_query, history, context)
            assistant_reply += f"\n\n*(Fell back to SOC Heuristic Engine due to API error: {str(e)[:100]})*"
            model_name = "SOC Heuristic Reasoner"
    else:
        assistant_reply = generate_heuristic_soc_response(user_query, history, context)

    latency_ms = round((time.time() - start_time) * 1000, 2)

    # Step 4: Persist user and assistant messages in SQLite memory
    add_chat_message(session_id, "user", user_query)
    msg_id = add_chat_message(
        session_id=session_id,
        role="assistant",
        content=assistant_reply,
        context_logs=context["logs"],
        threat_intel=context["threat_intel"]
    )

    return {
        "message_id": msg_id,
        "session_id": session_id,
        "role": "assistant",
        "content": assistant_reply,
        "model": model_name,
        "latency_ms": latency_ms,
        "trace_id": trace_id,
        "context_logs": context["logs"],
        "threat_intel": context["threat_intel"]
    }
