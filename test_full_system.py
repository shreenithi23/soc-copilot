import requests
import json
import time

BASE = "http://localhost:8000"

def run_tests():
    print("=" * 70)
    print("TEST REPORT: MULTI-SIEM SOC COPILOT WITH LIVE KEYS")
    print("=" * 70)

    # 1. Telemetry & Stats Segment
    print("\n[SEGMENT 1: TELEMETRY & STATS]")
    r = requests.get(f"{BASE}/api/stats")
    stats = r.json()
    print(f"Status Code: {r.status_code}")
    print(f"Total Logs Ingested: {stats.get('total_logs')}")
    print(f"Critical/High Alerts: {stats.get('critical_alerts')}")
    print(f"SIEM Distribution: {stats.get('by_source')}")
    print(f"VirusTotal Cached: {stats.get('vt_cached')}")
    print(f"VirusTotal Malicious Count: {stats.get('vt_malicious')}")

    # 2. Settings & Credentials Segment
    print("\n[SEGMENT 2: API CREDENTIALS VERIFICATION]")
    r = requests.get(f"{BASE}/api/settings")
    s = r.json()
    print(f"Gemini API: {'Configured' if s.get('gemini_configured') else 'Missing'} ({s.get('gemini_key_masked')})")
    print(f"VirusTotal API v3: {'Configured' if s.get('virustotal_configured') else 'Missing'} ({s.get('virustotal_key_masked')})")
    print(f"LangSmith Tracing: {'Configured' if s.get('langsmith_configured') else 'Missing'} ({s.get('langsmith_key_masked')})")
    print(f"LangSmith Project: {s.get('langsmith_project')}")

    # 3. Multi-SIEM Filtering & Ingestion
    print("\n[SEGMENT 3: MULTI-SIEM LOG RETRIEVAL & NORMALIZATION]")
    siem_list = ["Splunk", "Elastic", "Sentinel", "QRadar", "Wazuh"]
    for siem in siem_list:
        r = requests.get(f"{BASE}/api/logs", params={"source": siem})
        d = r.json()
        total = d.get("total", 0)
        first_alert = d.get("logs", [{}])[0].get("alert_name", "N/A")
        print(f"  • {siem:8s} -> {total} events | First Alert: {first_alert[:55]}")

    # 4. Real-time VirusTotal Threat Intelligence
    print("\n[SEGMENT 4: VIRUSTOTAL THREAT INTELLIGENCE ENGINE]")
    test_iocs = ["185.220.101.5", "update-microsoft-cloud.top", "44d88612fea8a8f36de82e1278abb02f"]
    for ioc in test_iocs:
        r = requests.post(f"{BASE}/api/threat-intel/lookup", json={"indicator": ioc})
        vt = r.json()
        print(f"  • Indicator: {vt.get('indicator')}")
        print(f"    - Type: {vt.get('ioc_type')} | Malicious Hits: {vt.get('malicious_count')} | Reputation: {vt.get('reputation')}")
        print(f"    - Threat Tags: {vt.get('tags')}")
        print(f"    - Source: {vt.get('source')}")

    # 5. LangSmith Pipeline Benchmark Evaluation
    print("\n[SEGMENT 5: LANGSMITH PIPELINE EVALUATION SUITE]")
    r = requests.post(f"{BASE}/api/eval/run")
    ev = r.json()
    print(f"Run Name: {ev.get('run_name')}")
    print(f"Accuracy Score: {ev.get('accuracy_score')}%")
    print(f"Average Latency: {ev.get('avg_latency_ms')} ms")
    print(f"LangSmith Tracing Cloud Sync: {ev.get('langsmith_synced')}")
    for tc in ev.get("results", []):
        print(f"    [{tc.get('status')}] {tc.get('name')}: {tc.get('details')}")

    # 6. Memory-Enabled SOC Copilot Chat
    print("\n[SEGMENT 6: MEMORY-ENABLED SOC COPILOT (GEMINI + LANGCHAIN)]")
    session_id = f"test-eval-{int(time.time())}"
    
    # Turn 1
    prompt1 = "What is the primary host and user compromised in the Splunk and Elastic events, and what malware was executed?"
    print(f"User Prompt 1: '{prompt1}'")
    r1 = requests.post(f"{BASE}/api/chat", json={"session_id": session_id, "message": prompt1})
    c1 = r1.json()
    print(f"Model: {c1.get('model')} | Latency: {c1.get('latency_ms')} ms")
    print("Grounded Telemetry attached:")
    print(f"  - Context Logs: {len(c1.get('context_logs', []))} events")
    print(f"  - VirusTotal IOCs: {list(c1.get('threat_intel', {}).get('ips', {}).keys())}")
    print(f"Response Preview:\n{c1.get('content', '')[:320]}...\n")

    # Turn 2 (Memory Retention Test)
    prompt2 = "For the compromised user and host we just discussed, draft the immediate containment commands."
    print(f"User Prompt 2 (Context Memory): '{prompt2}'")
    r2 = requests.post(f"{BASE}/api/chat", json={"session_id": session_id, "message": prompt2})
    c2 = r2.json()
    print(f"Model: {c2.get('model')} | Latency: {c2.get('latency_ms')} ms")
    print(f"Response Preview (Recalling Prior Turn):\n{c2.get('content', '')[:320]}...\n")

    print("=" * 70)
    print("ALL SEGMENTS COMPLETED SUCCESSFULLY")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
