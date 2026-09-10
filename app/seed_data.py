import json
from datetime import datetime, timedelta, timezone
from app.database import insert_logs
from app.threat_intel import lookup_ioc

def generate_multi_siem_seed_logs():
    """Generates realistic APT & Ransomware attack scenario across 5 SIEM platforms."""
    base_time = datetime.now(timezone.utc)


    # 1. Splunk Logs (WinEventLog & Network)
    splunk_logs = [
        {
            "id": "splunk-evt-101",
            "siem_source": "Splunk",
            "timestamp": (base_time - timedelta(minutes=45)).isoformat(),
            "severity": "CRITICAL",
            "event_type": "WinEventLog:Security",
            "src_ip": "10.0.4.15",
            "dest_ip": "10.0.4.1",
            "src_port": 49210,
            "dest_port": 88,
            "user": "victim_jdoe",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f",
            "domain": "corp.internal",
            "alert_name": "Overpass the Hash / Kerberos Ticket Request",
            "details": {
                "EventCode": 4768,
                "TicketOptions": "0x40810010",
                "Status": "0x0",
                "Service_Name": "krbtgt",
                "ProcessName": "C:\\Windows\\System32\\lsass.exe",
                "CommandLine": "mimikatz.exe sekurlsa::logonpasswords"
            },
            "raw_log": "09/10/2026 08:15:00 AM EventCode=4768 ComputerName=WS-FIN-04.corp.internal User=victim_jdoe ServiceName=krbtgt TicketOptions=0x40810010 Status=0x0 Hash=44d88612fea8a8f36de82e1278abb02f"
        },
        {
            "id": "splunk-evt-102",
            "siem_source": "Splunk",
            "timestamp": (base_time - timedelta(minutes=40)).isoformat(),
            "severity": "HIGH",
            "event_type": "cisco:asa",
            "src_ip": "10.0.4.15",
            "dest_ip": "185.220.101.5",
            "src_port": 51220,
            "dest_port": 443,
            "user": "victim_jdoe",
            "file_hash": None,
            "domain": "update-microsoft-cloud.top",
            "alert_name": "Cisco ASA Outbound Connection to High-Risk IP",
            "details": {
                "action": "allowed",
                "bytes_transferred": 2048500,
                "protocol": "TCP",
                "firewall_zone": "Trust-to-Untrust"
            },
            "raw_log": "%ASA-6-302013: Built outbound TCP connection 982142 for outside:185.220.101.5/443 (185.220.101.5/443) to inside:10.0.4.15/51220 domain=update-microsoft-cloud.top bytes=2048500"
        },
        {
            "id": "splunk-evt-103",
            "siem_source": "Splunk",
            "timestamp": (base_time - timedelta(minutes=30)).isoformat(),
            "severity": "CRITICAL",
            "event_type": "suricata:alert",
            "src_ip": "10.0.4.15",
            "dest_ip": "185.220.101.5",
            "src_port": 51222,
            "dest_port": 8443,
            "user": "SYSTEM",
            "file_hash": None,
            "domain": "update-microsoft-cloud.top",
            "alert_name": "ET MALWARE Cobalt Strike Malleable C2 Beaconing Observed",
            "details": {
                "signature_id": 2028821,
                "signature": "ET MALWARE Cobalt Strike TeamServer Traffic",
                "category": "A Network Trojan was detected",
                "confidence": 9
            },
            "raw_log": "09/10/2026 08:30:12 [**] [1:2028821:4] ET MALWARE Cobalt Strike Malleable C2 Beaconing [**] [Classification: Trojan] [Priority: 1] {TCP} 10.0.4.15:51222 -> 185.220.101.5:8443"
        }
    ]

    # 2. Elastic / ELK (ECS) Logs
    elastic_logs = [
        {
            "id": "elastic-ecs-201",
            "siem_source": "Elastic",
            "timestamp": (base_time - timedelta(minutes=50)).isoformat(),
            "severity": "HIGH",
            "event_type": "process_creation",
            "src_ip": "10.0.4.15",
            "dest_ip": None,
            "src_port": None,
            "dest_port": None,
            "user": "victim_jdoe",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f",
            "domain": None,
            "alert_name": "Suspicious PowerShell Obfuscated EncodedCommand Execution",
            "details": {
                "event": {"category": "process", "action": "start", "severity": 7},
                "process": {
                    "name": "powershell.exe",
                    "command_line": "powershell.exe -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
                    "parent": {"name": "WINWORD.EXE"},
                    "hash": {"sha256": "44d88612fea8a8f36de82e1278abb02f"}
                }
            },
            "raw_log": "{\"@timestamp\":\"2026-09-10T08:10:00Z\",\"event\":{\"category\":\"process\",\"action\":\"start\"},\"process\":{\"name\":\"powershell.exe\",\"parent\":{\"name\":\"WINWORD.EXE\"}},\"user\":{\"name\":\"victim_jdoe\"}}"
        },
        {
            "id": "elastic-ecs-202",
            "siem_source": "Elastic",
            "timestamp": (base_time - timedelta(minutes=25)).isoformat(),
            "severity": "CRITICAL",
            "event_type": "dns_tunneling",
            "src_ip": "10.0.4.15",
            "dest_ip": "185.220.101.5",
            "src_port": 53535,
            "dest_port": 53,
            "user": "SYSTEM",
            "file_hash": None,
            "domain": "cdn-sysinternals.com",
            "alert_name": "High Entropy DNS Tunneling Activity Exfiltrating Data",
            "details": {
                "event": {"category": "network", "dataset": "packetbeat.dns"},
                "dns": {
                    "question": {"name": "exfil-a89b01f92.cdn-sysinternals.com", "type": "TXT"},
                    "response_code": "NOERROR"
                }
            },
            "raw_log": "{\"@timestamp\":\"2026-09-10T08:35:00Z\",\"event\":{\"category\":\"network\"},\"dns\":{\"question\":{\"name\":\"exfil-a89b01f92.cdn-sysinternals.com\"}},\"source\":{\"ip\":\"10.0.4.15\"}}"
        }
    ]

    # 3. Microsoft Sentinel Logs
    sentinel_logs = [
        {
            "id": "sentinel-alert-301",
            "siem_source": "Sentinel",
            "timestamp": (base_time - timedelta(minutes=55)).isoformat(),
            "severity": "HIGH",
            "event_type": "InitialAccess",
            "src_ip": "45.33.32.156",
            "dest_ip": "10.0.4.15",
            "src_port": 443,
            "dest_port": 443,
            "user": "victim_jdoe@enterprise.corp",
            "file_hash": None,
            "domain": "update-microsoft-cloud.top",
            "alert_name": "Defender for Office 365: Phishing Link Clicked and Token Replayed",
            "details": {
                "Provider": "Microsoft Defender for Cloud Apps",
                "Tactics": "InitialAccess, CredentialAccess",
                "Techniques": "T1566.002, T1539",
                "IncidentId": "INC-2026-9921",
                "CompromisedEntity": "victim_jdoe@enterprise.corp"
            },
            "raw_log": "Sentinel Alert INC-2026-9921: Phishing Link Clicked on update-microsoft-cloud.top by user victim_jdoe@enterprise.corp. Token replay detected from external IP 45.33.32.156."
        },
        {
            "id": "sentinel-alert-302",
            "siem_source": "Sentinel",
            "timestamp": (base_time - timedelta(minutes=15)).isoformat(),
            "severity": "CRITICAL",
            "event_type": "Impact",
            "src_ip": "10.0.4.15",
            "dest_ip": "10.0.4.200",
            "src_port": 445,
            "dest_port": 445,
            "user": "victim_jdoe",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "domain": None,
            "alert_name": "Microsoft Defender for Endpoint: Mass File Encryption / Ransomware Behavior",
            "details": {
                "Provider": "MDE",
                "RansomwareFamily": "LockBit 3.0 Variant",
                "AffectedExtensions": ".lockbit, .readme.txt",
                "Tactics": "Impact",
                "Technique": "T1486"
            },
            "raw_log": "Defender for Endpoint: Suspicious rapid modification and renaming of 1,420 files to .lockbit extension by process hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
        }
    ]

    # 4. IBM QRadar (LEEF Format) Logs
    qradar_logs = [
        {
            "id": "qradar-leef-401",
            "siem_source": "QRadar",
            "timestamp": (base_time - timedelta(minutes=35)).isoformat(),
            "severity": "CRITICAL",
            "event_type": "leef_event",
            "src_ip": "10.0.4.15",
            "dest_ip": "10.0.4.200",
            "src_port": 49152,
            "dest_port": 445,
            "user": "Administrator",
            "file_hash": None,
            "domain": None,
            "alert_name": "QRadar SIEM: Lateral Movement via SMB Exec & Remote Service Instantiation",
            "details": {
                "vendor": "IBM",
                "product": "QRadar",
                "version": "7.5",
                "event_id": "SMB_REMOTE_EXEC",
                "sev": "9",
                "msg": "PsExec / WMI service execution detected from unprivileged host 10.0.4.15 targeting Domain Controller 10.0.4.200"
            },
            "raw_log": "LEEF:2.0|IBM|QRadar|7.5|SMB_REMOTE_EXEC|sev=9\tsrc=10.0.4.15\tdst=10.0.4.200\tspt=49152\tdpt=445\tusr=Administrator\tmsg=PsExec service execution targeting Domain Controller"
        },
        {
            "id": "qradar-leef-402",
            "siem_source": "QRadar",
            "timestamp": (base_time - timedelta(minutes=20)).isoformat(),
            "severity": "HIGH",
            "event_type": "leef_event",
            "src_ip": "10.0.4.15",
            "dest_ip": "194.26.29.112",
            "src_port": 54110,
            "dest_port": 8888,
            "user": "Administrator",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "domain": None,
            "alert_name": "QRadar SIEM: Large Data Exfiltration Outflow to Russian IP Space",
            "details": {
                "vendor": "IBM",
                "product": "QRadar",
                "sev": "8",
                "msg": "MegaUpload / Encrypted outbound stream of 4.5 GB to 194.26.29.112"
            },
            "raw_log": "LEEF:2.0|IBM|QRadar|7.5|EXFIL_ANOMALY|sev=8\tsrc=10.0.4.15\tdst=194.26.29.112\tspt=54110\tdpt=8888\tusr=Administrator\thash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\tmsg=Encrypted data outflow 4.5GB"
        }
    ]

    # 5. Wazuh HIDS Logs
    wazuh_logs = [
        {
            "id": "wazuh-alert-501",
            "siem_source": "Wazuh",
            "timestamp": (base_time - timedelta(minutes=48)).isoformat(),
            "severity": "HIGH",
            "event_type": "rule_5710",
            "src_ip": "45.33.32.156",
            "dest_ip": "10.0.4.15",
            "src_port": 44321,
            "dest_port": 22,
            "user": "root",
            "file_hash": None,
            "domain": None,
            "alert_name": "Wazuh Alert: Multiple Failed SSH Login Attempts Followed by Sudo Elevation",
            "details": {
                "rule": {"id": 5710, "level": 8, "description": "SSH Brute-force success on staging gateway"},
                "agent": {"id": "004", "name": "bastion-host-01"}
            },
            "raw_log": "{\"timestamp\":\"2026-09-10T08:12:00Z\",\"rule\":{\"id\":5710,\"level\":8,\"description\":\"SSH Brute-force success\"},\"agent\":{\"id\":\"004\",\"name\":\"bastion-host-01\"},\"data\":{\"srcip\":\"45.33.32.156\"}}"
        },
        {
            "id": "wazuh-alert-502",
            "siem_source": "Wazuh",
            "timestamp": (base_time - timedelta(minutes=10)).isoformat(),
            "severity": "CRITICAL",
            "event_type": "rule_100200",
            "src_ip": "10.0.4.200",
            "dest_ip": None,
            "src_port": None,
            "dest_port": None,
            "user": "SYSTEM",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "domain": None,
            "alert_name": "Wazuh Syscheck: Windows Volume Shadow Copies Deleted via vssadmin",
            "details": {
                "rule": {"id": 100200, "level": 12, "description": "Volume Shadow Copies Purged"},
                "full_log": "Process vssadmin.exe delete shadows /all /quiet executed by PID 4412"
            },
            "raw_log": "{\"timestamp\":\"2026-09-10T08:50:00Z\",\"rule\":{\"id\":100200,\"level\":12,\"description\":\"Volume Shadow Copies Purged\"},\"data\":{\"cmd\":\"vssadmin delete shadows /all /quiet\"}}"
        }
    ]

    all_logs = splunk_logs + elastic_logs + sentinel_logs + qradar_logs + wazuh_logs
    insert_logs(all_logs)

    # Pre-populate threat intelligence cache for the key IOCs so UI lights up immediately
    key_iocs = [
        ("185.220.101.5", "ip"),
        ("45.33.32.156", "ip"),
        ("194.26.29.112", "ip"),
        ("update-microsoft-cloud.top", "domain"),
        ("cdn-sysinternals.com", "domain"),
        ("44d88612fea8a8f36de82e1278abb02f", "hash"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash")
    ]
    for indicator, ioc_type in key_iocs:
        lookup_ioc(indicator, ioc_type)

    return len(all_logs)
