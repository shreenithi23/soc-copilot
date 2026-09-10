import re
import json
import csv
import io
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple

def get_utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


# Severity Normalization Map
SEVERITY_MAP = {
    # Numerical mapping
    "1": "LOW", "2": "LOW", "3": "MEDIUM", "4": "MEDIUM", "5": "MEDIUM",
    "6": "HIGH", "7": "HIGH", "8": "HIGH", "9": "CRITICAL", "10": "CRITICAL",
    # Textual mapping
    "INFO": "INFORMATIONAL", "INFORMATIONAL": "INFORMATIONAL", "DEBUG": "INFORMATIONAL",
    "NOTICE": "LOW", "LOW": "LOW",
    "WARN": "MEDIUM", "WARNING": "MEDIUM", "MEDIUM": "MEDIUM",
    "HIGH": "HIGH", "ALERT": "HIGH", "ERROR": "HIGH",
    "CRITICAL": "CRITICAL", "EMERGENCY": "CRITICAL", "FATAL": "CRITICAL"
}

def normalize_severity(val: Any) -> str:
    """Normalize diverse SIEM severity ratings to standard: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL."""
    if val is None:
        return "INFORMATIONAL"
    s = str(val).strip().upper()
    if s in SEVERITY_MAP:
        return SEVERITY_MAP[s]
    # Check if number in string
    try:
        num = int(float(s))
        if num <= 2:
            return "LOW"
        elif num <= 5:
            return "MEDIUM"
        elif num <= 8:
            return "HIGH"
        else:
            return "CRITICAL"
    except ValueError:
        pass
    return "MEDIUM" if "MED" in s else "HIGH" if "HIGH" in s else "CRITICAL" if "CRIT" in s else "INFORMATIONAL"

def parse_splunk_log(record: Dict[str, Any] | str) -> Dict[str, Any]:
    """Parse a Splunk CIM or KV log."""
    if isinstance(record, str):
        # Check if JSON string
        try:
            record = json.loads(record)
        except Exception:
            # Parse KV pairs like: timestamp host sourcetype=win:sec src=10.0.0.1 dest=192.168.1.5
            kv_dict = {}
            for match in re.finditer(r'([a-zA-Z0-9_\-\.]+)=([^\s"\'=]+|"[^"]*"|\'[^\']*\')', record):
                k, v = match.group(1), match.group(2).strip('"\'')
                kv_dict[k] = v
            kv_dict["_raw"] = record
            record = kv_dict

    raw_str = record.get("_raw") or json.dumps(record)
    timestamp = record.get("_time") or record.get("time") or record.get("timestamp") or get_utc_now_str()
    severity = normalize_severity(record.get("severity") or record.get("urgency") or record.get("priority") or "MEDIUM")
    
    src_ip = record.get("src") or record.get("src_ip") or record.get("source_ip") or record.get("client_ip")
    dest_ip = record.get("dest") or record.get("dest_ip") or record.get("destination_ip") or record.get("server_ip")
    src_port = record.get("src_port") or record.get("source_port")
    dest_port = record.get("dest_port") or record.get("destination_port")
    user = record.get("user") or record.get("username") or record.get("src_user") or record.get("account")
    file_hash = record.get("file_hash") or record.get("hash") or record.get("sha256") or record.get("md5")
    domain = record.get("dest_host") or record.get("query") or record.get("domain") or record.get("url")
    alert_name = record.get("signature") or record.get("event_name") or record.get("app") or record.get("sourcetype") or "Splunk Security Event"

    return {
        "id": str(uuid.uuid4()),
        "siem_source": "Splunk",
        "timestamp": str(timestamp),
        "severity": severity,
        "event_type": record.get("action") or record.get("sourcetype") or "splunk_alert",
        "src_ip": str(src_ip) if src_ip else None,
        "dest_ip": str(dest_ip) if dest_ip else None,
        "src_port": int(src_port) if src_port and str(src_port).isdigit() else None,
        "dest_port": int(dest_port) if dest_port and str(dest_port).isdigit() else None,
        "user": str(user) if user else None,
        "file_hash": str(file_hash) if file_hash else None,
        "domain": str(domain) if domain else None,
        "alert_name": str(alert_name),
        "details": record,
        "raw_log": raw_str
    }

def parse_elastic_ecs_log(record: Dict[str, Any] | str) -> Dict[str, Any]:
    """Parse an Elastic Common Schema (ECS) event."""
    if isinstance(record, str):
        try:
            record = json.loads(record)
        except Exception:
            return parse_generic_text(record, "Elastic")

    raw_str = json.dumps(record)
    timestamp = record.get("@timestamp") or record.get("timestamp") or get_utc_now_str()
    
    event_obj = record.get("event", {}) if isinstance(record.get("event"), dict) else {}
    severity = normalize_severity(
        event_obj.get("severity") or record.get("log.level") or record.get("severity") or "LOW"
    )
    alert_name = (
        event_obj.get("action") or 
        event_obj.get("category") or 
        record.get("message") or 
        "Elastic Security Alert"
    )
    if isinstance(alert_name, list):
        alert_name = ", ".join(alert_name)

    source_obj = record.get("source", {}) if isinstance(record.get("source"), dict) else {}
    dest_obj = record.get("destination", {}) if isinstance(record.get("destination"), dict) else {}
    user_obj = record.get("user", {}) if isinstance(record.get("user"), dict) else {}
    process_obj = record.get("process", {}) if isinstance(record.get("process"), dict) else {}
    dns_obj = record.get("dns", {}) if isinstance(record.get("dns"), dict) else {}

    src_ip = source_obj.get("ip") or record.get("source.ip")
    dest_ip = dest_obj.get("ip") or record.get("destination.ip")
    src_port = source_obj.get("port") or record.get("source.port")
    dest_port = dest_obj.get("port") or record.get("destination.port")
    user = user_obj.get("name") or record.get("user.name")
    
    file_hash = None
    if isinstance(process_obj.get("hash"), dict):
        file_hash = process_obj["hash"].get("sha256") or process_obj["hash"].get("md5")
    elif record.get("process.hash.sha256"):
        file_hash = record.get("process.hash.sha256")
    elif record.get("file.hash.sha256"):
        file_hash = record.get("file.hash.sha256")

    domain = dns_obj.get("question", {}).get("name") or record.get("dns.question.name") or record.get("url.domain")

    return {
        "id": str(uuid.uuid4()),
        "siem_source": "Elastic",
        "timestamp": str(timestamp),
        "severity": severity,
        "event_type": event_obj.get("action") or event_obj.get("dataset") or "ecs_event",
        "src_ip": str(src_ip) if src_ip else None,
        "dest_ip": str(dest_ip) if dest_ip else None,
        "src_port": int(src_port) if src_port and str(src_port).isdigit() else None,
        "dest_port": int(dest_port) if dest_port and str(dest_port).isdigit() else None,
        "user": str(user) if user else None,
        "file_hash": str(file_hash) if file_hash else None,
        "domain": str(domain) if domain else None,
        "alert_name": str(alert_name)[:120],
        "details": record,
        "raw_log": record.get("message") or raw_str
    }

def parse_sentinel_log(record: Dict[str, Any] | str) -> Dict[str, Any]:
    """Parse Microsoft Sentinel SecurityAlert or CommonSecurityLog."""
    if isinstance(record, str):
        try:
            record = json.loads(record)
        except Exception:
            return parse_generic_text(record, "Sentinel")

    raw_str = json.dumps(record)
    timestamp = record.get("TimeGenerated") or record.get("StartTime") or record.get("timestamp") or get_utc_now_str()
    severity = normalize_severity(record.get("AlertSeverity") or record.get("Severity") or record.get("LogSeverity") or "HIGH")
    alert_name = record.get("AlertDisplayName") or record.get("AlertName") or record.get("Activity") or record.get("DeviceEventClassID") or "Sentinel Security Alert"
    
    src_ip = record.get("SourceIP") or record.get("SourceIp") or record.get("src") or record.get("CallerIpAddress")
    dest_ip = record.get("DestinationIP") or record.get("DestinationIp") or record.get("dst")
    src_port = record.get("SourcePort")
    dest_port = record.get("DestinationPort")
    user = record.get("CompromisedEntity") or record.get("UserPrincipalName") or record.get("AccountName") or record.get("SourceUserName")
    file_hash = record.get("FileHash") or record.get("Sha256")
    domain = record.get("DestinationHostName") or record.get("DomainName")

    # Extract entities if available in Sentinel JSON
    entities = record.get("Entities")
    if isinstance(entities, list):
        for ent in entities:
            if isinstance(ent, dict):
                if ent.get("Type") == "ip" and not src_ip:
                    src_ip = ent.get("Address")
                elif ent.get("Type") == "account" and not user:
                    user = ent.get("Name")
                elif ent.get("Type") == "fileHash" and not file_hash:
                    file_hash = ent.get("Value")

    return {
        "id": str(uuid.uuid4()),
        "siem_source": "Sentinel",
        "timestamp": str(timestamp),
        "severity": severity,
        "event_type": record.get("Tactics") or record.get("Activity") or "sentinel_alert",
        "src_ip": str(src_ip) if src_ip else None,
        "dest_ip": str(dest_ip) if dest_ip else None,
        "src_port": int(src_port) if src_port and str(src_port).isdigit() else None,
        "dest_port": int(dest_port) if dest_port and str(dest_port).isdigit() else None,
        "user": str(user) if user else None,
        "file_hash": str(file_hash) if file_hash else None,
        "domain": str(domain) if domain else None,
        "alert_name": str(alert_name),
        "details": record,
        "raw_log": record.get("Description") or raw_str
    }

def parse_qradar_leef(line: str) -> Dict[str, Any]:
    """Parse IBM QRadar LEEF (Log Event Extended Format)."""
    # LEEF:Version|Vendor|Product|Version|EventID|Delimiter(optional)|Key=Value...
    parts = line.split("|")
    leef_data = {}
    if len(parts) >= 5:
        vendor = parts[1]
        product = parts[2]
        event_id = parts[4]
        leef_data["vendor"] = vendor
        leef_data["product"] = product
        leef_data["event_id"] = event_id

        # Attributes are in the rest of the string
        remainder = "|".join(parts[5:])
        # Delimiter could be tab or ^ or standard
        delim = "\t" if "\t" in remainder else " "
        for token in remainder.split(delim):
            if "=" in token:
                k, v = token.split("=", 1)
                leef_data[k.strip()] = v.strip()

    severity = normalize_severity(leef_data.get("sev") or leef_data.get("severity") or "MEDIUM")
    alert_name = leef_data.get("event_id") or leef_data.get("msg") or "QRadar Event"
    src_ip = leef_data.get("src") or leef_data.get("source")
    dest_ip = leef_data.get("dst") or leef_data.get("dst_ip") or leef_data.get("destination")
    src_port = leef_data.get("srcPort") or leef_data.get("spt")
    dest_port = leef_data.get("dstPort") or leef_data.get("dpt")
    user = leef_data.get("usr") or leef_data.get("username")
    file_hash = leef_data.get("fileHash") or leef_data.get("hash")
    domain = leef_data.get("domain") or leef_data.get("dstHost")

    return {
        "id": str(uuid.uuid4()),
        "siem_source": "QRadar",
        "timestamp": leef_data.get("devTime") or get_utc_now_str(),
        "severity": severity,
        "event_type": "leef_event",
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": int(src_port) if src_port and str(src_port).isdigit() else None,
        "dest_port": int(dest_port) if dest_port and str(dest_port).isdigit() else None,
        "user": user,
        "file_hash": file_hash,
        "domain": domain,
        "alert_name": alert_name,
        "details": leef_data,
        "raw_log": line
    }

def parse_wazuh_log(record: Dict[str, Any] | str) -> Dict[str, Any]:
    """Parse Wazuh / OSSEC JSON alerts."""
    if isinstance(record, str):
        try:
            record = json.loads(record)
        except Exception:
            return parse_generic_text(record, "Wazuh")

    rule = record.get("rule", {})
    agent = record.get("agent", {})
    data = record.get("data", {})

    severity = normalize_severity(rule.get("level") or "MEDIUM")
    alert_name = rule.get("description") or "Wazuh Alert"
    timestamp = record.get("timestamp") or get_utc_now_str()

    src_ip = data.get("srcip") or data.get("src_ip")
    dest_ip = data.get("dstip") or data.get("dst_ip")
    src_port = data.get("srcport")
    dest_port = data.get("dstport")
    user = data.get("dstuser") or data.get("srcuser") or record.get("decoder", {}).get("name")
    file_hash = data.get("sha256") or data.get("md5")
    domain = data.get("domain") or data.get("url")

    return {
        "id": str(uuid.uuid4()),
        "siem_source": "Wazuh",
        "timestamp": str(timestamp),
        "severity": severity,
        "event_type": f"rule_{rule.get('id', 'custom')}",
        "src_ip": str(src_ip) if src_ip else None,
        "dest_ip": str(dest_ip) if dest_ip else None,
        "src_port": int(src_port) if src_port and str(src_port).isdigit() else None,
        "dest_port": int(dest_port) if dest_port and str(dest_port).isdigit() else None,
        "user": str(user) if user else None,
        "file_hash": str(file_hash) if file_hash else None,
        "domain": str(domain) if domain else None,
        "alert_name": str(alert_name),
        "details": record,
        "raw_log": record.get("full_log") or json.dumps(record)
    }

def parse_generic_text(line: str, source_hint: str = "Generic SIEM") -> Dict[str, Any]:
    """Fallback parser for raw syslog or unstructured security text."""
    # Find IPs
    ip_matches = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', line)
    src_ip = ip_matches[0] if len(ip_matches) > 0 else None
    dest_ip = ip_matches[1] if len(ip_matches) > 1 else None

    # Severity inference
    lower_line = line.lower()
    if any(w in lower_line for w in ["critical", "ransomware", "c2", "exploit", "mimikatz"]):
        severity = "CRITICAL"
    elif any(w in lower_line for w in ["high", "failed password", "unauthorized", "malware", "drop"]):
        severity = "HIGH"
    elif any(w in lower_line for w in ["warning", "medium", "suspicious"]):
        severity = "MEDIUM"
    else:
        severity = "INFORMATIONAL"

    return {
        "id": str(uuid.uuid4()),
        "siem_source": source_hint,
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "event_type": "raw_log",
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": None,
        "dest_port": None,
        "user": None,
        "file_hash": None,
        "domain": None,
        "alert_name": line[:80],
        "details": {"raw": line},
        "raw_log": line
    }

def ingest_dataset_content(content: str, format_type: str = "auto") -> Tuple[List[Dict[str, Any]], int]:
    """
    Ingests and normalizes any security log content:
    - Splunk (JSON, KV, Syslog)
    - Elastic ECS JSON / NDJSON
    - Microsoft Sentinel JSON / Syslog
    - IBM QRadar LEEF
    - Wazuh JSON
    - CSV formats
    """
    normalized_logs = []
    content = content.strip()
    if not content:
        return [], 0

    # 1. Try parsing as JSON array
    if content.startswith("[") and content.endswith("]"):
        try:
            arr = json.loads(content)
            for item in arr:
                src_hint = (format_type if format_type != "auto" else detect_siem_type(item)).capitalize()
                normalized_logs.append(normalize_record(item, src_hint))
            return normalized_logs, len(normalized_logs)
        except Exception:
            pass

    # 2. Try parsing as NDJSON (newline-delimited JSON)
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    is_ndjson = False
    if lines:
        try:
            test_obj = json.loads(lines[0])
            if isinstance(test_obj, dict):
                is_ndjson = True
        except Exception:
            is_ndjson = False

    if is_ndjson:
        for line in lines:
            try:
                item = json.loads(line)
                src_hint = (format_type if format_type != "auto" else detect_siem_type(item)).capitalize()
                normalized_logs.append(normalize_record(item, src_hint))
            except Exception:
                continue
        return normalized_logs, len(normalized_logs)

    # 3. Check for LEEF format (QRadar)
    if "LEEF:" in content:
        for line in lines:
            if "LEEF:" in line:
                normalized_logs.append(parse_qradar_leef(line))
        return normalized_logs, len(normalized_logs)

    # 4. Check for CSV format
    if "," in lines[0] and any(header in lines[0].lower() for header in ["time", "severity", "source", "dest", "ip", "event"]):
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            normalized_logs.append(normalize_record(row, format_type if format_type != "auto" else "CSV Ingestion"))
        return normalized_logs, len(normalized_logs)

    # 5. Process line by line with auto-detection
    for line in lines:
        detected = detect_siem_type(line) if format_type == "auto" else format_type
        normalized_logs.append(normalize_record(line, detected))

    return normalized_logs, len(normalized_logs)

def detect_siem_type(record: Any) -> str:
    """Detect SIEM source based on signature keys or string contents."""
    if isinstance(record, dict):
        if "sourcetype" in record or "_raw" in record:
            return "Splunk"
        elif "@timestamp" in record or "event.category" in record or "ecs" in record:
            return "Elastic"
        elif "TimeGenerated" in record or "AlertSeverity" in record or "CompromisedEntity" in record:
            return "Sentinel"
        elif "rule" in record and "agent" in record:
            return "Wazuh"
        return "Splunk"
    elif isinstance(record, str):
        if record.startswith("LEEF:"):
            return "QRadar"
        elif "sourcetype=" in record:
            return "Splunk"
        elif "wazuh:" in record or "ossec:" in record:
            return "Wazuh"
    return "Splunk"

def normalize_record(record: Any, siem_source: str) -> Dict[str, Any]:
    """Route record to corresponding SIEM normalizer."""
    src = siem_source.lower()
    if "splunk" in src:
        return parse_splunk_log(record)
    elif "elastic" in src or "elk" in src:
        return parse_elastic_ecs_log(record)
    elif "sentinel" in src or "azure" in src:
        return parse_sentinel_log(record)
    elif "qradar" in src or "leef" in src:
        if isinstance(record, str):
            return parse_qradar_leef(record)
        return parse_splunk_log(record)
    elif "wazuh" in src or "ossec" in src:
        return parse_wazuh_log(record)
    else:
        if isinstance(record, dict):
            return parse_splunk_log(record)
        return parse_generic_text(str(record), siem_source)
