import re
import json
import csv
import io
import uuid
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Union

logger = logging.getLogger("aegis.normalizer")

NORMALIZATION_SCHEMA_VERSION = "2.0.0"

# Canonical Severity Definition
SEVERITY_MAP = {
    # Numerical
    "1": "LOW", "2": "LOW", "3": "MEDIUM", "4": "MEDIUM", "5": "MEDIUM",
    "6": "HIGH", "7": "HIGH", "8": "HIGH", "9": "CRITICAL", "10": "CRITICAL",
    # Textual
    "INFORMATIONAL": "INFORMATIONAL", "INFO": "INFORMATIONAL", "DEBUG": "INFORMATIONAL",
    "LOW": "LOW", "NOTICE": "LOW",
    "MEDIUM": "MEDIUM", "WARN": "MEDIUM", "WARNING": "MEDIUM", "MED": "MEDIUM",
    "HIGH": "HIGH", "ALERT": "HIGH", "ERROR": "HIGH",
    "CRITICAL": "CRITICAL", "FATAL": "CRITICAL", "EMERGENCY": "CRITICAL", "URGENT": "CRITICAL"
}

def normalize_severity(val: Any) -> str:
    """Normalize diverse SIEM severity ratings to standard: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL."""
    if val is None or val == "":
        return "INFORMATIONAL"
    s = str(val).strip().upper()
    if s in SEVERITY_MAP:
        return SEVERITY_MAP[s]
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
    except (ValueError, TypeError):
        pass
    
    if "CRIT" in s or "EMERG" in s or "FATAL" in s:
        return "CRITICAL"
    if "HIGH" in s or "ERR" in s:
        return "HIGH"
    if "MED" in s or "WARN" in s:
        return "MEDIUM"
    if "LOW" in s:
        return "LOW"
    return "INFORMATIONAL"

def standardize_timestamp(val: Any) -> Tuple[str, Optional[str]]:
    """
    Standardize timestamp strings or numeric epochs to standard ISO 8601 UTC format.
    Returns (iso_str, error_message).
    """
    if val is None or val == "":
        return datetime.now(timezone.utc).isoformat(), "Missing timestamp, defaulted to current UTC time"

    # Numeric epoch check
    if isinstance(val, (int, float)) or (isinstance(val, str) and val.replace(".", "", 1).isdigit()):
        try:
            num = float(val)
            if num > 1e11:  # Milliseconds epoch
                num /= 1000.0
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
            return dt.isoformat(), None
        except Exception as e:
            return datetime.now(timezone.utc).isoformat(), f"Invalid epoch timestamp '{val}': {e}"

    val_str = str(val).strip()

    # Try common datetime patterns
    patterns = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%b %d %H:%M:%S",
        "%b %d %Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S"
    ]

    # ISO parsing via fromisoformat if available
    try:
        iso_clean = val_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat(), None
    except Exception:
        pass

    for pattern in patterns:
        try:
            test_str = val_str
            test_pattern = pattern
            if "%Y" not in pattern and "%y" not in pattern:
                test_str = f"{datetime.now(timezone.utc).year} {val_str}"
                test_pattern = f"%Y {pattern}"

            dt = datetime.strptime(test_str, test_pattern)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat(), None
        except ValueError:
            continue

    return datetime.now(timezone.utc).isoformat(), f"Unrecognized timestamp format '{val_str}'"

def validate_ip(val: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Validates an IPv4 or IPv6 address.
    Returns (cleaned_ip, error_message).
    """
    if val is None or val == "":
        return None, None
    s = str(val).strip()
    if s.lower() in ("-", "null", "none", "n/a", "unknown", "—"):
        return None, None
    # Strip port if present in IP:PORT format
    if ":" in s and s.count(":") == 1 and not s.startswith("["):
        parts = s.split(":")
        s = parts[0]
    elif s.startswith("[") and "]:" in s:
        s = s[1:s.index("]")]

    try:
        ip = ipaddress.ip_address(s)
        return str(ip), None
    except ValueError:
        return None, f"Invalid IP address format: '{val}'"

def validate_port(val: Any) -> Tuple[Optional[int], Optional[str]]:
    """
    Validates network port range (1-65535).
    Returns (port_int, error_message).
    """
    if val is None or val == "":
        return None, None
    s = str(val).strip()
    if s.lower() in ("-", "null", "none", "n/a", "unknown", "—"):
        return None, None
    try:
        port_num = int(float(s))
        if 1 <= port_num <= 65535:
            return port_num, None
        return None, f"Port '{val}' out of valid range (1-65535)"
    except (ValueError, TypeError):
        return None, f"Invalid port integer: '{val}'"

def extract_nested_value(data: Any, path: str) -> Tuple[bool, Any]:
    """
    Extracts a value from a nested dict/list using dot-notation path, e.g. 'source.ip' or 'data.srcip'.
    Also checks if the key itself exists literally with dots (e.g. data["source.ip"]).
    Returns (found, value).
    """
    if not isinstance(data, dict):
        return False, None

    # 1. Exact match on literal key (for flat dicts with dot keys)
    if path in data:
        val = data[path]
        if val is not None and val != "":
            return True, val

    # 2. Case-insensitive exact match
    path_lower = path.lower()
    for k, v in data.items():
        if k.lower() == path_lower:
            if v is not None and v != "":
                return True, v

    # 3. Traverse dot-nested hierarchy
    parts = path.split(".")
    curr = data
    for part in parts:
        if isinstance(curr, list):
            if part.isdigit():
                idx = int(part)
                if 0 <= idx < len(curr):
                    curr = curr[idx]
                    continue
                return False, None
            elif len(curr) > 0 and isinstance(curr[0], dict):
                # Check key in first item
                if part in curr[0]:
                    curr = curr[0][part]
                    continue
                matched = None
                for k in curr[0].keys():
                    if k.lower() == part.lower():
                        matched = k
                        break
                if matched:
                    curr = curr[0][matched]
                    continue
            return False, None

        if not isinstance(curr, dict):
            return False, None
        
        # Exact part match
        if part in curr:
            curr = curr[part]
            continue
            
        # Case-insensitive part match
        matched_key = None
        for k in curr.keys():
            if k.lower() == part.lower():
                matched_key = k
                break
        if matched_key is not None:
            curr = curr[matched_key]
        else:
            return False, None

    if curr is not None and curr != "":
        return True, curr
    return False, None

# Centralized Source-Aware Field Mapping Registry
# Defines candidate paths by source format and canonical target
FIELD_MAPPING_REGISTRY: Dict[str, Dict[str, List[str]]] = {
    "appsec": {
        "timestamp": ["discovered_date", "created_date", "first_found", "last_updated", "timestamp", "time"],
        "severity": ["severity", "cvss_score", "fixing_effort", "level"],
        "alert_name": ["issue_name", "vulnerability_name", "cwe.cwe_name", "title", "name", "description", "signature"],
        "event_type": ["issue_category", "issue_type", "vulnerability_type", "cwe.cwe_id", "potential_attack_type"],
        "event_category": ["issue_category", "issue_type", "category"],
        "src_ip": ["src", "src_ip", "attacker_ip"],
        "dest_ip": ["dest", "dest_ip", "affected_ip", "target_ip"],
        "src_port": ["src_port", "source_port"],
        "dest_port": ["dest_port", "destination_port", "port"],
        "user": ["user", "actor", "account"],
        "src_user": ["actor", "user"],
        "dest_user": ["target_user"],
        "src_host": ["scanner", "source_host"],
        "dest_host": ["affected_asset", "target", "asset", "host"],
        "domain": ["affected_asset", "target", "asset", "url", "domain"],
        "file_hash": ["hash", "file_hash", "sha256"],
        "file_name": ["file", "path", "file_name"],
        "process_name": ["process"],
        "process_cmd": ["cwe.cwe_id", "recommendation"],
        "protocol": ["protocol", "transport"],
        "action": ["status", "confidence"]
    },
    "splunk": {
        "timestamp": ["_time", "time", "timestamp", "discovered_date", "EventTime", "@timestamp"],
        "severity": ["severity", "urgency", "priority", "log_level", "level"],
        "alert_name": ["signature", "issue_name", "event_name", "app", "sourcetype", "alert_name", "rule_name"],
        "event_type": ["action", "issue_category", "issue_type", "sourcetype", "event_type", "EventCode"],
        "src_ip": ["src", "src_ip", "source_ip", "client_ip", "c_ip", "source.ip", "SrcIpAddr"],
        "dest_ip": ["dest", "dest_ip", "destination_ip", "server_ip", "s_ip", "destination.ip", "DstIpAddr"],
        "src_port": ["src_port", "source_port", "spt", "source.port", "SrcPortNumber"],
        "dest_port": ["dest_port", "destination_port", "dpt", "destination.port", "DstPortNumber"],
        "user": ["user", "username", "src_user", "account", "TargetUserName", "user.name"],
        "src_user": ["src_user", "user", "username"],
        "dest_user": ["dest_user", "TargetUserName", "dst_user"],
        "src_host": ["src_host", "client_host", "host", "ComputerName", "host.name"],
        "dest_host": ["dest_host", "affected_asset", "server_host", "dest", "destination.host"],
        "domain": ["affected_asset", "dest_host", "query", "domain", "url", "dns.question.name"],
        "file_hash": ["file_hash", "hash", "sha256", "md5", "sha1", "Hash"],
        "file_name": ["file_name", "process_name", "app", "ProcessName"],
        "process_name": ["process", "process_name", "ProcessName", "app"],
        "process_cmd": ["CommandLine", "cmd", "process.command_line"],
        "protocol": ["protocol", "transport", "proto", "network.transport"],
        "action": ["action", "status", "vendor_action", "event.action"]
    },
    "elastic": {
        "timestamp": ["@timestamp", "timestamp", "event.created", "event.start"],
        "severity": ["event.severity", "log.level", "severity", "event.risk_score"],
        "alert_name": ["event.action", "event.category", "rule.name", "message", "signal.rule.name"],
        "event_type": ["event.action", "event.dataset", "event.category", "event.kind"],
        "src_ip": ["source.ip", "client.ip", "src_ip", "source.address", "src"],
        "dest_ip": ["destination.ip", "server.ip", "dest_ip", "destination.address", "dest"],
        "src_port": ["source.port", "client.port", "src_port"],
        "dest_port": ["destination.port", "server.port", "dest_port"],
        "user": ["user.name", "user.target.name", "user.id", "user"],
        "src_user": ["user.name", "source.user.name"],
        "dest_user": ["user.target.name", "destination.user.name"],
        "src_host": ["host.hostname", "host.name", "source.domain"],
        "dest_host": ["destination.domain", "dns.question.name", "url.domain"],
        "domain": ["dns.question.name", "url.domain", "destination.domain"],
        "file_hash": ["process.hash.sha256", "file.hash.sha256", "process.hash.md5", "file.hash.md5", "hash.sha256"],
        "file_name": ["file.name", "process.name", "process.executable"],
        "process_name": ["process.name", "process.executable"],
        "process_cmd": ["process.command_line", "process.args"],
        "protocol": ["network.transport", "network.protocol"],
        "action": ["event.action", "event.outcome"]
    },
    "sentinel": {
        "timestamp": ["TimeGenerated", "StartTime", "EventTime", "timestamp", "TimeCreated"],
        "severity": ["AlertSeverity", "Severity", "LogSeverity", "severity"],
        "alert_name": ["AlertDisplayName", "AlertName", "Activity", "DeviceEventClassID", "Title"],
        "event_type": ["Tactics", "Activity", "EventSubType", "EventType", "Category"],
        "src_ip": ["SrcIpAddr", "SourceIP", "SourceIp", "CallerIpAddress", "SourceAddress", "src", "IpAddress"],
        "dest_ip": ["DstIpAddr", "DestinationIP", "DestinationIp", "DestinationAddress", "dst", "dest"],
        "src_port": ["SrcPortNumber", "SourcePort", "src_port"],
        "dest_port": ["DstPortNumber", "DestinationPort", "dest_port"],
        "user": ["CompromisedEntity", "UserPrincipalName", "AccountName", "TargetUserName", "SourceUserName", "user"],
        "src_user": ["SourceUserName", "AccountName", "Caller"],
        "dest_user": ["TargetUserName", "CompromisedEntity", "UserPrincipalName"],
        "src_host": ["Computer", "DeviceName", "SourceHostName"],
        "dest_host": ["DestinationHostName", "TargetDeviceName"],
        "domain": ["DestinationHostName", "DomainName", "FQDN", "DestinationDomain"],
        "file_hash": ["FileHash", "Sha256", "MD5", "FileHashValue"],
        "file_name": ["FileName", "ProcessName", "Process"],
        "process_name": ["ProcessName", "NewProcessName", "Process"],
        "process_cmd": ["CommandLine", "ProcessCommandLine"],
        "protocol": ["NetworkProtocol", "Protocol"],
        "action": ["DeviceAction", "Action", "Activity", "Status"]
    },
    "qradar": {
        "timestamp": ["devTime", "devTimeFormat", "timestamp"],
        "severity": ["sev", "severity", "level"],
        "alert_name": ["event_id", "msg", "eventName", "alert_name"],
        "event_type": ["event_id", "cat", "event_type"],
        "src_ip": ["src", "src_ip", "source", "source_ip"],
        "dest_ip": ["dst", "dst_ip", "destination", "dest_ip"],
        "src_port": ["srcPort", "spt", "src_port"],
        "dest_port": ["dstPort", "dpt", "dest_port"],
        "user": ["usr", "username", "user", "account"],
        "src_user": ["usr", "src_user"],
        "dest_user": ["dst_user", "target_user"],
        "src_host": ["srcHost", "src_host", "identHostName"],
        "dest_host": ["dstHost", "dest_host", "domain"],
        "domain": ["domain", "dstHost", "url"],
        "file_hash": ["fileHash", "hash", "sha256", "md5"],
        "file_name": ["fileName", "processName"],
        "process_name": ["processName", "process"],
        "process_cmd": ["cmd", "commandLine"],
        "protocol": ["proto", "protocol"],
        "action": ["action", "status"]
    },
    "wazuh": {
        "timestamp": ["timestamp", "data.timestamp", "@timestamp"],
        "severity": ["rule.level", "severity", "level"],
        "alert_name": ["rule.description", "rule.name", "alert_name"],
        "event_type": ["rule.id", "decoder.name", "event_type"],
        "src_ip": ["data.srcip", "data.src_ip", "data.win.eventdata.ipAddress", "data.netinfo.srcip"],
        "dest_ip": ["data.dstip", "data.dst_ip", "data.win.eventdata.destIp", "data.netinfo.dstip"],
        "src_port": ["data.srcport", "data.src_port", "data.win.eventdata.ipPort"],
        "dest_port": ["data.dstport", "data.dst_port"],
        "user": ["data.dstuser", "data.srcuser", "data.win.eventdata.targetUserName", "decoder.name", "data.user"],
        "src_user": ["data.srcuser", "data.win.eventdata.subjectUserName"],
        "dest_user": ["data.dstuser", "data.win.eventdata.targetUserName"],
        "src_host": ["agent.name", "agent.hostname", "data.win.system.computer"],
        "dest_host": ["data.domain", "data.dsthost"],
        "domain": ["data.domain", "data.url", "data.dns.question.name"],
        "file_hash": ["data.sha256", "data.md5", "syscheck.sha256_after", "syscheck.md5_after", "data.win.eventdata.hashes"],
        "file_name": ["syscheck.path", "data.win.eventdata.image", "data.file"],
        "process_name": ["data.win.eventdata.image", "data.process", "data.win.eventdata.originalFileName"],
        "process_cmd": ["data.win.eventdata.commandLine", "data.cmd", "full_log"],
        "protocol": ["data.protocol", "data.netinfo.protocol"],
        "action": ["data.action", "rule.action"]
    },
    "csv": {
        "timestamp": ["TimeGenerated", "Timestamp", "time", "Date", "EventTime", "@timestamp", "devTime", "TimeGenerated [UTC]"],
        "severity": ["AlertSeverity", "Severity", "EventOriginalSeverity", "EventSeverity", "severity", "Priority", "level"],
        "alert_name": ["AlertName", "EventMessage", "EventOriginalSubType", "EventType", "Activity", "EventName", "Signature", "Description", "Title"],
        "event_type": ["EventType", "EventOriginalType", "EventSubType", "Tactics", "Category", "EventCode"],
        "src_ip": ["SrcIpAddr", "SourceIP", "SourceIp", "SourceAddress", "src", "src_ip", "ClientIP", "IpAddr"],
        "dest_ip": ["DstIpAddr", "TargetIpAddr", "DestinationIP", "DestinationIp", "DestinationAddress", "dst", "dest_ip", "ServerIP"],
        "src_port": ["SrcPortNumber", "SourcePort", "src_port", "spt"],
        "dest_port": ["DstPortNumber", "TargetPortNumber", "DestinationPort", "dest_port", "dpt"],
        "user": ["AccountName", "ActorUserName", "UserPrincipalName", "UserName", "TargetUserName", "user", "CompromisedEntity"],
        "src_user": ["SourceUserName", "ActorUserName", "AccountName", "Caller"],
        "dest_user": ["TargetUserName", "CompromisedEntity", "UserPrincipalName"],
        "src_host": ["Computer", "DeviceName", "SourceHost", "Host", "DvcId"],
        "dest_host": ["DestinationHost", "DestinationHostName", "TargetDevice"],
        "domain": ["Domain", "DomainName", "DestinationHostName", "FQDN"],
        "file_hash": ["FileHash", "Sha256", "MD5", "Hash"],
        "file_name": ["FileName", "ProcessName", "Process"],
        "process_name": ["ProcessName", "Process"],
        "process_cmd": ["CommandLine", "Command"],
        "protocol": ["Protocol", "LogonProtocol", "NetworkProtocol", "Transport"],
        "action": ["Action", "DeviceAction", "EventResult", "Status", "Activity"]
    },
    "generic": {
        "timestamp": ["timestamp", "time", "date", "@timestamp", "TimeGenerated"],
        "severity": ["severity", "level", "priority", "urgency"],
        "alert_name": ["message", "msg", "event", "name", "summary", "signature"],
        "event_type": ["type", "event_type", "action", "category"],
        "src_ip": ["src", "src_ip", "source_ip", "source", "client_ip", "source.ip", "SrcIpAddr"],
        "dest_ip": ["dest", "dest_ip", "destination_ip", "destination", "server_ip", "destination.ip", "DstIpAddr"],
        "src_port": ["src_port", "source_port", "spt"],
        "dest_port": ["dest_port", "destination_port", "dpt"],
        "user": ["user", "username", "account"],
        "src_user": ["src_user", "source_user"],
        "dest_user": ["dest_user", "target_user"],
        "src_host": ["host", "hostname", "source_host"],
        "dest_host": ["dest_host", "domain"],
        "domain": ["domain", "url", "fqdn"],
        "file_hash": ["hash", "file_hash", "sha256", "md5"],
        "file_name": ["file", "file_name", "process"],
        "process_name": ["process", "process_name"],
        "process_cmd": ["cmd", "command"],
        "protocol": ["proto", "protocol"],
        "action": ["action", "status"]
    }
}

class CanonicalEvent:
    """Represents a validated, normalized security event in canonical schema."""
    def __init__(self, raw_input: Any, siem_source: str, log_format: str = "json"):
        self.id = str(uuid.uuid4())
        self.siem_source = siem_source
        self.log_format = log_format
        self.vendor: Optional[str] = None
        self.product: Optional[str] = None
        self.timestamp: str = datetime.now(timezone.utc).isoformat()
        self.severity: str = "INFORMATIONAL"
        self.alert_name: str = "Security Event"
        self.event_type: str = "security_alert"
        self.event_category: Optional[str] = None
        
        # Endpoints
        self.src_ip: Optional[str] = None
        self.src_port: Optional[int] = None
        self.src_host: Optional[str] = None
        self.src_user: Optional[str] = None
        
        self.dest_ip: Optional[str] = None
        self.dest_port: Optional[int] = None
        self.dest_host: Optional[str] = None
        self.dest_user: Optional[str] = None
        
        # Primary user / entity (backward compatible)
        self.user: Optional[str] = None
        
        # Identifiers & Artifacts
        self.domain: Optional[str] = None
        self.file_hash: Optional[str] = None
        self.file_name: Optional[str] = None
        self.process_name: Optional[str] = None
        self.process_cmd: Optional[str] = None
        self.protocol: Optional[str] = None
        self.action: Optional[str] = None
        
        # Payload & Diagnostics
        self.details: Dict[str, Any] = {}
        self.raw_log: str = ""
        self.raw_event: Any = raw_input
        self.normalization_status: str = "success"  # success, partial, failed
        self.mapping_version: str = NORMALIZATION_SCHEMA_VERSION
        self.unmapped_fields: List[str] = []
        self.conflicting_fields: List[Dict[str, Any]] = []
        self.validation_errors: List[str] = []
        self.threat_intel: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Produce dictionary output compatible with both legacy and new schemas."""
        return {
            "id": self.id,
            "siem_source": self.siem_source,
            "vendor": self.vendor,
            "product": self.product,
            "log_format": self.log_format,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "alert_name": self.alert_name,
            "event_type": self.event_type,
            "event_category": self.event_category,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "src_host": self.src_host,
            "src_user": self.src_user,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "dest_host": self.dest_host,
            "dest_user": self.dest_user,
            "user": self.user,
            "domain": self.domain,
            "file_hash": self.file_hash,
            "file_name": self.file_name,
            "process_name": self.process_name,
            "process_cmd": self.process_cmd,
            "protocol": self.protocol,
            "action": self.action,
            "details": self.details,
            "raw_log": self.raw_log,
            "raw_event": self.raw_event,
            "normalization_status": self.normalization_status,
            "mapping_version": self.mapping_version,
            "unmapped_fields": self.unmapped_fields,
            "conflicting_fields": self.conflicting_fields,
            "validation_errors": self.validation_errors,
            "threat_intel": self.threat_intel
        }

def map_fields_with_registry(
    record: Dict[str, Any], 
    source_key: str, 
    canonical_event: CanonicalEvent
) -> None:
    """
    Applies the source-aware field mapping registry to a structured record.
    Extracts values, detects conflicts among candidate aliases, records unmapped fields,
    and performs data type normalization & validation.
    """
    mapping = FIELD_MAPPING_REGISTRY.get(source_key.lower()) or FIELD_MAPPING_REGISTRY["generic"]
    mapped_keys: set = set()

    for canonical_field, candidate_paths in mapping.items():
        found_values: Dict[str, Any] = {}
        for path in candidate_paths:
            found, val = extract_nested_value(record, path)
            if found:
                mapped_keys.add(path.split(".")[0])
                mapped_keys.add(path)
                found_values[path] = val

        if not found_values:
            continue

        # Check for conflicting aliases with differing values
        unique_reprs = {str(v).strip().lower(): v for p, v in found_values.items()}
        selected_val = list(found_values.values())[0]  # Priority order: first matching candidate

        if len(unique_reprs) > 1:
            conflict_entry = {
                "field": canonical_field,
                "candidates": {k: str(v) for k, v in found_values.items()},
                "selected": str(selected_val)
            }
            canonical_event.conflicting_fields.append(conflict_entry)
            logger.debug(f"Conflicting aliases detected for {canonical_field}: {conflict_entry}")

        # Apply value to canonical event with type validation
        _apply_canonical_field(canonical_event, canonical_field, selected_val)

    # Secondary resolution: populate primary user if not set
    if not canonical_event.user:
        canonical_event.user = canonical_event.src_user or canonical_event.dest_user

    # Compute unmapped fields from input record
    for k in record.keys():
        if k not in mapped_keys and k.lower() not in [mk.lower() for mk in mapped_keys]:
            canonical_event.unmapped_fields.append(k)

def _apply_canonical_field(event: CanonicalEvent, field: str, val: Any) -> None:
    """Applies and validates single field against canonical constraints."""
    if val is None or val == "":
        return

    if field == "timestamp":
        iso_str, err = standardize_timestamp(val)
        event.timestamp = iso_str
        if err:
            event.validation_errors.append(err)

    elif field == "severity":
        event.severity = normalize_severity(val)

    elif field == "alert_name":
        if isinstance(val, list):
            event.alert_name = ", ".join(str(x) for x in val)
        else:
            event.alert_name = str(val)[:200]

    elif field == "event_type":
        if isinstance(val, list):
            event.event_type = ", ".join(str(x) for x in val)
        else:
            event.event_type = str(val)

    elif field in ("src_ip", "dest_ip"):
        clean_ip, err = validate_ip(val)
        if clean_ip:
            setattr(event, field, clean_ip)
        elif err:
            event.validation_errors.append(err)

    elif field in ("src_port", "dest_port"):
        clean_port, err = validate_port(val)
        if clean_port is not None:
            setattr(event, field, clean_port)
        elif err:
            event.validation_errors.append(err)

    elif field in ("user", "src_user", "dest_user", "src_host", "dest_host", "domain", 
                    "file_hash", "file_name", "process_name", "process_cmd", 
                    "protocol", "action", "event_category"):
        if isinstance(val, list):
            setattr(event, field, ", ".join(str(x) for x in val))
        else:
            setattr(event, field, str(val))

def determine_status(event: CanonicalEvent) -> str:
    """
    Computes normalization outcome:
    - success: core fields mapped, no severe validation failures.
    - partial: valid event with some unmapped fields, non-fatal validation errors or conflicting aliases.
    - failed: corrupt record, missing basic identity, or invalid structure.
    """
    if not event.alert_name and not event.event_type:
        return "failed"
    if not event.timestamp:
        return "failed"
    
    has_conflicts = len(event.conflicting_fields) > 0
    has_errors = len(event.validation_errors) > 0
    has_unmapped = len(event.unmapped_fields) > 0

    if has_conflicts or has_errors or has_unmapped:
        return "partial"
    return "success"

# ======================================================================
# Source-Specific Parser Adapters
# ======================================================================

class SplunkAdapter:
    """Adapter for Splunk CIM JSON or Key-Value text."""
    @staticmethod
    def parse(record: Union[Dict[str, Any], str]) -> CanonicalEvent:
        event = CanonicalEvent(record, "Splunk", "json" if isinstance(record, dict) else "kv")
        event.vendor = "Splunk"
        event.product = "Splunk Enterprise"

        if isinstance(record, str):
            # Try parsing as JSON first
            try:
                record = json.loads(record)
                event.log_format = "json"
            except Exception:
                # Key-Value extraction: e.g. time="2026-09-10" src=10.0.0.1 dest=192.168.1.1
                kv = {}
                for m in re.finditer(r'([a-zA-Z0-9_\-\.]+)=([^\s"\'=]+|"[^"]*"|\'[^\']*\')', record):
                    k, v = m.group(1), m.group(2).strip('"\'')
                    kv[k] = v
                kv["_raw"] = record
                event.raw_log = record
                event.details = kv
                map_fields_with_registry(kv, "splunk", event)
                event.normalization_status = determine_status(event)
                return event

        event.raw_log = record.get("_raw") or json.dumps(record)
        event.details = record
        map_fields_with_registry(record, "splunk", event)
        event.normalization_status = determine_status(event)
        return event

class ElasticECSAdapter:
    """Adapter for Elastic Common Schema (ECS) events."""
    @staticmethod
    def parse(record: Union[Dict[str, Any], str]) -> CanonicalEvent:
        event = CanonicalEvent(record, "Elastic", "ecs")
        event.vendor = "Elastic"
        event.product = "Elasticsearch / Fleet"

        if isinstance(record, str):
            try:
                record = json.loads(record)
            except Exception as e:
                event.normalization_status = "failed"
                event.validation_errors.append(f"Invalid Elastic JSON: {e}")
                event.raw_log = record
                return event

        event.raw_log = record.get("message") or json.dumps(record)
        event.details = record
        map_fields_with_registry(record, "elastic", event)
        event.normalization_status = determine_status(event)
        return event

class SentinelASIMAdapter:
    """Adapter for Microsoft Sentinel SecurityAlert & ASIM events."""
    @staticmethod
    def parse(record: Union[Dict[str, Any], str]) -> CanonicalEvent:
        event = CanonicalEvent(record, "Sentinel", "json")
        event.vendor = "Microsoft"
        event.product = "Microsoft Sentinel"

        if isinstance(record, str):
            try:
                record = json.loads(record)
            except Exception as e:
                event.normalization_status = "failed"
                event.validation_errors.append(f"Invalid Sentinel JSON: {e}")
                event.raw_log = record
                return event

        event.raw_log = record.get("Description") or json.dumps(record)
        event.details = record
        map_fields_with_registry(record, "sentinel", event)

        # Sentinel Entities inspection for auxiliary IOCs
        entities = record.get("Entities")
        if isinstance(entities, list):
            for ent in entities:
                if isinstance(ent, dict):
                    ent_type = ent.get("Type", "").lower()
                    if ent_type == "ip" and not event.src_ip:
                        ip_val, _ = validate_ip(ent.get("Address"))
                        if ip_val:
                            event.src_ip = ip_val
                    elif ent_type == "account" and not event.user:
                        event.user = ent.get("Name") or ent.get("UserPrincipalName")
                    elif ent_type in ("filehash", "file_hash") and not event.file_hash:
                        event.file_hash = ent.get("Value")

        event.normalization_status = determine_status(event)
        return event

class QRadarLEEFAdapter:
    """Adapter for IBM QRadar LEEF (Log Event Extended Format)."""
    @staticmethod
    def parse(line: str) -> CanonicalEvent:
        event = CanonicalEvent(line, "QRadar", "leef")
        event.vendor = "IBM"
        event.product = "QRadar SIEM"
        event.raw_log = str(line)

        if not str(line).startswith("LEEF:"):
            event.normalization_status = "failed"
            event.validation_errors.append("Malformed LEEF: Missing 'LEEF:' prefix header")
            return event

        parts = line.split("|")
        if len(parts) < 5:
            event.normalization_status = "failed"
            event.validation_errors.append("Malformed LEEF: Insufficient header pipe delimiters (< 5)")
            return event

        event.vendor = parts[1] or "IBM"
        event.product = parts[2] or "QRadar"
        event.alert_name = parts[4] or "LEEF Event"

        leef_dict = {
            "vendor": event.vendor,
            "product": event.product,
            "event_id": parts[4]
        }

        # Delimiter detection
        remainder = "|".join(parts[5:])
        delim = "\t" if "\t" in remainder else "^" if "^" in remainder else " "
        for token in remainder.split(delim):
            if "=" in token:
                k, v = token.split("=", 1)
                leef_dict[k.strip()] = v.strip()

        event.details = leef_dict
        map_fields_with_registry(leef_dict, "qradar", event)
        event.normalization_status = determine_status(event)
        return event

class WazuhAdapter:
    """Adapter for Wazuh / OSSEC agent alerts."""
    @staticmethod
    def parse(record: Union[Dict[str, Any], str]) -> CanonicalEvent:
        event = CanonicalEvent(record, "Wazuh", "json")
        event.vendor = "Wazuh"
        event.product = "Wazuh HIDS"

        if isinstance(record, str):
            try:
                record = json.loads(record)
            except Exception as e:
                event.normalization_status = "failed"
                event.validation_errors.append(f"Invalid Wazuh JSON: {e}")
                event.raw_log = record
                return event

        rule = record.get("rule", {}) if isinstance(record.get("rule"), dict) else {}
        agent = record.get("agent", {}) if isinstance(record.get("agent"), dict) else {}
        
        event.raw_log = record.get("full_log") or json.dumps(record)
        event.details = record
        event.alert_name = rule.get("description") or "Wazuh Alert"
        event.event_type = f"rule_{rule.get('id', 'custom')}"
        if agent.get("name"):
            event.src_host = agent.get("name")

        map_fields_with_registry(record, "wazuh", event)
        event.normalization_status = determine_status(event)
        return event

class CSVAdapter:
    """Adapter for CSV records (Sentinel queries, Cynerio, authentication tables)."""
    @staticmethod
    def parse(row: Dict[str, Any], source_hint: str = "CSV Ingestion") -> CanonicalEvent:
        event = CanonicalEvent(row, source_hint, "csv")
        event.vendor = "CSV Import"
        event.product = "Tabular Telemetry"
        event.details = dict(row)
        event.raw_log = json.dumps(row)

        map_fields_with_registry(row, "csv", event)
        event.normalization_status = determine_status(event)
        return event

class GenericAdapter:
    """Fallback adapter for syslog or unstructured text."""
    @staticmethod
    def parse(line: str, source_hint: str = "Generic SIEM") -> CanonicalEvent:
        event = CanonicalEvent(line, source_hint, "syslog")
        event.vendor = "Generic"
        event.product = "Syslog"
        event.raw_log = line
        event.details = {"raw": line}

        # IP extraction via regex
        ip_matches = re.findall(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            line
        )
        if len(ip_matches) > 0:
            ip, _ = validate_ip(ip_matches[0])
            event.src_ip = ip
        if len(ip_matches) > 1:
            ip, _ = validate_ip(ip_matches[1])
            event.dest_ip = ip

        # Severity heuristic
        lower = line.lower()
        if any(w in lower for w in ["critical", "ransomware", "c2", "exploit", "mimikatz"]):
            event.severity = "CRITICAL"
        elif any(w in lower for w in ["high", "failed password", "unauthorized", "malware", "drop"]):
            event.severity = "HIGH"
        elif any(w in lower for w in ["warning", "medium", "suspicious"]):
            event.severity = "MEDIUM"
        else:
            event.severity = "INFORMATIONAL"

        event.alert_name = line[:100]
        event.normalization_status = "partial" if (event.src_ip or event.dest_ip) else "failed"
        return event

# ======================================================================
# Central Detection & Normalization Routing
# ======================================================================

def detect_siem_format(record: Any) -> Tuple[str, str]:
    """
    Detects (siem_source, format_type) from record content or structure.
    """
    if isinstance(record, dict):
        # AppSec / Vulnerability Scanner signature
        if "issue_name" in record or "cwe" in record or "affected_asset" in record or "cvss_score" in record or "vulnerability" in record:
            return "AppSec Scanner", "appsec"
        # Wazuh signature
        if "rule" in record and ("agent" in record or "decoder" in record):
            return "Wazuh", "wazuh"
        # Elastic ECS signature
        if "@timestamp" in record or "ecs" in record or "event.category" in record or "source.ip" in record:
            return "Elastic", "elastic"
        # Microsoft Sentinel / ASIM signature
        if "TimeGenerated" in record or "AlertSeverity" in record or "CompromisedEntity" in record or "SrcIpAddr" in record:
            return "Sentinel", "sentinel"
        # Splunk signature
        if "sourcetype" in record or "_raw" in record:
            return "Splunk", "splunk"
        return "Splunk", "splunk"

    elif isinstance(record, str):
        line = record.strip()
        if line.startswith("LEEF:"):
            return "QRadar", "qradar"
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
                return detect_siem_format(parsed)
            except Exception:
                pass
        if "sourcetype=" in line:
            return "Splunk", "splunk"
        if "wazuh:" in line.lower() or "ossec:" in line.lower():
            return "Wazuh", "wazuh"

    return "Generic SIEM", "generic"

def normalize_single_record(record: Any, format_hint: str = "auto") -> CanonicalEvent:
    """
    Routes a single record through its source-specific adapter and returns a CanonicalEvent.
    """
    hint = (format_hint or "auto").lower()

    if hint == "auto":
        siem_source, fmt = detect_siem_format(record)
    else:
        siem_source = hint.capitalize()
        fmt = hint

    if "appsec" in fmt or "vulnerability" in fmt:
        event = CanonicalEvent(record, siem_source, "json")
        event.vendor = "AppSec"
        event.product = "Vulnerability Scanner"
        event.details = record if isinstance(record, dict) else {}
        event.raw_log = json.dumps(record) if isinstance(record, dict) else str(record)
        map_fields_with_registry(event.details, "appsec", event)
        event.normalization_status = determine_status(event)
        return event
    elif "splunk" in fmt:
        return SplunkAdapter.parse(record)
    elif "elastic" in fmt or "ecs" in fmt:
        return ElasticECSAdapter.parse(record)
    elif "sentinel" in fmt or "asim" in fmt:
        return SentinelASIMAdapter.parse(record)
    elif "qradar" in fmt or "leef" in fmt:
        if isinstance(record, str):
            return QRadarLEEFAdapter.parse(record)
        if isinstance(record, dict) and isinstance(record.get("raw_log"), str) and record["raw_log"].startswith("LEEF:"):
            return QRadarLEEFAdapter.parse(record["raw_log"])
        return SplunkAdapter.parse(record)
    elif "wazuh" in fmt or "ossec" in fmt:
        return WazuhAdapter.parse(record)
    elif "csv" in fmt:
        if isinstance(record, dict):
            return CSVAdapter.parse(record, siem_source)
        return GenericAdapter.parse(str(record), siem_source)
    else:
        if isinstance(record, dict):
            return SplunkAdapter.parse(record)
        return GenericAdapter.parse(str(record), siem_source)

def ingest_and_normalize_content(
    content: str, 
    format_type: str = "auto"
) -> Tuple[List[CanonicalEvent], Dict[str, Any]]:
    """
    Main ingestion parser: parses raw text (JSON, NDJSON, CSV, LEEF, Syslog)
    into a list of CanonicalEvents and produces normalization diagnostics.
    """
    content = content.strip()
    if not content:
        return [], {"processed": 0, "success": 0, "partial": 0, "failed": 0, "duplicates": 0}

    events: List[CanonicalEvent] = []

    # 1. JSON Array
    if content.startswith("[") and content.endswith("]"):
        try:
            arr = json.loads(content)
            for item in arr:
                events.append(normalize_single_record(item, format_type))
            return events, summarize_batch(events)
        except Exception:
            pass

    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if not lines:
        return [], {"processed": 0, "success": 0, "partial": 0, "failed": 0, "duplicates": 0}

    # 2. NDJSON
    try:
        first_json = json.loads(lines[0])
        if isinstance(first_json, dict):
            for line in lines:
                try:
                    obj = json.loads(line)
                    events.append(normalize_single_record(obj, format_type))
                except Exception as e:
                    fail_evt = CanonicalEvent(line, "Unknown", "json")
                    fail_evt.normalization_status = "failed"
                    fail_evt.validation_errors.append(f"NDJSON line syntax error: {e}")
                    fail_evt.raw_log = line
                    events.append(fail_evt)
            return events, summarize_batch(events)
    except Exception:
        pass

    # 3. LEEF Lines
    if "LEEF:" in lines[0] or any(l.startswith("LEEF:") for l in lines):
        for line in lines:
            if "LEEF:" in line:
                events.append(QRadarLEEFAdapter.parse(line))
            else:
                events.append(GenericAdapter.parse(line, "QRadar"))
        return events, summarize_batch(events)

    # 4. CSV Format
    first_line_lower = lines[0].lower()
    if "," in lines[0] and any(h in first_line_lower for h in ["time", "severity", "src", "dest", "ip", "user", "event", "activity"]):
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                events.append(CSVAdapter.parse(row, "Sentinel" if ("srcipaddr" in first_line_lower or "activity" in first_line_lower) else "CSV Ingestion"))
            return events, summarize_batch(events)
        except Exception:
            pass

    # 5. Fallback line-by-line
    for line in lines:
        events.append(normalize_single_record(line, format_type))

    return events, summarize_batch(events)

def summarize_batch(events: List[CanonicalEvent]) -> Dict[str, Any]:
    """Generates an ingestion summary breakdown."""
    summary = {
        "processed": len(events),
        "success": 0,
        "partial": 0,
        "failed": 0,
        "duplicates": 0
    }
    for e in events:
        if e.normalization_status == "success":
            summary["success"] += 1
        elif e.normalization_status == "partial":
            summary["partial"] += 1
        else:
            summary["failed"] += 1
    return summary

# ======================================================================
# Decoupled Threat Intelligence Enrichment Stage
# ======================================================================

def enrich_event_threat_intel(event: CanonicalEvent, lookup_fn: Optional[Any] = None) -> None:
    """
    Enriches a normalized event with threat intelligence without breaking or blocking normalization.
    """
    if lookup_fn is None:
        try:
            from app.threat_intel import lookup_ioc
            lookup_fn = lookup_ioc
        except ImportError:
            return

    indicators_to_check = []
    if event.src_ip:
        indicators_to_check.append((event.src_ip, "ip"))
    if event.dest_ip:
        indicators_to_check.append((event.dest_ip, "ip"))
    if event.file_hash:
        indicators_to_check.append((event.file_hash, "hash"))
    if event.domain:
        indicators_to_check.append((event.domain, "domain"))

    enriched_results = {}
    for ind, ioc_type in indicators_to_check:
        try:
            res = lookup_fn(ind, ioc_type)
            if res:
                enriched_results[ind] = {
                    "ioc_type": ioc_type,
                    "malicious_count": res.get("malicious_count", 0),
                    "suspicious_count": res.get("suspicious_count", 0),
                    "reputation": res.get("reputation", 0),
                    "tags": res.get("tags", []),
                    "source": res.get("source", "Threat Feed")
                }
        except Exception as e:
            logger.warning(f"Threat intel lookup non-fatal failure for {ind}: {e}")

    if enriched_results:
        event.threat_intel = enriched_results
