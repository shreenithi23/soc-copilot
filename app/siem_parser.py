"""
Aegis AI SIEM Parser & External Log Normalization Gateway.
Wraps the source-aware normalization engine to guarantee backward compatibility
while providing full canonical schema mappings, conflict detection, and diagnostics.
"""

from typing import List, Dict, Any, Tuple, Optional, Union
from app.normalization_engine import (
    normalize_severity,
    standardize_timestamp,
    validate_ip,
    validate_port,
    CanonicalEvent,
    SplunkAdapter,
    ElasticECSAdapter,
    SentinelASIMAdapter,
    QRadarLEEFAdapter,
    WazuhAdapter,
    CSVAdapter,
    GenericAdapter,
    detect_siem_format,
    normalize_single_record,
    ingest_and_normalize_content,
    summarize_batch,
    enrich_event_threat_intel,
    FIELD_MAPPING_REGISTRY,
    NORMALIZATION_SCHEMA_VERSION
)

def parse_splunk_log(record: Union[Dict[str, Any], str]) -> Dict[str, Any]:
    """Parse a Splunk CIM or Key-Value log into canonical schema."""
    event = SplunkAdapter.parse(record)
    return event.to_dict()

def parse_elastic_ecs_log(record: Union[Dict[str, Any], str]) -> Dict[str, Any]:
    """Parse an Elastic Common Schema (ECS) event into canonical schema."""
    event = ElasticECSAdapter.parse(record)
    return event.to_dict()

def parse_sentinel_log(record: Union[Dict[str, Any], str]) -> Dict[str, Any]:
    """Parse Microsoft Sentinel SecurityAlert, CommonSecurityLog, or ASIM event."""
    event = SentinelASIMAdapter.parse(record)
    return event.to_dict()

def parse_qradar_leef(line: str) -> Dict[str, Any]:
    """Parse IBM QRadar LEEF 1.0 or 2.0 pipe-delimited format."""
    event = QRadarLEEFAdapter.parse(line)
    return event.to_dict()

def parse_wazuh_log(record: Union[Dict[str, Any], str]) -> Dict[str, Any]:
    """Parse Wazuh / OSSEC agent alerts into canonical schema."""
    event = WazuhAdapter.parse(record)
    return event.to_dict()

def parse_generic_text(line: str, source_hint: str = "Generic SIEM") -> Dict[str, Any]:
    """Fallback parser for raw syslog or unstructured security text."""
    event = GenericAdapter.parse(line, source_hint)
    return event.to_dict()

def detect_siem_type(record: Any) -> str:
    """Detect SIEM source based on signature keys or string contents."""
    siem_source, _ = detect_siem_format(record)
    return siem_source

def normalize_record(record: Any, siem_source: str) -> Dict[str, Any]:
    """Route record to corresponding SIEM normalizer."""
    event = normalize_single_record(record, siem_source)
    return event.to_dict()

def ingest_dataset_content(content: str, format_type: str = "auto") -> Tuple[List[Dict[str, Any]], int]:
    """
    Ingests and normalizes any security log content into canonical schema:
    - Splunk (CIM JSON, Key-Value syslog)
    - Elastic ECS JSON / NDJSON
    - Microsoft Sentinel / ASIM JSON & Syslog
    - IBM QRadar LEEF
    - Wazuh alerts JSON
    - CSV tables (e.g. Sentinel query outputs, Cynerio, authentication)
    """
    events, summary = ingest_and_normalize_content(content, format_type)
    dict_logs = [e.to_dict() for e in events]
    return dict_logs, len(dict_logs)
