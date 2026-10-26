import unittest
import os
import json
from datetime import datetime, timezone

# Ensure test DB is used
os.environ["DATABASE_PATH"] = "test_soc.db"

from app.database import (
    init_db,
    insert_logs,
    query_logs,
    get_mapping_coverage,
    reprocess_stored_logs,
    get_db_connection
)
from app.normalization_engine import (
    CanonicalEvent,
    SplunkAdapter,
    ElasticECSAdapter,
    SentinelASIMAdapter,
    QRadarLEEFAdapter,
    WazuhAdapter,
    CSVAdapter,
    GenericAdapter,
    standardize_timestamp,
    validate_ip,
    validate_port,
    normalize_severity,
    normalize_single_record,
    ingest_and_normalize_content,
    enrich_event_threat_intel
)
from app.siem_parser import (
    parse_splunk_log,
    parse_elastic_ecs_log,
    parse_sentinel_log,
    parse_qradar_leef,
    parse_wazuh_log,
    ingest_dataset_content
)

class TestNormalizationPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    # 1. Flat JSON using src_ip and dest_ip
    def test_01_flat_json_src_dest_ip(self):
        record = {
            "timestamp": "2026-09-10T10:00:00Z",
            "src_ip": "192.168.1.10",
            "dest_ip": "10.0.0.1",
            "user": "alice",
            "action": "allowed",
            "signature": "Firewall Allow Traffic"
        }
        res = parse_splunk_log(record)
        self.assertEqual(res["src_ip"], "192.168.1.10")
        self.assertEqual(res["dest_ip"], "10.0.0.1")
        self.assertEqual(res["user"], "alice")
        self.assertEqual(res["normalization_status"], "success")

    # 2. Nested Elastic ECS JSON using source.ip and destination.ip
    def test_02_nested_elastic_ecs_json(self):
        # A: Truly nested ECS JSON
        nested_ecs = {
            "@timestamp": "2026-09-10T11:20:00Z",
            "event": {"action": "network_flow", "severity": 7},
            "source": {"ip": "10.0.1.50", "port": 49152},
            "destination": {"ip": "185.220.101.5", "port": 443},
            "user": {"name": "victim_user"},
            "process": {"name": "curl.exe", "hash": {"sha256": "44d88612fea8a8f36de82e1278abb02f"}}
        }
        res_nested = parse_elastic_ecs_log(nested_ecs)
        self.assertEqual(res_nested["src_ip"], "10.0.1.50")
        self.assertEqual(res_nested["dest_ip"], "185.220.101.5")
        self.assertEqual(res_nested["src_port"], 49152)
        self.assertEqual(res_nested["dest_port"], 443)
        self.assertEqual(res_nested["user"], "victim_user")
        self.assertEqual(res_nested["file_hash"], "44d88612fea8a8f36de82e1278abb02f")
        self.assertEqual(res_nested["severity"], "HIGH")

        # B: Dotted flat keys in ECS JSON
        dotted_ecs = {
            "@timestamp": "2026-09-10T11:20:00Z",
            "source.ip": "10.0.1.50",
            "destination.ip": "185.220.101.5",
            "source.port": 5353,
            "destination.port": 53,
            "user.name": "victim_user",
            "event.action": "dns_lookup"
        }
        res_dotted = parse_elastic_ecs_log(dotted_ecs)
        self.assertEqual(res_dotted["src_ip"], "10.0.1.50")
        self.assertEqual(res_dotted["dest_ip"], "185.220.101.5")
        self.assertEqual(res_dotted["src_port"], 5353)
        self.assertEqual(res_dotted["dest_port"], 53)
        self.assertEqual(res_dotted["user"], "victim_user")

    # 3. Sentinel or ASIM records using SrcIpAddr and DstIpAddr
    def test_03_sentinel_asim_records(self):
        asim_record = {
            "TimeGenerated": "2026-09-10 12:30:00",
            "AlertDisplayName": "Suspicious RDP Login Attempt",
            "AlertSeverity": "High",
            "SrcIpAddr": "10.0.4.15",
            "DstIpAddr": "45.33.32.156",
            "SrcPortNumber": "50123",
            "DstPortNumber": "3389",
            "AccountName": "admin_user",
            "Computer": "DC-PRIMARY-01",
            "Activity": "LogonAttempt"
        }
        res = parse_sentinel_log(asim_record)
        self.assertEqual(res["src_ip"], "10.0.4.15")
        self.assertEqual(res["dest_ip"], "45.33.32.156")
        self.assertEqual(res["src_port"], 50123)
        self.assertEqual(res["dest_port"], 3389)
        self.assertEqual(res["user"], "admin_user")
        self.assertEqual(res["src_host"], "DC-PRIMARY-01")
        self.assertEqual(res["severity"], "HIGH")

    # 4. QRadar LEEF records with source and destination attributes
    def test_04_qradar_leef_records(self):
        leef_line = "LEEF:2.0|IBM|QRadar|7.5|NetworkAnomaly|sev=8\tsrc=10.0.2.100\tdst=194.26.29.112\tspt=5353\tdpt=53\tusr=net_admin\tdevTime=Sep 10 2026 14:00:00"
        res = parse_qradar_leef(leef_line)
        self.assertEqual(res["siem_source"], "QRadar")
        self.assertEqual(res["src_ip"], "10.0.2.100")
        self.assertEqual(res["dest_ip"], "194.26.29.112")
        self.assertEqual(res["src_port"], 5353)
        self.assertEqual(res["dest_port"], 53)
        self.assertEqual(res["user"], "net_admin")
        self.assertEqual(res["severity"], "HIGH")

    # 5. CSV records with vendor-specific column names
    def test_05_csv_records_vendor_columns(self):
        csv_content = """TimeGenerated,AlertName,SrcIpAddr,DstIpAddr,SrcPortNumber,DstPortNumber,AccountName,DeviceAction
2026-09-10T15:00:00Z,BruteForceAttempt,198.51.100.25,10.0.0.5,44123,3389,target_corp,Blocked
"""
        logs, count = ingest_dataset_content(csv_content, "csv")
        self.assertEqual(count, 1)
        row = logs[0]
        self.assertEqual(row["src_ip"], "198.51.100.25")
        self.assertEqual(row["dest_ip"], "10.0.0.5")
        self.assertEqual(row["src_port"], 44123)
        self.assertEqual(row["dest_port"], 3389)
        self.assertEqual(row["user"], "target_corp")
        self.assertEqual(row["action"], "Blocked")

    # 6. Missing source or destination endpoints
    def test_06_missing_source_or_destination_endpoints(self):
        # A host process execution alert has no network endpoints
        proc_alert = {
            "timestamp": "2026-09-10T16:00:00Z",
            "signature": "Host Registry Modification",
            "severity": "MEDIUM",
            "user": "sec_operator",
            "ProcessName": "reg.exe"
        }
        res = parse_splunk_log(proc_alert)
        self.assertIsNone(res["src_ip"])
        self.assertIsNone(res["dest_ip"])
        self.assertEqual(res["user"], "sec_operator")
        # Ensure event is NOT classified as failed
        self.assertIn(res["normalization_status"], ["success", "partial"])

    # 7. Conflicting aliases with different values
    def test_07_conflicting_aliases_with_different_values(self):
        # Log contains both 'src' and 'src_ip' with different values
        conflict_record = {
            "timestamp": "2026-09-10T17:00:00Z",
            "signature": "Conflicting Source IP Alert",
            "src": "10.0.0.1",
            "src_ip": "192.168.1.99"
        }
        event = SplunkAdapter.parse(conflict_record)
        self.assertGreater(len(event.conflicting_fields), 0)
        self.assertEqual(event.conflicting_fields[0]["field"], "src_ip")
        self.assertEqual(event.normalization_status, "partial")
        # Ensure the selected value is from the candidates
        self.assertIn(event.src_ip, ["10.0.0.1", "192.168.1.99"])

    # 8. String ports, invalid ports, and invalid IP addresses
    def test_08_string_ports_invalid_ports_and_invalid_ips(self):
        # Valid string port converted to integer
        p_val, p_err = validate_port("8080")
        self.assertEqual(p_val, 8080)
        self.assertIsNone(p_err)

        # Out-of-range port
        bad_port, port_err = validate_port("999999")
        self.assertIsNone(bad_port)
        self.assertIsNotNone(port_err)

        # Invalid IP address
        bad_ip, ip_err = validate_ip("999.888.777.666")
        self.assertIsNone(bad_ip)
        self.assertIsNotNone(ip_err)

        # Valid IPv6
        ipv6_val, v6_err = validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertEqual(ipv6_val, "2001:db8:85a3::8a2e:370:7334")
        self.assertIsNone(v6_err)

    # 9. Missing or differently formatted timestamps
    def test_09_missing_or_differently_formatted_timestamps(self):
        # Milliseconds epoch
        ts_epoch, err_epoch = standardize_timestamp(1725964800000)
        self.assertIn("2024", ts_epoch)
        self.assertIsNone(err_epoch)

        # Standard ISO string
        ts_iso, err_iso = standardize_timestamp("2026-09-10T08:15:00Z")
        self.assertIn("2026-09-10", ts_iso)
        self.assertIsNone(err_iso)

        # Missing timestamp should default to current UTC and produce non-fatal notification
        ts_missing, err_missing = standardize_timestamp(None)
        self.assertIsNotNone(ts_missing)
        self.assertIsNotNone(err_missing)

    # 10. Unknown fields that must be preserved
    def test_10_unknown_fields_preserved(self):
        custom_record = {
            "timestamp": "2026-09-10T18:00:00Z",
            "signature": "Custom Sensor Anomaly",
            "src": "10.0.0.5",
            "proprietary_sensor_tier": "Alpha-9",
            "custom_payload_telemetry": {"tag": "honeypot", "id": 1042}
        }
        res = parse_splunk_log(custom_record)
        self.assertIn("proprietary_sensor_tier", res["unmapped_fields"])
        self.assertIn("custom_payload_telemetry", res["unmapped_fields"])
        # Preserved in details
        self.assertEqual(res["details"]["proprietary_sensor_tier"], "Alpha-9")

    # 11. Malformed records and unsupported formats
    def test_11_malformed_records_and_unsupported_formats(self):
        # Malformed LEEF
        malformed_leef = "LEEF:BROKEN_NOT_ENOUGH_PIPES"
        res_leef = parse_qradar_leef(malformed_leef)
        self.assertEqual(res_leef["normalization_status"], "failed")
        self.assertGreater(len(res_leef["validation_errors"]), 0)

        # Malformed JSON string passed to ECS adapter
        res_bad_json = ElasticECSAdapter.parse("{ unclosed json: ")
        self.assertEqual(res_bad_json.normalization_status, "failed")

    # 12. Partially normalized events that must still be stored when permitted
    def test_12_partially_normalized_events_stored(self):
        partial_event = {
            "id": "partial-evt-test-01",
            "siem_source": "Sentinel",
            "timestamp": "2026-09-10T19:00:00Z",
            "alert_name": "Partially Mapped Sentinel Audit Event",
            "severity": "LOW",
            "normalization_status": "partial",
            "validation_errors": ["Unknown connector vendor code"],
            "unmapped_fields": ["internal_guid_ref"],
            "conflicting_fields": []
        }
        res = insert_logs([partial_event])
        self.assertEqual(int(res), 1)

        queried = query_logs(status="partial", limit=10)
        matching = [l for l in queried["logs"] if l["id"] == "partial-evt-test-01"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["normalization_status"], "partial")

    # 13. Threat-intelligence service failures that must not break normalization
    def test_13_threat_intel_service_failures_do_not_break_normalization(self):
        evt = CanonicalEvent({"src": "185.220.101.5"}, "Splunk")
        evt.src_ip = "185.220.101.5"
        evt.alert_name = "C2 Connection Test"
        evt.timestamp = datetime.now(timezone.utc).isoformat()

        # Simulate a failing threat intel lookup function
        def broken_lookup(indicator, ioc_type):
            raise ConnectionError("VirusTotal v3 API Endpoint Unreachable")

        # Normalization and enrichment must survive without crashing
        enrich_event_threat_intel(evt, lookup_fn=broken_lookup)
        self.assertEqual(evt.src_ip, "185.220.101.5")
        self.assertIn(evt.normalization_status, ["success", "partial"])

    # 14. Duplicate ingestion and reprocessing behavior
    def test_14_duplicate_ingestion_and_reprocessing(self):
        import uuid
        event_id = f"dedup-test-{uuid.uuid4()}"
        sample_log = {
            "id": event_id,
            "siem_source": "Splunk",
            "timestamp": "2026-09-10T20:00:00Z",
            "severity": "HIGH",
            "alert_name": "Duplicate Ingestion Test",
            "src_ip": "10.0.4.15",
            "dest_ip": "185.220.101.5",
            "normalization_status": "success",
            "raw_log": "09/10/2026 src=10.0.4.15 dest=185.220.101.5 action=drop"
        }

        # First insert
        res1 = insert_logs([sample_log], detect_duplicates=True)
        self.assertEqual(res1.summary["duplicates"], 0)

        # Duplicate insert
        res2 = insert_logs([sample_log], detect_duplicates=True)
        self.assertEqual(res2.summary["duplicates"], 1)

        # Reprocess stored log
        reprocess_res = reprocess_stored_logs(log_ids=[event_id])
        self.assertEqual(reprocess_res["status"], "success")
        self.assertEqual(reprocess_res["reprocessed_count"], 1)

        # Check coverage calculation
        coverage = get_mapping_coverage()
        self.assertGreater(coverage["total_events"], 0)
        self.assertIn("Splunk", coverage["sources"])
        self.assertIn("src_ip", coverage["canonical_field_coverage"])

if __name__ == "__main__":
    unittest.main()
