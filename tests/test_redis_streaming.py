import unittest
import time
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.config import (
    STREAM_RAW,
    STREAM_NORMALIZED,
    STREAM_ALERTS,
    STREAM_DLQ,
    GROUP_NORMALIZERS,
    GROUP_CORRELATORS,
    GROUP_PERSISTERS
)
from app.streaming.redis_client import (
    get_sync_redis,
    check_redis_health,
    setup_streams_and_groups
)
from app.database import (
    insert_correlated_alert,
    query_security_alerts
)

class TestRedisStreaming(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_ctx = TestClient(app)
        cls.client = cls.client_ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_ctx.__exit__(None, None, None)

    def test_01_redis_connection_and_setup(self):
        """Verify Redis server is reachable and stream groups can be provisioned."""
        r = get_sync_redis()
        self.assertTrue(r.ping(), "Redis sync ping failed")
        asyncio.run(setup_streams_and_groups())

        for stream_name, group_name in [
            (STREAM_RAW, GROUP_NORMALIZERS),
            (STREAM_NORMALIZED, GROUP_CORRELATORS),
            (STREAM_NORMALIZED, GROUP_PERSISTERS),
            (STREAM_ALERTS, GROUP_PERSISTERS)
        ]:
            groups = [g["name"].decode() if isinstance(g["name"], bytes) else g["name"] for g in r.xinfo_groups(stream_name)]
            self.assertIn(group_name, groups, f"Group {group_name} missing on stream {stream_name}")

    def test_02_producer_lifecycle_and_burst(self):
        """Verify synthetic producer can start, burst scenario events, and stop cleanly."""
        r = get_sync_redis()
        start_len = r.xlen(STREAM_RAW)

        res = self.client.post("/api/stream/trigger-scenario", json={"scenario": "brute_force", "count": 4})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["scenario"], "brute_force")
        self.assertEqual(data["events_published"], 4)

        time.sleep(0.5)
        end_len = r.xlen(STREAM_RAW)
        self.assertGreaterEqual(end_len, start_len + 4)

    def test_03_stream_status_endpoint(self):
        """Verify /api/stream/status returns detailed metrics and stream inspection."""
        res = self.client.get("/api/stream/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        
        self.assertTrue(data["redis_healthy"])
        self.assertIn("streams", data)
        self.assertIn(STREAM_RAW, data["streams"])
        self.assertIn(STREAM_NORMALIZED, data["streams"])
        self.assertIn(STREAM_ALERTS, data["streams"])
        self.assertIn(STREAM_DLQ, data["streams"])
        self.assertIn("producer", data)
        self.assertIn("workers", data)

    def test_04_dlq_and_reprocess(self):
        """Verify malformed records trigger DLQ routing and can be reprocessed."""
        res = self.client.post("/api/stream/trigger-scenario", json={"scenario": "dlq_test", "count": 2})
        self.assertEqual(res.status_code, 200)

        # Wait for normalizer to process and route to DLQ
        time.sleep(1.0)

        dlq_res = self.client.get("/api/stream/dlq")
        self.assertEqual(dlq_res.status_code, 200)
        dlq_data = dlq_res.json()
        self.assertGreaterEqual(dlq_data["total"], 1)
        
        first_item = dlq_data["dlq_events"][0]
        event_id = first_item["id"]

        reprocess_res = self.client.post(f"/api/stream/dlq/{event_id}/reprocess")
        self.assertEqual(reprocess_res.status_code, 200)
        rep_data = reprocess_res.json()
        self.assertTrue(rep_data["reprocessed"])

    def test_05_correlated_alerts_query(self):
        """Verify correlated alerts are retrieved with contributing events and evidence."""
        test_alert = {
            "alert_id": f"test-alert-{int(time.time())}",
            "rule_id": "RULE-AUTH-BRUTEFORCE",
            "severity": "CRITICAL",
            "title": "Integration Test: Password Spraying Detected",
            "description": "5 consecutive failed authentications",
            "user": "test_service_account",
            "host": "srv-app-01",
            "contributing_event_ids": ["evt-1", "evt-2", "evt-3"],
            "evidence": {"failure_count": 5, "window_seconds": 60}
        }
        insert_correlated_alert(test_alert)

        res = self.client.get("/api/alerts?user=test_service_account")
        self.assertEqual(res.status_code, 200)
        alerts = res.json().get("alerts", [])
        self.assertGreaterEqual(len(alerts), 1)
        
        matched = next((a for a in alerts if a["alert_id"] == test_alert["alert_id"]), None)
        self.assertIsNotNone(matched)
        self.assertEqual(matched["rule_id"], "RULE-AUTH-BRUTEFORCE")
        self.assertEqual(matched["severity"], "CRITICAL")
        self.assertIn("evt-1", matched["contributing_event_ids"])
        self.assertEqual(matched["evidence"]["failure_count"], 5)

if __name__ == "__main__":
    unittest.main()
