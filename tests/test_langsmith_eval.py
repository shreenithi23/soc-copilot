import unittest
import os
import json
from unittest.mock import patch, MagicMock

# Use test database
os.environ["DATABASE_PATH"] = "test_soc.db"

from app.database import init_db, record_eval_run, get_eval_runs, get_eval_run_by_id
from app.langsmith_eval import (
    EVALUATION_BENCHMARK,
    BENCHMARK_VERSION,
    DATASET_NAME,
    compute_f1,
    evaluate_ioc_case,
    evaluate_severity_case,
    evaluate_vt_case,
    evaluate_memory_case,
    evaluate_leef_case,
    target_runner,
    sync_langsmith_dataset_and_experiment,
    run_langsmith_evaluation
)

class TestLangSmithEvaluationPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_01_compute_f1_metrics(self):
        # Perfect match
        p, r, f1 = compute_f1({"1.1.1.1", "2.2.2.2"}, {"1.1.1.1", "2.2.2.2"})
        self.assertEqual(p, 1.0)
        self.assertEqual(r, 1.0)
        self.assertEqual(f1, 1.0)

        # Empty sets
        p, r, f1 = compute_f1(set(), set())
        self.assertEqual(p, 1.0)
        self.assertEqual(r, 1.0)
        self.assertEqual(f1, 1.0)

        # Partial match
        p, r, f1 = compute_f1({"1.1.1.1"}, {"1.1.1.1", "2.2.2.2"})
        self.assertEqual(p, 1.0)
        self.assertEqual(r, 0.5)
        self.assertAlmostEqual(f1, 0.6667, places=3)

        # False positives
        p, r, f1 = compute_f1({"1.1.1.1", "3.3.3.3"}, {"1.1.1.1"})
        self.assertEqual(p, 0.5)
        self.assertEqual(r, 1.0)
        self.assertAlmostEqual(f1, 0.6667, places=3)

    def test_02_ioc_evaluator_and_internal_filtering(self):
        case = next(c for c in EVALUATION_BENCHMARK if c["id"] == "eval-01")
        result = evaluate_ioc_case(case)
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["metrics"]["f1_score"], 1.0)
        self.assertTrue(result["metrics"]["internal_filtered"])
        # Ensure internal IP 10.0.1.20 was NOT treated as malicious external IOC
        self.assertNotIn("10.0.1.20", result["actual_output"]["ips"])
        self.assertIn("185.220.101.5", result["actual_output"]["ips"])
        self.assertIn("update-microsoft-cloud.top", result["actual_output"]["domains"])

    def test_03_severity_normalization_evaluator(self):
        case = next(c for c in EVALUATION_BENCHMARK if c["id"] == "eval-02")
        result = evaluate_severity_case(case)
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["metrics"]["accuracy"], 1.0)
        self.assertEqual(result["metrics"]["correct_sources"], 5)
        self.assertEqual(result["actual_output"]["Splunk"], "CRITICAL")
        self.assertEqual(result["actual_output"]["Elastic"], "MEDIUM")
        self.assertEqual(result["actual_output"]["Sentinel"], "HIGH")
        self.assertEqual(result["actual_output"]["QRadar"], "HIGH")
        self.assertEqual(result["actual_output"]["Wazuh"], "CRITICAL")

    @patch("app.langsmith_eval.lookup_ioc")
    def test_04_virustotal_threat_scoring_deterministic_mock(self, mock_lookup):
        mock_lookup.return_value = {
            "indicator": "185.220.101.5",
            "ioc_type": "ip",
            "malicious_count": 68,
            "suspicious_count": 4,
            "harmless_count": 0,
            "undetected_count": 12,
            "reputation": -85,
            "tags": ["tor-exit-node", "cobalt-strike", "c2-server"],
            "source": "VirusTotal v3 API"
        }
        case = next(c for c in EVALUATION_BENCHMARK if c["id"] == "eval-03")
        result = evaluate_vt_case(case)
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["metrics"]["schema_fidelity"], 1.0)
        self.assertTrue(result["metrics"]["threshold_met"])
        self.assertEqual(result["actual_output"]["malicious_count"], 68)

    def test_05_virustotal_threat_scoring_live_or_fallback(self):
        # Tests lookup_ioc directly with fallback if live key is absent or rate-limited
        case = next(c for c in EVALUATION_BENCHMARK if c["id"] == "eval-03")
        result = evaluate_vt_case(case)
        self.assertIn(result["status"], ["PASSED", "FAILED"])
        self.assertIn("malicious_count", result["actual_output"])

    @patch("langchain_google_genai.ChatGoogleGenerativeAI")
    def test_06_memory_recall_and_cross_session_isolation(self, mock_llm_cls):
        mock_instance = MagicMock()
        def fake_invoke(messages):
            full_text = " ".join(getattr(m, "content", "") for m in messages)
            if "172.31.99.88" in full_text:
                return MagicMock(content="We previously isolated server 172.31.99.88 and flagged user test_sec_user42.")
            return MagicMock(content="No active isolated hosts or users identified in current conversation.")
        mock_instance.invoke.side_effect = fake_invoke
        mock_llm_cls.return_value = mock_instance

        case = next(c for c in EVALUATION_BENCHMARK if c["id"] == "eval-04")
        result = evaluate_memory_case(case)
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["metrics"]["entity_recall"], 1.0)
        self.assertEqual(result["metrics"]["session_isolation"], 1.0)
        self.assertFalse(result["actual_output"]["cross_session_leak"])

    def test_07_qradar_leef_parsing_fidelity_and_edge_cases(self):
        case = next(c for c in EVALUATION_BENCHMARK if c["id"] == "eval-05")
        result = evaluate_leef_case(case)
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["metrics"]["primary_fidelity"], 1.0)
        self.assertEqual(result["metrics"]["edge_cases_fidelity"], 1.0)
        self.assertEqual(result["actual_output"]["src_ip"], "10.0.1.50")
        self.assertEqual(result["actual_output"]["dest_ip"], "194.26.29.112")
        self.assertEqual(result["actual_output"]["severity"], "CRITICAL")
        self.assertEqual(result["actual_output"]["user"], "jdoe")

    def test_08_missing_langsmith_credentials_behavior(self):
        # When LangSmith is unconfigured, sync should return NOT_CONFIGURED and never raise
        with patch("app.langsmith_eval.settings.is_langsmith_configured", return_value=False):
            sync_res = sync_langsmith_dataset_and_experiment([])
            self.assertEqual(sync_res["sync_status"], "NOT_CONFIGURED")
            self.assertIsNone(sync_res["experiment_url"])

    def test_09_remote_api_failure_handled_truthfully(self):
        with patch("app.langsmith_eval.settings.is_langsmith_configured", return_value=True):
            with patch("langsmith.Client", side_effect=Exception("Connection refused to api.smith.langchain.com")):
                sync_res = sync_langsmith_dataset_and_experiment([])
                self.assertEqual(sync_res["sync_status"], "FAILED")
                self.assertIn("Connection refused", sync_res["error_details"])
                self.assertIsNone(sync_res["experiment_url"])

    def test_10_sqlite_persistence_and_retrieval(self):
        test_run = {
            "id": "test-eval-unit-001",
            "run_name": "Unit Test Run",
            "dataset_name": DATASET_NAME,
            "benchmark_version": BENCHMARK_VERSION,
            "test_cases_count": 5,
            "passed_count": 5,
            "accuracy_score": 100.0,
            "avg_latency_ms": 12.5,
            "results": [{"id": "eval-01", "status": "PASSED"}],
            "aggregate_metrics": {"accuracy_score": 100.0},
            "experiment_name": "unit-test-exp-1",
            "experiment_url": "https://smith.langchain.com/o/test",
            "sync_status": "SYNCED",
            "error_details": None,
            "completed_at": "2026-10-25T12:00:00Z",
            "created_at": "2026-10-25T12:00:00Z",
            "langsmith_synced": True
        }
        record_eval_run(test_run)
        
        fetched = get_eval_run_by_id("test-eval-unit-001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], "test-eval-unit-001")
        self.assertEqual(fetched["sync_status"], "SYNCED")
        self.assertEqual(fetched["experiment_name"], "unit-test-exp-1")
        self.assertEqual(fetched["benchmark_version"], BENCHMARK_VERSION)
        self.assertEqual(fetched["accuracy_score"], 100.0)

    @patch("langchain_google_genai.ChatGoogleGenerativeAI")
    def test_11_secrets_redaction(self, mock_llm_cls):
        mock_instance = MagicMock()
        mock_instance.invoke.return_value = MagicMock(content="Host 172.31.99.88 and user test_sec_user42 are confirmed.")
        mock_llm_cls.return_value = mock_instance

        # Verify that no API keys or secrets leak in evaluation output
        eval_run = run_langsmith_evaluation(sync_remote=False)
        run_json = json.dumps(eval_run)
        for key_env in ["GEMINI_API_KEY", "VIRUSTOTAL_API_KEY", "LANGCHAIN_API_KEY"]:
            val = os.environ.get(key_env)
            if val and len(val) > 8:
                self.assertNotIn(val, run_json)

if __name__ == "__main__":
    unittest.main()
