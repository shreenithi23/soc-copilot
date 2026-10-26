"""
Stateful Correlation Worker for Redis Streams.
Consumes canonical security events from 'security:normalized' in consumer group 'group:correlators',
maintains bounded state in Redis with sliding time-window sorted sets and TTLs,
evaluates 4 core security detection rules, and publishes alerts to 'security:alerts'.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.config import (
    STREAM_NORMALIZED,
    STREAM_ALERTS,
    GROUP_CORRELATORS,
    STREAM_BATCH_SIZE,
    STREAM_BLOCK_MS,
    STREAM_CLAIM_MIN_IDLE_MS,
)
from app.streaming.redis_client import get_async_redis, xadd_json

logger = logging.getLogger("streaming.correlator")


class StatefulCorrelationWorker:
    """
    Evaluates multi-event correlation rules using Redis-backed sliding-window sorted sets.
    State survives worker restarts and auto-expires via TTL.
    """

    def __init__(self, consumer_name: Optional[str] = None):
        self.consumer_name = consumer_name or f"correlator-{uuid.uuid4().hex[:6]}"
        self.is_running = False
        self.task: Optional[asyncio.Task] = None
        
        # Operational telemetry
        self.events_analyzed = 0
        self.alerts_generated = 0
        self.last_active_at: Optional[str] = None
        self.last_error: Optional[str] = None
        self._claim_cursor = "0-0"
        self._last_claim_check = 0.0

    async def start(self) -> None:
        """Start worker background loop."""
        if self.is_running:
            return
        self.is_running = True
        self.task = asyncio.create_task(self._run_loop(), name=f"worker-{self.consumer_name}")
        logger.info(f"StatefulCorrelationWorker '{self.consumer_name}' started.")

    async def stop(self) -> None:
        """Gracefully stop worker background loop."""
        self.is_running = False
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info(f"StatefulCorrelationWorker '{self.consumer_name}' stopped.")

    async def _run_loop(self) -> None:
        """Main loop consuming normalized events and evaluating correlation rules."""
        while self.is_running:
            try:
                redis = await get_async_redis()

                # 1. Recover abandoned pending messages periodically (every 10s)
                now = time.time()
                if now - self._last_claim_check > 10.0:
                    self._last_claim_check = now
                    await self._recover_abandoned_messages(redis)

                # 2. Read new messages using XREADGROUP
                streams = {STREAM_NORMALIZED: ">"}
                response = await redis.xreadgroup(
                    groupname=GROUP_CORRELATORS,
                    consumername=self.consumer_name,
                    streams=streams,
                    count=STREAM_BATCH_SIZE,
                    block=STREAM_BLOCK_MS,
                )

                if not response:
                    await asyncio.sleep(0.05)
                    continue

                for stream_name, messages in response:
                    for msg_id, raw_fields in messages:
                        await self._process_event(redis, msg_id, raw_fields)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.last_error = str(e)
                if "NOGROUP" in str(e):
                    from app.streaming.redis_client import setup_streams_and_groups
                    try:
                        await setup_streams_and_groups()
                    except Exception:
                        pass
                logger.error(f"Error in StatefulCorrelationWorker loop: {e}")
                await asyncio.sleep(1.0)

    async def _recover_abandoned_messages(self, redis) -> None:
        """Recover pending unacknowledged messages using XAUTOCLAIM."""
        try:
            claim_res = await redis.xautoclaim(
                name=STREAM_NORMALIZED,
                groupname=GROUP_CORRELATORS,
                consumername=self.consumer_name,
                min_idle_time=STREAM_CLAIM_MIN_IDLE_MS,
                start_id=self._claim_cursor,
                count=10,
            )
            if claim_res and len(claim_res) >= 2:
                next_cursor = claim_res[0]
                claimed_msgs = claim_res[1]
                self._claim_cursor = str(next_cursor, "utf-8") if isinstance(next_cursor, bytes) else str(next_cursor)
                if claimed_msgs:
                    logger.warning(f"Reclaimed {len(claimed_msgs)} abandoned normalized messages in '{self.consumer_name}'")
                    for msg_id, raw_fields in claimed_msgs:
                        await self._process_event(redis, msg_id, raw_fields)
        except Exception as e:
            logger.debug(f"XAUTOCLAIM check in correlator: {e}")

    async def _process_event(self, redis, msg_id: Any, raw_fields: Dict[Any, Any]) -> None:
        """Evaluate event against the 4 detection rules, emit alerts if matched, and XACK."""
        self.events_analyzed += 1
        self.last_active_at = datetime.now(timezone.utc).isoformat()

        # Decode field keys & values
        fields: Dict[str, Any] = {}
        for k, v in raw_fields.items():
            key_str = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            val_str = v.decode("utf-8") if isinstance(v, bytes) else str(v)
            if val_str.startswith("{") or val_str.startswith("["):
                try:
                    fields[key_str] = json.loads(val_str)
                except Exception:
                    fields[key_str] = val_str
            else:
                fields[key_str] = val_str

        # If payload was serialized inside 'payload' field, unnest it
        event = fields["payload"] if ("payload" in fields and isinstance(fields["payload"], dict)) else fields

        # Evaluate rules
        try:
            await self._eval_rule1_brute_force(redis, event)
            await self._eval_rule2_auth_compromise(redis, event)
            await self._eval_rule3_endpoint_sequence(redis, event)
            await self._eval_rule4_unusual_outbound(redis, event)
        except Exception as err:
            logger.error(f"Rule evaluation error for event {event.get('id')}: {err}", exc_info=True)
        finally:
            # Acknowledge normalized event
            try:
                await redis.xack(STREAM_NORMALIZED, GROUP_CORRELATORS, msg_id)
            except Exception as ack_err:
                logger.error(f"Failed to XACK normalized event {msg_id}: {ack_err}")

    # =========================================================================
    # RULE 1: Repeated Authentication Failures (Brute Force)
    # Window: 60s, Threshold: >= 3 failed logins on same user or source IP
    # =========================================================================
    async def _eval_rule1_brute_force(self, redis, event: Dict[str, Any]) -> None:
        event_type = str(event.get("event_type", "")).lower()
        action = str(event.get("action", "")).lower()
        alert_name = str(event.get("alert_name", "")).lower()
        raw_log = str(event.get("raw_log", "")).lower()
        details_str = str(event.get("details", "")).lower()

        is_auth_failure = (
            "auth_failure" in event_type
            or "failed" in event_type
            or "failedlogon" in event_type
            or "failed" in action
            or "failure" in action
            or "fail" in action
            or "failed" in alert_name
            or "failure" in alert_name
            or "4625" in raw_log
            or "4625" in details_str
        )
        if not is_auth_failure:
            return

        user = event.get("user") or event.get("src_user") or "unknown_user"
        src_ip = event.get("src_ip") or "unknown_src"
        event_id = event.get("id") or str(uuid.uuid4())
        now_ts = time.time()
        window_sec = 60
        threshold = 3

        # State key in Redis
        state_key = f"corr:auth_fails:{user}:{src_ip}"
        cooldown_key = f"corr:cooldown:RULE-AUTH-BRUTEFORCE:{user}:{src_ip}"

        # Sliding window using Sorted Set
        # Add event_id with score = now_ts
        pipe = redis.pipeline()
        pipe.zadd(state_key, {event_id: now_ts})
        # Remove events older than now - window_sec
        pipe.zremrangebyscore(state_key, 0, now_ts - window_sec)
        # Count remaining
        pipe.zcard(state_key)
        # Fetch event IDs in window
        pipe.zrange(state_key, 0, -1)
        # Set TTL on state set
        pipe.expire(state_key, window_sec * 2)
        results = await pipe.execute()

        count = results[2]
        event_ids_bytes = results[3]
        event_ids = [e.decode("utf-8") if isinstance(e, bytes) else str(e) for e in event_ids_bytes]

        if count >= threshold:
            # Check cooldown to prevent duplicate alert storms
            in_cooldown = await redis.get(cooldown_key)
            if not in_cooldown:
                await redis.set(cooldown_key, "1", ex=90)  # 90s cooldown
                await self._publish_alert(
                    rule_id="RULE-AUTH-BRUTEFORCE",
                    rule_name="Repeated Authentication Failures (Brute Force Detected)",
                    severity="HIGH",
                    description=f"Detected {count} consecutive authentication failures for account '{user}' from source {src_ip} within {window_sec}s.",
                    user=user,
                    host=event.get("src_host") or src_ip,
                    src_ip=src_ip,
                    dest_ip=event.get("dest_ip"),
                    contributing_event_ids=event_ids,
                    correlation_window_sec=window_sec,
                    evidence={
                        "failure_count": count,
                        "threshold": threshold,
                        "time_window_seconds": window_sec,
                        "victim_user": user,
                        "attacker_ip": src_ip,
                        "sample_event_id": event_id,
                    },
                )

    # =========================================================================
    # RULE 2: Failures Followed by Successful Authentication
    # Window: 120s, Pattern: >= 2 failures followed by 1 successful login
    # =========================================================================
    async def _eval_rule2_auth_compromise(self, redis, event: Dict[str, Any]) -> None:
        event_type = str(event.get("event_type", "")).lower()
        action = str(event.get("action", "")).lower()
        alert_name = str(event.get("alert_name", "")).lower()

        raw_log = str(event.get("raw_log", "")).lower()

        is_auth_success = (
            "auth_success" in event_type
            or "success" in action
            or "successful" in alert_name
            or "logon_success" in event_type
            or "4624" in raw_log
        )
        if not is_auth_success:
            return

        user = event.get("user") or event.get("src_user") or "unknown_user"
        src_ip = event.get("src_ip") or "unknown_src"
        event_id = event.get("id") or str(uuid.uuid4())
        now_ts = time.time()
        window_sec = 120

        state_key = f"corr:auth_fails:{user}:{src_ip}"
        cooldown_key = f"corr:cooldown:RULE-AUTH-COMPROMISE:{user}:{src_ip}"

        # Check if there were prior failures in the state key
        prior_failures_bytes = await redis.zrange(state_key, 0, -1)
        if not prior_failures_bytes:
            return

        prior_ids = [e.decode("utf-8") if isinstance(e, bytes) else str(e) for e in prior_failures_bytes]
        if len(prior_ids) >= 2:
            in_cooldown = await redis.get(cooldown_key)
            if not in_cooldown:
                await redis.set(cooldown_key, "1", ex=120)
                all_ids = prior_ids + [event_id]
                await self._publish_alert(
                    rule_id="RULE-AUTH-COMPROMISE",
                    rule_name="Successful Authentication Following Repeated Failures (Potential Account Compromise)",
                    severity="CRITICAL",
                    description=f"Account '{user}' successfully logged in from {src_ip} immediately following {len(prior_ids)} failed attempts.",
                    user=user,
                    host=event.get("src_host") or src_ip,
                    src_ip=src_ip,
                    dest_ip=event.get("dest_ip"),
                    contributing_event_ids=all_ids,
                    correlation_window_sec=window_sec,
                    evidence={
                        "prior_failure_count": len(prior_ids),
                        "successful_login_event": event_id,
                        "user": user,
                        "source_ip": src_ip,
                        "assessment": "High probability of credential stuffing or brute force success",
                    },
                )
                # Clear failure state so next login won't re-trigger immediately
                await redis.delete(state_key)

    # =========================================================================
    # RULE 3: Suspicious Endpoint Sequence
    # Window: 180s, Pattern: Process execution + File activity + Endpoint alert on same host/user
    # =========================================================================
    async def _eval_rule3_endpoint_sequence(self, redis, event: Dict[str, Any]) -> None:
        event_type = str(event.get("event_type", "")).lower()
        alert_name = str(event.get("alert_name", "")).lower()
        process_cmd = str(event.get("process_cmd", "")).lower()
        process_name = str(event.get("process_name", "")).lower()
        file_name = str(event.get("file_name", "")).lower()
        host = event.get("src_host") or event.get("dest_host") or "unknown_host"
        user = event.get("user") or "unknown_user"
        event_id = event.get("id") or str(uuid.uuid4())
        now_ts = time.time()
        window_sec = 180

        # Classify activity
        is_suspicious_proc = any(
            t in process_cmd or t in process_name
            for t in ["mimikatz", "powershell", "certutil", "whoami", "rundll32", "regsvr32", "cmd.exe"]
        ) or "process_creation" in event_type
        
        is_file_act = (
            "file" in event_type
            or any(ext in file_name for ext in [".exe", ".bat", ".ps1", ".vbs", ".dll", ".zip"])
            or "file_mod" in event_type
        )
        
        is_edr_alert = (
            "alert" in event_type
            or "edr" in alert_name
            or "credential" in alert_name
            or "tamper" in alert_name
            or event.get("severity") in ["HIGH", "CRITICAL"]
        )

        stage = None
        if is_suspicious_proc:
            stage = "process"
        elif is_file_act:
            stage = "file"
        elif is_edr_alert:
            stage = "edr"

        if not stage:
            return

        state_key = f"corr:endpoint_seq:{host}"
        cooldown_key = f"corr:cooldown:RULE-ENDPOINT-CHAIN:{host}"

        # Record stage entry: JSON string {stage, event_id, time}
        entry = json.dumps({"stage": stage, "id": event_id, "time": now_ts, "user": user})
        pipe = redis.pipeline()
        pipe.zadd(state_key, {entry: now_ts})
        pipe.zremrangebyscore(state_key, 0, now_ts - window_sec)
        pipe.zrange(state_key, 0, -1)
        pipe.expire(state_key, window_sec * 2)
        results = await pipe.execute()

        raw_entries = results[2]
        stages_seen = set()
        contributing_ids = []
        for r in raw_entries:
            val = r.decode("utf-8") if isinstance(r, bytes) else str(r)
            try:
                p = json.loads(val)
                stages_seen.add(p.get("stage"))
                contributing_ids.append(p.get("id"))
            except Exception:
                pass

        # If >= 2 distinct stages seen in the sequence window
        if len(stages_seen) >= 2:
            in_cooldown = await redis.get(cooldown_key)
            if not in_cooldown:
                await redis.set(cooldown_key, "1", ex=120)
                await self._publish_alert(
                    rule_id="RULE-ENDPOINT-CHAIN",
                    rule_name="Suspicious Multi-Stage Endpoint Attack Sequence",
                    severity="CRITICAL" if len(stages_seen) >= 3 else "HIGH",
                    description=f"Correlated multi-stage attack telemetry on host '{host}' (stages: {', '.join(sorted(stages_seen))}) within {window_sec}s.",
                    user=user,
                    host=host,
                    src_ip=event.get("src_ip"),
                    dest_ip=event.get("dest_ip"),
                    contributing_event_ids=contributing_ids,
                    correlation_window_sec=window_sec,
                    evidence={
                        "stages_detected": list(stages_seen),
                        "host": host,
                        "user": user,
                        "latest_process": event.get("process_name") or event.get("process_cmd"),
                        "latest_file": event.get("file_name"),
                        "window_sec": window_sec,
                    },
                )

    # =========================================================================
    # RULE 4: Unusual Outbound Traffic / C2 Beaconing
    # Window: 120s, Pattern: Unusual external port or suspicious destination + DNS
    # =========================================================================
    async def _eval_rule4_unusual_outbound(self, redis, event: Dict[str, Any]) -> None:
        dest_port = event.get("dest_port")
        dest_ip = event.get("dest_ip") or ""
        domain = event.get("domain") or ""
        event_type = str(event.get("event_type", "")).lower()
        src_ip = event.get("src_ip") or "unknown_src"
        event_id = event.get("id") or str(uuid.uuid4())
        now_ts = time.time()
        window_sec = 120

        suspicious_ports = {4444, 8888, 1337, 9001, 6667, 8443, 31337}
        is_suspicious_port = dest_port in suspicious_ports
        is_suspicious_dns = any(d in domain.lower() for d in [".ru", ".xyz", ".top", "c2", "beacon", "malicious"])
        is_outbound_telemetry = (
            "network" in event_type
            or "firewall" in event_type
            or "c2" in event_type
            or is_suspicious_port
            or is_suspicious_dns
        )
        if not is_outbound_telemetry:
            return

        state_key = f"corr:c2_outbound:{src_ip}"
        cooldown_key = f"corr:cooldown:RULE-NET-C2-OUTBOUND:{src_ip}"

        entry = json.dumps({"id": event_id, "dest_ip": dest_ip, "port": dest_port, "domain": domain, "ts": now_ts})
        pipe = redis.pipeline()
        pipe.zadd(state_key, {entry: now_ts})
        pipe.zremrangebyscore(state_key, 0, now_ts - window_sec)
        pipe.zrange(state_key, 0, -1)
        pipe.expire(state_key, window_sec * 2)
        results = await pipe.execute()

        raw_entries = results[2]
        contributing_ids = []
        has_anomalous_port = False
        has_dns_or_domain = False
        for r in raw_entries:
            val = r.decode("utf-8") if isinstance(r, bytes) else str(r)
            try:
                p = json.loads(val)
                contributing_ids.append(p.get("id"))
                if p.get("port") in suspicious_ports:
                    has_anomalous_port = True
                if p.get("domain"):
                    has_dns_or_domain = True
            except Exception:
                pass

        # Trigger if anomalous port is observed or repeated outbound burst >= 3
        if has_anomalous_port or (has_dns_or_domain and len(contributing_ids) >= 2) or len(contributing_ids) >= 3:
            in_cooldown = await redis.get(cooldown_key)
            if not in_cooldown:
                await redis.set(cooldown_key, "1", ex=120)
                await self._publish_alert(
                    rule_id="RULE-NET-C2-OUTBOUND",
                    rule_name="Unusual Outbound Network Traffic / Suspected C2 Beacon",
                    severity="HIGH",
                    description=f"Observed anomalous outbound traffic from host {src_ip} targeting {dest_ip}:{dest_port} (domain: {domain or 'N/A'}).",
                    user=event.get("user") or "system",
                    host=event.get("src_host") or src_ip,
                    src_ip=src_ip,
                    dest_ip=dest_ip,
                    contributing_event_ids=contributing_ids,
                    correlation_window_sec=window_sec,
                    evidence={
                        "source_host": src_ip,
                        "destination_target": f"{dest_ip}:{dest_port}",
                        "domain_query": domain,
                        "suspicious_port": is_suspicious_port,
                        "burst_count": len(contributing_ids),
                        "window_sec": window_sec,
                    },
                )

    # =========================================================================
    # Alert Publisher Helper
    # =========================================================================
    async def _publish_alert(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        description: str,
        user: Optional[str],
        host: Optional[str],
        src_ip: Optional[str],
        dest_ip: Optional[str],
        contributing_event_ids: List[str],
        correlation_window_sec: int,
        evidence: Dict[str, Any],
    ) -> None:
        """Construct canonical alert payload and publish to STREAM_ALERTS."""
        alert_id = f"alert-{uuid.uuid4().hex[:10]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        alert_payload = {
            "id": alert_id,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "description": description,
            "user": user,
            "host": host,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "contributing_event_ids": contributing_event_ids,
            "evidence": evidence,
            "correlation_window_sec": correlation_window_sec,
            "created_at": now_iso,
        }

        try:
            await xadd_json(STREAM_ALERTS, alert_payload)
            self.alerts_generated += 1
            logger.warning(f"CORRELATED ALERT [{severity}] {rule_id}: {rule_name} (entity: {user}@{host})")
        except Exception as e:
            logger.error(f"Failed to publish alert to {STREAM_ALERTS}: {e}", exc_info=True)

    def get_status(self) -> Dict[str, Any]:
        """Return runtime status and metrics."""
        return {
            "consumer_name": self.consumer_name,
            "is_running": self.is_running,
            "events_analyzed": self.events_analyzed,
            "alerts_generated": self.alerts_generated,
            "last_active_at": self.last_active_at,
            "last_error": self.last_error,
        }
