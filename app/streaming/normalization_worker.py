"""
Normalization Worker for Redis Streams.
Consumes heterogeneous raw security events from 'security:raw', runs them through
the SOC Copilot Canonical Normalization Engine, validates schemas, and publishes
canonical events to 'security:normalized' or permanently malformed records to 'security:dlq'.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.config import (
    STREAM_RAW,
    STREAM_NORMALIZED,
    STREAM_DLQ,
    GROUP_NORMALIZERS,
    STREAM_BATCH_SIZE,
    STREAM_BLOCK_MS,
    STREAM_CLAIM_MIN_IDLE_MS,
)
from app.normalization_engine import normalize_single_record, CanonicalEvent
from app.streaming.redis_client import get_async_redis, xadd_json

logger = logging.getLogger("streaming.normalizer")


class NormalizationWorker:
    """
    Consumes raw security logs from Redis Stream 'security:raw' in consumer group 'group:normalizers'.
    Transforms logs into CanonicalEvent format, validating fields and timestamps.
    Safe failure handoff: Malformed records sent to 'security:dlq' with error diagnostics.
    """

    def __init__(self, consumer_name: Optional[str] = None):
        self.consumer_name = consumer_name or f"normalizer-{uuid.uuid4().hex[:6]}"
        self.is_running = False
        self.task: Optional[asyncio.Task] = None
        
        # Operational telemetry
        self.events_read = 0
        self.events_normalized = 0
        self.events_dlq = 0
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
        logger.info(f"NormalizationWorker '{self.consumer_name}' started.")

    async def stop(self) -> None:
        """Gracefully stop worker background loop."""
        self.is_running = False
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info(f"NormalizationWorker '{self.consumer_name}' stopped.")

    async def _run_loop(self) -> None:
        """Main consumer loop with recovery and DLQ handoff."""
        while self.is_running:
            try:
                redis = await get_async_redis()

                # 1. Recover abandoned pending messages via XAUTOCLAIM periodically (every 10s)
                now = time.time()
                if now - self._last_claim_check > 10.0:
                    self._last_claim_check = now
                    await self._recover_abandoned_messages(redis)

                # 2. Read new messages using XREADGROUP
                # Format: {stream_name: [(msg_id, {field: val})]}
                streams = {STREAM_RAW: ">"}
                response = await redis.xreadgroup(
                    groupname=GROUP_NORMALIZERS,
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
                        await self._process_message(redis, msg_id, raw_fields)

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
                logger.error(f"Error in NormalizationWorker loop: {e}")
                await asyncio.sleep(1.0)

    async def _recover_abandoned_messages(self, redis) -> None:
        """Check for and reclaim abandoned messages from crashed consumers."""
        try:
            # XAUTOCLAIM stream group consumer min-idle-time start [COUNT count]
            claim_res = await redis.xautoclaim(
                name=STREAM_RAW,
                groupname=GROUP_NORMALIZERS,
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
                    logger.warning(f"Reclaimed {len(claimed_msgs)} abandoned raw messages in '{self.consumer_name}'")
                    for msg_id, raw_fields in claimed_msgs:
                        await self._process_message(redis, msg_id, raw_fields)
        except Exception as e:
            logger.debug(f"XAUTOCLAIM check skipped or failed: {e}")

    async def _process_message(self, redis, msg_id: Any, raw_fields: Dict[Any, Any]) -> None:
        """Process a single raw message, normalize, publish to normalized or DLQ, and XACK."""
        self.events_read += 1
        self.last_active_at = datetime.now(timezone.utc).isoformat()

        # Decode field keys & values
        fields = {}
        for k, v in raw_fields.items():
            key_str = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            val_str = v.decode("utf-8") if isinstance(v, bytes) else str(v)
            fields[key_str] = val_str

        # Determine event ID and format hint
        event_id = fields.get("event_id") or fields.get("id") or str(uuid.uuid4())
        format_hint = fields.get("format_hint") or fields.get("format_type") or fields.get("siem_source") or "auto"

        # Unpack raw payload
        raw_record = None
        if "payload" in fields and fields["payload"]:
            payload_str = fields["payload"]
            try:
                if isinstance(payload_str, str) and (payload_str.startswith("{") or payload_str.startswith("[")):
                    raw_record = json.loads(payload_str)
                else:
                    raw_record = payload_str
            except Exception as json_err:
                # Permanently corrupt JSON -> Dead Letter Queue handoff
                await self._handoff_to_dlq(
                    redis=redis,
                    msg_id=msg_id,
                    event_id=event_id,
                    raw_payload=payload_str,
                    error=f"Invalid JSON payload: {json_err}",
                    source_format=format_hint,
                    diagnostics={"parsing_stage": "json_decode", "exception": str(json_err)},
                )
                return
        else:
            # The stream fields themselves are the raw record
            raw_record = {}
            for k, v in fields.items():
                if isinstance(v, str) and (v.startswith("{") or v.startswith("[")):
                    try:
                        raw_record[k] = json.loads(v)
                    except Exception:
                        raw_record[k] = v
                else:
                    raw_record[k] = v

        if isinstance(raw_record, dict):
            format_hint = raw_record.get("format_hint") or raw_record.get("format_type") or raw_record.get("siem_source") or format_hint
            event_id = raw_record.get("id") or raw_record.get("event_id") or event_id

        # Determine payload to normalize
        target_payload = raw_record
        if isinstance(raw_record, dict) and isinstance(raw_record.get("raw_log"), str) and raw_record["raw_log"].startswith("LEEF:"):
            target_payload = raw_record["raw_log"]

        # Run through Normalization Engine
        try:
            canonical: CanonicalEvent = normalize_single_record(target_payload, format_hint=format_hint)
            
            # Maintain the original event_id if provided
            if event_id:
                canonical.id = event_id

            # Check normalization outcome
            if canonical.normalization_status == "failed" or format_hint in ["unsupported", "corrupted", "dlq_test"]:
                # Validation policy failed or feed unsupported
                err_msg = f"Validation failed: {'; '.join(canonical.validation_errors)}" if canonical.validation_errors else f"Unsupported or corrupted feed format: {format_hint}"
                await self._handoff_to_dlq(
                    redis=redis,
                    msg_id=msg_id,
                    event_id=event_id,
                    raw_payload=raw_record,
                    error=err_msg,
                    source_format=format_hint,
                    diagnostics={
                        "parsing_stage": "validation",
                        "unmapped_fields": canonical.unmapped_fields,
                        "validation_errors": canonical.validation_errors,
                    },
                )
                return

            # Produce canonical event dictionary
            canonical_dict = canonical.to_dict()
            canonical_dict["ingested_at"] = self.last_active_at
            canonical_dict["stream_msg_id"] = str(msg_id, "utf-8") if isinstance(msg_id, bytes) else str(msg_id)

            # Publish to STREAM_NORMALIZED
            await xadd_json(STREAM_NORMALIZED, canonical_dict)
            self.events_normalized += 1

            # Acknowledge original raw message in STREAM_RAW
            await redis.xack(STREAM_RAW, GROUP_NORMALIZERS, msg_id)

        except Exception as norm_err:
            logger.error(f"Normalization exception for event {event_id}: {norm_err}", exc_info=True)
            await self._handoff_to_dlq(
                redis=redis,
                msg_id=msg_id,
                event_id=event_id,
                raw_payload=raw_record or payload_str,
                error=f"Engine exception: {norm_err}",
                source_format=format_hint,
                diagnostics={"parsing_stage": "normalization_engine", "exception": str(norm_err)},
            )

    async def _handoff_to_dlq(
        self,
        redis,
        msg_id: Any,
        event_id: str,
        raw_payload: Any,
        error: str,
        source_format: str,
        diagnostics: Dict[str, Any],
    ) -> None:
        """Safely route unparseable/failed event to DLQ and XACK original message."""
        self.events_dlq += 1
        dlq_entry = {
            "dlq_id": f"dlq-{uuid.uuid4().hex[:8]}",
            "event_id": event_id,
            "stream_msg_id": str(msg_id, "utf-8") if isinstance(msg_id, bytes) else str(msg_id),
            "source_format": source_format,
            "error": error,
            "diagnostics": diagnostics,
            "raw_payload": raw_payload if isinstance(raw_payload, str) else json.dumps(raw_payload),
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "reprocessed": False,
        }

        try:
            await xadd_json(STREAM_DLQ, dlq_entry)
            # Acknowledge raw message so it does not loop infinitely
            await redis.xack(STREAM_RAW, GROUP_NORMALIZERS, msg_id)
            logger.warning(f"Sent malformed event {event_id} to DLQ: {error}")
        except Exception as dlq_err:
            logger.error(f"Failed to publish event {event_id} to DLQ: {dlq_err}", exc_info=True)

    def get_status(self) -> Dict[str, Any]:
        """Return runtime status and metrics."""
        return {
            "consumer_name": self.consumer_name,
            "is_running": self.is_running,
            "events_read": self.events_read,
            "events_normalized": self.events_normalized,
            "events_dlq": self.events_dlq,
            "last_active_at": self.last_active_at,
            "last_error": self.last_error,
        }
