"""
Persistence Worker for Redis Streams.
Consumes normalized events from 'security:normalized' and correlated alerts from 'security:alerts'
in consumer group 'group:persisters', and idempotently persists them to SQLite database via
existing database layer functions (insert_logs, insert_correlated_alert).
Acknowledge (XACK) only after database commit.
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
    GROUP_PERSISTERS,
    STREAM_BATCH_SIZE,
    STREAM_BLOCK_MS,
    STREAM_CLAIM_MIN_IDLE_MS,
)
from app.database import insert_logs, insert_correlated_alert
from app.streaming.redis_client import get_async_redis

logger = logging.getLogger("streaming.persister")


class PersistenceWorker:
    """
    Consumes from Redis Streams 'security:normalized' and 'security:alerts',
    persisting records to SQLite idempotently and acknowledging each message.
    """

    def __init__(self, consumer_name: Optional[str] = None):
        self.consumer_name = consumer_name or f"persister-{uuid.uuid4().hex[:6]}"
        self.is_running = False
        self.task: Optional[asyncio.Task] = None

        # Operational telemetry
        self.events_persisted = 0
        self.alerts_persisted = 0
        self.last_active_at: Optional[str] = None
        self.last_error: Optional[str] = None
        self._claim_cursor_norm = "0-0"
        self._claim_cursor_alert = "0-0"
        self._last_claim_check = 0.0

    async def start(self) -> None:
        """Start worker background loop."""
        if self.is_running:
            return
        self.is_running = True
        self.task = asyncio.create_task(self._run_loop(), name=f"worker-{self.consumer_name}")
        logger.info(f"PersistenceWorker '{self.consumer_name}' started.")

    async def stop(self) -> None:
        """Gracefully stop worker background loop."""
        self.is_running = False
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info(f"PersistenceWorker '{self.consumer_name}' stopped.")

    async def _run_loop(self) -> None:
        """Main loop consuming normalized events and alerts."""
        while self.is_running:
            try:
                redis = await get_async_redis()

                # 1. Recover abandoned pending messages periodically (every 10s)
                now = time.time()
                if now - self._last_claim_check > 10.0:
                    self._last_claim_check = now
                    await self._recover_abandoned_messages(redis)

                # 2. Read new messages from both streams
                streams = {
                    STREAM_NORMALIZED: ">",
                    STREAM_ALERTS: ">",
                }
                response = await redis.xreadgroup(
                    groupname=GROUP_PERSISTERS,
                    consumername=self.consumer_name,
                    streams=streams,
                    count=STREAM_BATCH_SIZE,
                    block=STREAM_BLOCK_MS,
                )

                if not response:
                    await asyncio.sleep(0.05)
                    continue

                for stream_name, messages in response:
                    s_name = stream_name.decode("utf-8") if isinstance(stream_name, bytes) else str(stream_name)
                    if s_name == STREAM_NORMALIZED:
                        await self._persist_normalized_batch(redis, messages)
                    elif s_name == STREAM_ALERTS:
                        await self._persist_alerts_batch(redis, messages)

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
                logger.error(f"Error in PersistenceWorker loop: {e}")
                await asyncio.sleep(1.0)

    async def _recover_abandoned_messages(self, redis) -> None:
        """Recover abandoned messages from failed persistence consumers."""
        # Normalized stream
        try:
            claim_norm = await redis.xautoclaim(
                name=STREAM_NORMALIZED,
                groupname=GROUP_PERSISTERS,
                consumername=self.consumer_name,
                min_idle_time=STREAM_CLAIM_MIN_IDLE_MS,
                start_id=self._claim_cursor_norm,
                count=10,
            )
            if claim_norm and len(claim_norm) >= 2:
                next_cursor = claim_norm[0]
                claimed_msgs = claim_norm[1]
                self._claim_cursor_norm = str(next_cursor, "utf-8") if isinstance(next_cursor, bytes) else str(next_cursor)
                if claimed_msgs:
                    logger.warning(f"Reclaimed {len(claimed_msgs)} abandoned normalized messages in persister")
                    await self._persist_normalized_batch(redis, claimed_msgs)
        except Exception as e:
            logger.debug(f"Persistence autoclaim normalized error: {e}")

        # Alerts stream
        try:
            claim_alert = await redis.xautoclaim(
                name=STREAM_ALERTS,
                groupname=GROUP_PERSISTERS,
                consumername=self.consumer_name,
                min_idle_time=STREAM_CLAIM_MIN_IDLE_MS,
                start_id=self._claim_cursor_alert,
                count=10,
            )
            if claim_alert and len(claim_alert) >= 2:
                next_cursor = claim_alert[0]
                claimed_msgs = claim_alert[1]
                self._claim_cursor_alert = str(next_cursor, "utf-8") if isinstance(next_cursor, bytes) else str(next_cursor)
                if claimed_msgs:
                    logger.warning(f"Reclaimed {len(claimed_msgs)} abandoned alert messages in persister")
                    await self._persist_alerts_batch(redis, claimed_msgs)
        except Exception as e:
            logger.debug(f"Persistence autoclaim alert error: {e}")

    async def _persist_normalized_batch(self, redis, messages: List[Any]) -> None:
        """Batch persist normalized logs into siem_logs and acknowledge in Redis."""
        parsed_logs: List[Dict[str, Any]] = []
        msg_ids: List[Any] = []

        for msg_id, raw_fields in messages:
            msg_ids.append(msg_id)
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
            log_data = fields["payload"] if ("payload" in fields and isinstance(fields["payload"], dict)) else fields
            parsed_logs.append(log_data)

        if not parsed_logs:
            return

        try:
            # Idempotent insert into SQLite via insert_logs (uses INSERT OR REPLACE)
            # Offload synchronous SQLite call to thread pool to avoid blocking async loop
            await asyncio.to_thread(insert_logs, parsed_logs, False, True)
            
            # Acknowledge messages in Redis
            for m_id in msg_ids:
                await redis.xack(STREAM_NORMALIZED, GROUP_PERSISTERS, m_id)

            self.events_persisted += len(parsed_logs)
            self.last_active_at = datetime.now(timezone.utc).isoformat()

        except Exception as db_err:
            self.last_error = f"Database normalized persist failed: {db_err}"
            logger.error(self.last_error, exc_info=True)

    async def _persist_alerts_batch(self, redis, messages: List[Any]) -> None:
        """Persist correlated alerts into security_alerts and acknowledge in Redis."""
        for msg_id, raw_fields in messages:
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

            alert_data = fields["payload"] if ("payload" in fields and isinstance(fields["payload"], dict)) else fields

            try:
                # Idempotent insert into security_alerts table
                await asyncio.to_thread(insert_correlated_alert, alert_data)
                # Acknowledge in Redis
                await redis.xack(STREAM_ALERTS, GROUP_PERSISTERS, msg_id)
                self.alerts_persisted += 1
                self.last_active_at = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                self.last_error = f"Database alert persist failed: {e}"
                logger.error(self.last_error, exc_info=True)

    def get_status(self) -> Dict[str, Any]:
        """Return runtime status and metrics."""
        return {
            "consumer_name": self.consumer_name,
            "is_running": self.is_running,
            "events_persisted": self.events_persisted,
            "alerts_persisted": self.alerts_persisted,
            "last_active_at": self.last_active_at,
            "last_error": self.last_error,
        }
