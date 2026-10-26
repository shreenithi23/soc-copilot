"""
Central Stream Lifecycle Manager and Real-Time Event Hub.
Manages the synthetic producer, normalization worker, correlation worker, persistence worker,
aggregates end-to-end pipeline metrics, and provides an async generator for Server-Sent Events (SSE).
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional, Set

from app.config import (
    STREAM_RAW,
    STREAM_NORMALIZED,
    STREAM_ALERTS,
    STREAM_DLQ,
)
from app.streaming.redis_client import (
    check_redis_health,
    get_async_redis,
    get_stream_metrics,
    setup_streams_and_groups,
    xadd_json,
)
from app.streaming.producer import synthetic_producer, SyntheticLogProducer
from app.streaming.normalization_worker import NormalizationWorker
from app.streaming.correlation_worker import StatefulCorrelationWorker
from app.streaming.persistence_worker import PersistenceWorker

logger = logging.getLogger("streaming.manager")


class StreamManager:
    """
    Singleton orchestrator for Redis Streams pipeline.
    Controls initialization, worker lifecycles, real-time SSE event subscriptions,
    and pipeline operational telemetry.
    """

    def __init__(self):
        self.producer: SyntheticLogProducer = synthetic_producer
        self.normalizer: NormalizationWorker = NormalizationWorker()
        self.correlator: StatefulCorrelationWorker = StatefulCorrelationWorker()
        self.persister: PersistenceWorker = PersistenceWorker()
        
        self.is_initialized = False
        self._broadcaster_task: Optional[asyncio.Task] = None
        self._subscribers: Set[asyncio.Queue] = set()
        self._running = False
        self._start_time = time.time()

    async def initialize(self) -> bool:
        """Initialize Redis connection, streams, and consumer groups."""
        try:
            health = await check_redis_health()
            if not health.get("connected"):
                logger.warning(f"Redis not available during StreamManager initialization: {health.get('error')}")
                return False

            await setup_streams_and_groups()
            self.is_initialized = True
            logger.info("StreamManager initialized Redis streams and consumer groups successfully.")
            return True
        except Exception as e:
            logger.error(f"StreamManager initialization failed: {e}", exc_info=True)
            return False

    async def start_all(self, start_producer: bool = False) -> None:
        """Start all workers and broadcaster. Producer starts only if explicitly enabled."""
        if not self._running:
            # Ensure streams & consumer groups are ready
            await self.initialize()

            self._running = True
            await self.normalizer.start()
            await self.correlator.start()
            await self.persister.start()
            self._broadcaster_task = asyncio.create_task(self._run_live_broadcaster(), name="sse-broadcaster")
            logger.info("StreamManager started all background streaming workers.")

        if start_producer and not self.producer.is_running:
            await self.producer.start()

    async def stop_all(self) -> None:
        """Gracefully stop all streaming workers and producer."""
        self._running = False

        # Stop producer first to halt incoming raw logs
        if self.producer.is_running:
            await self.producer.stop()

        # Stop workers
        await self.normalizer.stop()
        await self.correlator.stop()
        await self.persister.stop()

        if self._broadcaster_task and not self._broadcaster_task.done():
            self._broadcaster_task.cancel()
            try:
                await self._broadcaster_task
            except asyncio.CancelledError:
                pass

        logger.info("StreamManager stopped all streaming workers.")

    # =========================================================================
    # Live Real-Time SSE Broadcaster
    # Reads newest events from STREAM_NORMALIZED and STREAM_ALERTS and pushes
    # to connected SSE client queues without consuming from worker consumer groups.
    # =========================================================================
    async def _run_live_broadcaster(self) -> None:
        """Tail normalized events and alerts for connected frontend clients."""
        norm_last_id = "$"
        alert_last_id = "$"

        while self._running:
            try:
                if not self._subscribers:
                    await asyncio.sleep(0.2)
                    continue

                redis = await get_async_redis()
                # XREAD without group reads newly arrived messages for live display
                streams = {
                    STREAM_NORMALIZED: norm_last_id,
                    STREAM_ALERTS: alert_last_id,
                }
                res = await redis.xread(streams=streams, count=20, block=500)
                if not res:
                    continue

                for stream_name, messages in res:
                    s_name = stream_name.decode("utf-8") if isinstance(stream_name, bytes) else str(stream_name)
                    for msg_id, raw_fields in messages:
                        m_id_str = msg_id.decode("utf-8") if isinstance(msg_id, bytes) else str(msg_id)
                        
                        fields: Dict[str, Any] = {}
                        for k, v in raw_fields.items():
                            k_s = k.decode("utf-8") if isinstance(k, bytes) else str(k)
                            v_s = v.decode("utf-8") if isinstance(v, bytes) else str(v)
                            if v_s.startswith("{") or v_s.startswith("["):
                                try:
                                    fields[k_s] = json.loads(v_s)
                                except Exception:
                                    fields[k_s] = v_s
                            else:
                                fields[k_s] = v_s

                        actual_data = fields["payload"] if ("payload" in fields and isinstance(fields["payload"], dict)) else fields

                        if s_name == STREAM_NORMALIZED:
                            norm_last_id = m_id_str
                            event_data = {
                                **(actual_data if isinstance(actual_data, dict) else {}),
                                "type": "event",
                                "stream": "normalized",
                                "timestamp": (actual_data.get("timestamp") if isinstance(actual_data, dict) else None) or datetime.now(timezone.utc).isoformat(),
                            }
                            await self._fanout(event_data)
                        elif s_name == STREAM_ALERTS:
                            alert_last_id = m_id_str
                            alert_data = {
                                **(actual_data if isinstance(actual_data, dict) else {}),
                                "type": "correlated_alert",
                                "stream": "alerts",
                                "timestamp": (actual_data.get("created_at") if isinstance(actual_data, dict) else None) or datetime.now(timezone.utc).isoformat(),
                            }
                            await self._fanout(alert_data)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Broadcaster loop tick error: {e}")
                await asyncio.sleep(1.0)

    async def _fanout(self, payload: Dict[str, Any]) -> None:
        """Push payload to all active client subscriber queues."""
        dead_queues = []
        for q in self._subscribers:
            try:
                if q.qsize() < 100:  # Prevent memory backlog
                    q.put_nowait(payload)
            except Exception:
                dead_queues.append(q)

        for dq in dead_queues:
            self._subscribers.discard(dq)

    async def subscribe_live_events(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Async generator yielding SSE messages to a connected web client."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        
        # Initial greeting event
        yield {
            "event": "message",
            "data": json.dumps({
                "type": "connected",
                "message": "Connected to SOC Copilot Redis Stream Live Feed",
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "streams": [STREAM_RAW, STREAM_NORMALIZED, STREAM_ALERTS, STREAM_DLQ],
            }),
        }

        try:
            # Yield recent historical events from STREAM_NORMALIZED so UI displays immediate data
            try:
                redis_client = await get_async_redis()
                historical = await redis_client.xrevrange(STREAM_NORMALIZED, max="+", min="-", count=15)
                for h_id, h_fields in reversed(historical):
                    h_dict = {}
                    for hk, hv in h_fields.items():
                        hk_s = hk.decode("utf-8") if isinstance(hk, bytes) else str(hk)
                        hv_s = hv.decode("utf-8") if isinstance(hv, bytes) else str(hv)
                        if hv_s.startswith("{") or hv_s.startswith("["):
                            try:
                                h_dict[hk_s] = json.loads(hv_s)
                            except Exception:
                                h_dict[hk_s] = hv_s
                        else:
                            h_dict[hk_s] = hv_s
                    h_payload = h_dict["payload"] if ("payload" in h_dict and isinstance(h_dict["payload"], dict)) else h_dict
                    yield {
                        "event": "message",
                        "data": json.dumps({
                            **(h_payload if isinstance(h_payload, dict) else {}),
                            "type": "event",
                            "stream": "normalized",
                        }),
                    }
            except Exception as e:
                logger.debug(f"Failed to yield initial stream history: {e}")

            last_heartbeat = time.time()
            while True:
                try:
                    # Timeout every 10 seconds to send heartbeat
                    item = await asyncio.wait_for(q.get(), timeout=10.0)
                    yield {
                        "event": "message",
                        "data": json.dumps(item),
                    }
                except asyncio.TimeoutError:
                    # SSE heartbeat keep-alive
                    now = time.time()
                    if now - last_heartbeat >= 10.0:
                        last_heartbeat = now
                        metrics = await self.get_pipeline_status()
                        yield {
                            "event": "message",
                            "data": json.dumps({
                                "type": "heartbeat",
                                "status": "alive",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "metrics": metrics.get("metrics", {}),
                            }),
                        }
        finally:
            self._subscribers.discard(q)

    # =========================================================================
    # Status and Operational Telemetry
    # =========================================================================
    async def get_pipeline_status(self) -> Dict[str, Any]:
        """Aggregate real-time metrics across Redis, Producer, and Workers."""
        redis_health = await check_redis_health()
        stream_metrics = await get_stream_metrics() if redis_health.get("connected") else {}
        producer_status = self.producer.get_status()
        normalizer_status = self.normalizer.get_status()
        correlator_status = self.correlator.get_status()
        persister_status = self.persister.get_status()

        # Processing latency estimate
        total_produced = producer_status.get("total_produced", 0)
        total_normalized = normalizer_status.get("events_normalized", 0)
        total_alerts = correlator_status.get("alerts_generated", 0)
        total_dlq = normalizer_status.get("events_dlq", 0)

        return {
            "redis_healthy": redis_health.get("connected", False),
            "system": {
                "redis_connected": redis_health.get("connected", False),
                "redis_ping_ms": redis_health.get("ping_ms"),
                "redis_version": redis_health.get("version"),
                "uptime_seconds": round(time.time() - self._start_time, 1),
                "active_subscribers": len(self._subscribers),
            },
            "producer": producer_status,
            "workers": {
                "normalizer": normalizer_status,
                "correlator": correlator_status,
                "persister": persister_status,
            },
            "streams": stream_metrics,
            "metrics": {
                "events_produced": total_produced,
                "events_normalized": total_normalized,
                "alerts_generated": total_alerts,
                "dlq_count": total_dlq,
                "events_persisted": persister_status.get("events_persisted", 0),
                "alerts_persisted": persister_status.get("alerts_persisted", 0),
                "current_rate_eps": producer_status.get("events_per_second", 0),
            },
        }

    # =========================================================================
    # Dead Letter Queue (DLQ) Inspection and Reprocessing
    # =========================================================================
    async def get_dlq_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch latest malformed/failed events from STREAM_DLQ for analyst inspection."""
        try:
            redis = await get_async_redis()
            # XREVRANGE reads newest records from stream
            entries = await redis.xrevrange(STREAM_DLQ, max="+", min="-", count=limit)
            result = []
            for msg_id, raw_fields in entries:
                m_id = msg_id.decode("utf-8") if isinstance(msg_id, bytes) else str(msg_id)
                fields: Dict[str, Any] = {"stream_msg_id": m_id}
                for k, v in raw_fields.items():
                    k_s = k.decode("utf-8") if isinstance(k, bytes) else str(k)
                    v_s = v.decode("utf-8") if isinstance(v, bytes) else str(v)
                    if v_s.startswith("{") or v_s.startswith("["):
                        try:
                            fields[k_s] = json.loads(v_s)
                        except Exception:
                            fields[k_s] = v_s
                    else:
                        fields[k_s] = v_s
                if "id" not in fields:
                    fields["id"] = fields.get("event_id") or fields.get("dlq_id") or m_id
                result.append(fields)
            return result
        except Exception as e:
            logger.error(f"Failed to fetch DLQ events: {e}")
            return []

    async def reprocess_dlq_event(self, event_id: str, format_hint: Optional[str] = None) -> Dict[str, Any]:
        """
        Locate event in DLQ and re-publish back to 'security:raw' with optional corrected format hint.
        """
        try:
            dlq_records = await self.get_dlq_events(limit=100)
            target = None
            for rec in dlq_records:
                if rec.get("event_id") == event_id or rec.get("dlq_id") == event_id or rec.get("stream_msg_id") == event_id:
                    target = rec
                    break

            if not target:
                return {"success": False, "error": f"Event '{event_id}' not found in DLQ"}

            raw_payload = target.get("raw_payload")
            hint = format_hint or target.get("source_format") or "auto"

            # Re-publish to STREAM_RAW with a new tracking event_id
            reprocessed_id = f"reproc-{event_id}"
            await xadd_json(
                STREAM_RAW,
                {
                    "event_id": reprocessed_id,
                    "format_hint": hint,
                    "payload": raw_payload,
                    "reprocessed_from": event_id,
                    "reprocessed_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            return {
                "success": True,
                "reprocessed": True,
                "reprocessed_event_id": reprocessed_id,
                "message": f"Event {event_id} successfully resubmitted to {STREAM_RAW} with format hint '{hint}'",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


# Global singleton StreamManager
stream_manager = StreamManager()
