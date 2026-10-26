"""
FastAPI Stream Management, Live Feed, and Alert Endpoints.
Integrates Redis Streams pipeline with the SOC Copilot web layer,
providing SSE live event delivery, producer controls, and DLQ management.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from app.database import (
    query_logs,
    query_security_alerts,
    get_security_alert_by_id,
    clear_all_security_alerts,
)
from app.streaming.manager import stream_manager

logger = logging.getLogger("api.stream")

router = APIRouter()


# =========================================================================
# Request / Response Schemas
# =========================================================================
class StreamStartRequest(BaseModel):
    rate: Optional[float] = Field(default=None, description="Events per second (EPS), e.g. 1, 5, 10, 50")
    eps: Optional[float] = Field(default=None, description="Events per second (EPS) alias")
    scenario: Optional[str] = Field(default="mixed", description="Scenario: mixed, brute_force, auth_compromise, endpoint_chain, c2_outbound, dlq_test")
    total_events: Optional[int] = Field(default=0, description="0 for continuous streaming, or a positive integer limit")


class StreamConfigRequest(BaseModel):
    events_per_second: Optional[float] = Field(default=None, ge=0.1, le=200.0)
    eps: Optional[float] = Field(default=None, ge=0.1, le=200.0)
    rate: Optional[float] = Field(default=None, ge=0.1, le=200.0)
    active_scenario: Optional[str] = None
    seed: Optional[int] = None


class TriggerScenarioRequest(BaseModel):
    scenario: str = Field(description="Scenario name: brute_force, auth_compromise, endpoint_chain, c2_outbound, dlq_test")
    count: Optional[int] = Field(default=5, ge=1, le=50)


class ReprocessDLQRequest(BaseModel):
    format_hint: Optional[str] = Field(default=None, description="Optional format hint override: splunk, elastic, sentinel, qradar, wazuh")


# =========================================================================
# 1. Stream Status & Lifecycle Endpoints
# =========================================================================
@router.get("/stream/status")
async def get_stream_status():
    """
    Returns actual Redis connectivity, consumer-group state, producer state,
    worker status, and processing diagnostics.
    """
    status = await stream_manager.get_pipeline_status()
    return status


@router.post("/stream/start")
async def start_stream(req: Optional[StreamStartRequest] = None):
    """
    Start continuous synthetic event production through the controlled producer lifecycle manager.
    """
    producer = stream_manager.producer
    rate = 5.0
    scenario = "mixed"
    total_events = 0
    if req:
        if req.rate is not None:
            rate = req.rate
        elif req.eps is not None:
            rate = req.eps
        if req.scenario:
            scenario = req.scenario
        if req.total_events is not None:
            total_events = req.total_events

    producer.set_rate(rate)
    producer.active_scenario = scenario
    producer.total_target_events = total_events

    # Ensure workers and producer are active
    await stream_manager.start_all(start_producer=True)
    if not producer.is_running:
        await producer.start()

    return {
        "status": "started",
        "message": f"Real-time event producer started at {rate} EPS with scenario '{scenario}'",
        "producer": producer.get_status(),
    }


@router.post("/stream/stop")
async def stop_stream():
    """
    Stop the synthetic event producer gracefully without terminating background workers.
    """
    producer = stream_manager.producer
    if producer.is_running:
        await producer.stop()
    return {
        "status": "stopped",
        "message": "Real-time event producer stopped gracefully",
        "producer": producer.get_status(),
    }


@router.post("/stream/config")
async def update_stream_config(req: StreamConfigRequest):
    """
    Validate and update supported producer settings at runtime.
    """
    producer = stream_manager.producer
    rate_val = req.events_per_second or req.eps or req.rate
    if rate_val is not None:
        producer.set_rate(rate_val)
    if req.active_scenario is not None:
        producer.active_scenario = req.active_scenario
    if req.seed is not None:
        producer.seed = req.seed

    return {
        "status": "success",
        "message": "Stream producer configuration updated",
        "config": producer.get_status(),
    }


@router.get("/stream/metrics")
async def get_stream_metrics_api():
    """
    Return actual operational metrics for Redis Streams and processing workers.
    """
    status = await stream_manager.get_pipeline_status()
    return {
        "metrics": status.get("metrics", {}),
        "streams": status.get("streams", {}),
        "system": status.get("system", {}),
    }


@router.post("/stream/trigger-scenario")
async def trigger_scenario(req: TriggerScenarioRequest):
    """
    Trigger a controlled demonstration scenario burst directly into Redis Streams.
    """
    producer = stream_manager.producer
    # Ensure workers are active
    if not stream_manager._running:
        await stream_manager.start_all(start_producer=False)

    published = await producer.trigger_scenario(req.scenario, req.count)
    return {
        "status": "success",
        "scenario": req.scenario,
        "events_published": published,
        "message": f"Successfully published {published} events for scenario '{req.scenario}' into 'security:raw'",
    }


# =========================================================================
# 2. Live Events & Queries
# =========================================================================
@router.get("/events/live")
async def stream_live_events(request: Request):
    """
    Server-Sent Events (SSE) live endpoint delivering real-time normalized events
    and correlated security alerts to connected frontend dashboards.
    """
    return EventSourceResponse(stream_manager.subscribe_live_events())


@router.get("/events")
async def get_events_paginated(
    source: Optional[str] = "all",
    severity: Optional[str] = "all",
    status: Optional[str] = "all",
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """
    Paginated event queries across persisted SIEM records.
    """
    return query_logs(
        siem_source=source,
        severity=severity,
        status=status,
        search=search,
        limit=limit,
        offset=offset,
    )


# =========================================================================
# 3. Security Alerts Endpoints
# =========================================================================
@router.get("/alerts")
async def get_security_alerts(
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """
    Query correlated security alerts persisted by the streaming correlation engine.
    """
    res = query_security_alerts(
        rule_id=rule_id,
        severity=severity,
        user=user,
        host=host,
        limit=limit,
        offset=offset,
    )
    return {
        "alerts": res.get("alerts", []),
        "total": res.get("total", 0),
        "count": len(res.get("alerts", [])),
        "limit": limit,
        "offset": offset,
    }


@router.get("/alerts/{alert_id}")
async def get_security_alert_detail(alert_id: str):
    """
    Get detailed timeline, evidence, and contributing event IDs for a correlated security alert.
    """
    alert = get_security_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@router.delete("/alerts")
async def delete_all_alerts():
    """Clear all persisted correlated alerts."""
    count = clear_all_security_alerts()
    return {"status": "success", "cleared_count": count}


# =========================================================================
# 4. Dead Letter Queue (DLQ) Inspection & Reprocessing
# =========================================================================
@router.get("/stream/dlq")
async def inspect_dlq(limit: int = 50):
    """
    Inspect dead-letter records with error diagnostics from 'security:dlq'.
    """
    dlq_entries = await stream_manager.get_dlq_events(limit=limit)
    return {
        "dlq_entries": dlq_entries,
        "dlq_events": dlq_entries,
        "total": len(dlq_entries),
        "total_returned": len(dlq_entries),
    }


@router.post("/stream/dlq/{event_id}/reprocess")
async def reprocess_dlq_event_api(event_id: str, req: Optional[ReprocessDLQRequest] = None):
    """
    Reprocess an eligible failed event through a controlled, idempotent workflow.
    """
    hint = req.format_hint if req else None
    result = await stream_manager.reprocess_dlq_event(event_id=event_id, format_hint=hint)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Reprocessing failed"))
    return result
