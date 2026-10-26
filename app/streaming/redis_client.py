import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
import redis
import redis.asyncio as aioredis
from app.config import settings

logger = logging.getLogger("aegis.redis")

# Global async client cache
_async_redis_client: Optional[aioredis.Redis] = None
_cached_loop: Optional[asyncio.AbstractEventLoop] = None

def get_sync_redis() -> redis.Redis:
    """Returns a synchronous Redis connection client."""
    return redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        db=settings.REDIS_DB,
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5
    )

async def get_async_redis() -> aioredis.Redis:
    """Returns an asynchronous Redis connection client tied to the active event loop."""
    global _async_redis_client, _cached_loop
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if _async_redis_client is not None:
        if _cached_loop is None or _cached_loop.is_closed() or (current_loop is not None and _cached_loop != current_loop):
            _async_redis_client = None

    if _async_redis_client is None:
        _async_redis_client = aioredis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD,
            db=settings.REDIS_DB,
            decode_responses=True,
            socket_timeout=10,
            socket_connect_timeout=10
        )
        _cached_loop = current_loop
    return _async_redis_client

async def close_async_redis():
    """Gracefully closes async Redis connection."""
    global _async_redis_client
    if _async_redis_client is not None:
        try:
            await _async_redis_client.close()
        except Exception as e:
            logger.warning(f"Error closing async Redis client: {e}")
        finally:
            _async_redis_client = None

async def check_redis_health() -> Dict[str, Any]:
    """Inspects live Redis connectivity, ping latency, and server info."""
    try:
        r = await get_async_redis()
        pong = await r.ping()
        info = await r.info(section="server")
        memory = await r.info(section="memory")
        return {
            "connected": bool(pong),
            "status": "connected" if pong else "degraded",
            "redis_version": info.get("redis_version", "unknown"),
            "uptime_seconds": info.get("uptime_in_seconds", 0),
            "used_memory_human": memory.get("used_memory_human", "0B"),
            "connected_clients": info.get("connected_clients", 0)
        }
    except Exception as e:
        return {
            "connected": False,
            "status": "disconnected",
            "error": str(e),
            "redis_version": None,
            "uptime_seconds": 0
        }

async def setup_streams_and_groups():
    """
    Idempotently creates all required Redis streams and consumer groups.
    Safe to call multiple times without error.
    """
    r = await get_async_redis()

    stream_group_mappings = [
        (settings.STREAM_RAW, settings.GROUP_NORMALIZERS),
        (settings.STREAM_NORMALIZED, settings.GROUP_CORRELATORS),
        (settings.STREAM_NORMALIZED, settings.GROUP_PERSISTERS),
        (settings.STREAM_ALERTS, settings.GROUP_PERSISTERS)
    ]

    for stream_name, group_name in stream_group_mappings:
        try:
            # MKSTREAM ensures stream is created if it does not exist
            # '0' starts from the beginning so new consumers read existing stream entries
            await r.xgroup_create(name=stream_name, groupname=group_name, id="0", mkstream=True)
            logger.info(f"Initialized consumer group '{group_name}' on stream '{stream_name}'")
        except aioredis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                logger.debug(f"Consumer group '{group_name}' already exists on '{stream_name}'")
            else:
                logger.error(f"Error creating group '{group_name}' on '{stream_name}': {e}")
                raise

async def xadd_json(stream: str, data: Dict[str, Any], maxlen: int = 50000) -> str:
    """
    Helper to publish a structured JSON payload to a Redis stream.
    Payload is stored under 'payload' field as serialized JSON with metadata fields.
    """
    r = await get_async_redis()
    fields = {
        "event_id": str(data.get("id") or data.get("event_id") or ""),
        "timestamp": str(data.get("timestamp") or ""),
        "source": str(data.get("siem_source") or data.get("source") or "unknown"),
        "payload": json.dumps(data)
    }
    # Approximate trimming keeps memory bounded without performance penalty
    entry_id = await r.xadd(name=stream, fields=fields, maxlen=maxlen, approximate=True)
    return entry_id

async def get_stream_metrics() -> Dict[str, Any]:
    """Retrieves real-time length, consumer group counts, and pending entries for each stream."""
    r = await get_async_redis()
    streams = [
        settings.STREAM_RAW,
        settings.STREAM_NORMALIZED,
        settings.STREAM_ALERTS,
        settings.STREAM_DLQ
    ]
    metrics = {}

    for s in streams:
        try:
            length = await r.xlen(s)
            groups_info = []
            try:
                g_list = await r.xinfo_groups(s)
                for g in g_list:
                    groups_info.append({
                        "name": g.get("name"),
                        "consumers": g.get("consumers", 0),
                        "pending": g.get("pending", 0),
                        "last_delivered_id": g.get("last-delivered-id")
                    })
            except Exception:
                pass

            metrics[s] = {
                "length": length,
                "groups": groups_info
            }
        except Exception as e:
            metrics[s] = {"length": 0, "error": str(e), "groups": []}

    return metrics
