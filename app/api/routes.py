from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from app.database import (
    query_logs,
    get_stats,
    list_chat_sessions,
    get_session_history,
    get_all_cached_intel,
    get_eval_runs,
    get_eval_run_by_id,
    insert_logs,
    get_iam_data,
    get_audit_logs,
    get_mapping_coverage,
    reprocess_stored_logs,
    clear_all_logs,
    clear_all_chat_sessions,
    clear_threat_intel_cache,
    reset_all_platform_data,
    purge_raw_log_payloads
)
from app.siem_parser import ingest_dataset_content
from app.threat_intel import lookup_ioc
from app.llm_engine import process_soc_query
from app.langsmith_eval import run_langsmith_evaluation
from app.seed_data import generate_multi_siem_seed_logs
from app.config import settings

router = APIRouter()

# Pydantic Request Models
class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str

class IOCLookupRequest(BaseModel):
    indicator: str
    ioc_type: Optional[str] = None

class IngestTextRequest(BaseModel):
    content: str
    format_type: Optional[str] = "auto"
    store_raw_log: Optional[bool] = False

class ReprocessRequest(BaseModel):
    log_ids: Optional[List[str]] = None
    source: Optional[str] = "all"

class SettingsUpdateRequest(BaseModel):
    gemini_key: Optional[str] = None
    vt_key: Optional[str] = None
    langsmith_key: Optional[str] = None

# 1. Stats & Telemetry
@router.get("/stats")
async def api_get_stats():
    return get_stats()

# 2. Log Explorer & Ingestion
@router.get("/logs")
async def api_get_logs(
    source: Optional[str] = "all",
    severity: Optional[str] = "all",
    status: Optional[str] = "all",
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    return query_logs(siem_source=source, severity=severity, status=status, search=search, limit=limit, offset=offset)

@router.get("/logs/coverage")
async def api_get_mapping_coverage():
    return get_mapping_coverage()

@router.post("/logs/reprocess")
async def api_reprocess_logs(req: ReprocessRequest):
    result = reprocess_stored_logs(log_ids=req.log_ids, source=req.source)
    return result

@router.post("/logs/clear")
async def api_clear_all_logs(clear_chats: bool = True, clear_intel: bool = True):
    result = reset_all_platform_data(include_logs=True, include_chats=clear_chats, include_intel=clear_intel)
    return {
        "status": "success",
        "cleared_count": result["cleared_logs"],
        "cleared_chats": result["cleared_chats"],
        "cleared_intel": result["cleared_intel"],
        "summary": result,
        "message": f"Successfully reset {result['cleared_logs']} log files, {result['cleared_chats']} AI threat hunting conversations, and {result['cleared_intel']} VirusTotal threat intelligence indicators."
    }


@router.post("/logs/purge-raw")
async def api_purge_raw_logs():
    affected = purge_raw_log_payloads()
    return {
        "status": "success",
        "affected_count": affected,
        "message": f"Purged raw log payloads from {affected} stored records while retaining all analytical findings and IOCs."
    }

@router.post("/logs/ingest-text")
async def api_ingest_text(req: IngestTextRequest):
    logs, count = ingest_dataset_content(req.content, req.format_type or "auto")
    summary = {"processed": count, "success": count, "partial": 0, "failed": 0, "duplicates": 0, "ingested": count}
    if count > 0:
        store_raw = bool(req.store_raw_log)
        res = insert_logs(logs, detect_duplicates=False, store_raw_log=store_raw)
        summary = res.summary
    return {
        "status": "success",
        "ingested_count": summary.get("ingested", count),
        "processed_count": summary.get("processed", count),
        "success_count": summary.get("success", count),
        "partial_count": summary.get("partial", 0),
        "failed_count": summary.get("failed", 0),
        "duplicate_count": summary.get("duplicates", 0),
        "summary": summary
    }

@router.post("/logs/upload")
async def api_upload_log_file(
    file: UploadFile = File(...), 
    format_type: str = Form("auto"),
    store_raw_log: bool = Form(False)
):
    content_bytes = await file.read()
    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_str = content_bytes.decode("latin-1")
    
    logs, count = ingest_dataset_content(content_str, format_type)
    summary = {"processed": count, "success": count, "partial": 0, "failed": 0, "duplicates": 0, "ingested": count}
    if count > 0:
        res = insert_logs(logs, detect_duplicates=False, store_raw_log=store_raw_log)
        summary = res.summary
    return {
        "status": "success",
        "filename": file.filename,
        "ingested_count": summary.get("ingested", count),
        "processed_count": summary.get("processed", count),
        "success_count": summary.get("success", count),
        "partial_count": summary.get("partial", 0),
        "failed_count": summary.get("failed", 0),
        "duplicate_count": summary.get("duplicates", 0),
        "summary": summary
    }

@router.post("/logs/seed")
async def api_seed_logs(reset_chat: bool = True, reset_intel: bool = True):
    if reset_chat:
        clear_all_chat_sessions()
    if reset_intel:
        clear_threat_intel_cache()
    count = generate_multi_siem_seed_logs()
    return {
        "status": "success", 
        "seeded_count": count,
        "chat_reset": reset_chat,
        "intel_reset": reset_intel
    }

# 3. Memory-Enabled SOC Copilot Chat
@router.post("/chat")
async def api_chat(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Query message cannot be empty")
    
    result = process_soc_query(session_id=req.session_id, user_query=req.message)
    return result

@router.get("/chat/sessions")
async def api_list_sessions():
    return list_chat_sessions()

@router.get("/chat/history/{session_id}")
async def api_get_history(session_id: str):
    return get_session_history(session_id)

@router.post("/chat/clear")
async def api_clear_chat_sessions():
    cleared = clear_all_chat_sessions()
    return {
        "status": "success",
        "cleared_count": cleared,
        "message": f"Successfully cleared all {cleared} AI threat hunting conversations and session histories."
    }

# 4. Threat Intel & VirusTotal
@router.post("/threat-intel/lookup")
async def api_threat_lookup(req: IOCLookupRequest):
    if not req.indicator.strip():
        raise HTTPException(status_code=400, detail="Indicator cannot be empty")
    return lookup_ioc(req.indicator, req.ioc_type)

@router.get("/threat-intel/cached")
async def api_get_cached_intel():
    return get_all_cached_intel()

@router.post("/threat-intel/clear")
async def api_clear_threat_intel_cache():
    cleared = clear_threat_intel_cache()
    return {
        "status": "success",
        "cleared_count": cleared,
        "message": f"Successfully cleared all {cleared} VirusTotal v3 cached threat intelligence indicators."
    }


# 5. LangSmith Pipeline Evaluation
@router.post("/eval/run")
async def api_run_eval(sync_remote: bool = True):
    return run_langsmith_evaluation(sync_remote=sync_remote)

@router.get("/eval/latest")
async def api_get_latest_eval():
    runs = get_eval_runs(limit=1)
    if not runs:
        return None
    return runs[0]

@router.get("/eval/history")
async def api_get_eval_history(limit: int = 20):
    return get_eval_runs(limit=limit)

@router.get("/eval/runs/{run_id}")
async def api_get_eval_run(run_id: str):
    run = get_eval_run_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Evaluation run '{run_id}' not found")
    return run

# 6. Settings & API Keys
@router.get("/settings")
async def api_get_settings():
    def mask_key(k: str) -> str:
        if not k:
            return ""
        if len(k) <= 8:
            return "••••••••"
        return k[:4] + "••••••••" + k[-4:]

    return {
        "gemini_configured": bool(settings.GEMINI_API_KEY),
        "gemini_key_masked": mask_key(settings.GEMINI_API_KEY),
        "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
        "virustotal_key_masked": mask_key(settings.VIRUSTOTAL_API_KEY),
        "langsmith_configured": bool(settings.LANGCHAIN_API_KEY),
        "langsmith_key_masked": mask_key(settings.LANGCHAIN_API_KEY),
        "langsmith_project": settings.LANGCHAIN_PROJECT,
        "database_path": str(settings.DB_PATH)
    }

@router.post("/settings")
async def api_update_settings(req: SettingsUpdateRequest):
    settings.update_keys(
        gemini_key=req.gemini_key,
        vt_key=req.vt_key,
        langsmith_key=req.langsmith_key
    )
    return {"status": "success", "message": "Settings updated successfully"}

# 7. Identity & Access Management (IAM)
@router.get("/iam")
async def api_get_iam():
    return get_iam_data()

# 8. Audit Logs & Provenance
@router.get("/audit")
async def api_get_audit(limit: int = 100):
    return get_audit_logs(limit=limit)

