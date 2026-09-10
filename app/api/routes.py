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
    insert_logs
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
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    return query_logs(siem_source=source, severity=severity, search=search, limit=limit, offset=offset)

@router.post("/logs/ingest-text")
async def api_ingest_text(req: IngestTextRequest):
    logs, count = ingest_dataset_content(req.content, req.format_type or "auto")
    if count > 0:
        insert_logs(logs)
    return {"status": "success", "ingested_count": count}

@router.post("/logs/upload")
async def api_upload_log_file(file: UploadFile = File(...), format_type: str = Form("auto")):
    content_bytes = await file.read()
    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_str = content_bytes.decode("latin-1")
    
    logs, count = ingest_dataset_content(content_str, format_type)
    if count > 0:
        insert_logs(logs)
    return {"status": "success", "filename": file.filename, "ingested_count": count}

@router.post("/logs/seed")
async def api_seed_logs():
    count = generate_multi_siem_seed_logs()
    return {"status": "success", "seeded_count": count}

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

# 4. Threat Intel & VirusTotal
@router.post("/threat-intel/lookup")
async def api_threat_lookup(req: IOCLookupRequest):
    if not req.indicator.strip():
        raise HTTPException(status_code=400, detail="Indicator cannot be empty")
    return lookup_ioc(req.indicator, req.ioc_type)

@router.get("/threat-intel/cached")
async def api_get_cached_intel():
    return get_all_cached_intel()

# 5. LangSmith Pipeline Evaluation
@router.post("/eval/run")
async def api_run_eval():
    return run_langsmith_evaluation()

@router.get("/eval/history")
async def api_get_eval_history():
    return get_eval_runs()

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
