import sqlite3
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.config import settings

def get_utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db_connection() -> sqlite3.Connection:
    """Create a thread-safe connection to the SQLite database with dictionary rows."""
    conn = sqlite3.connect(str(settings.DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables and indexes."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. SIEM Logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS siem_logs (
        id TEXT PRIMARY KEY,
        siem_source TEXT NOT NULL,
        timestamp TEXT,
        severity TEXT,
        event_type TEXT,
        src_ip TEXT,
        dest_ip TEXT,
        src_port INTEGER,
        dest_port INTEGER,
        user TEXT,
        file_hash TEXT,
        domain TEXT,
        alert_name TEXT,
        details_json TEXT,
        raw_log TEXT,
        created_at TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_siem_source ON siem_logs(siem_source)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON siem_logs(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON siem_logs(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_dest_ip ON siem_logs(dest_ip)")

    # 2. Chat Sessions table (for multi-turn conversational memory)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS chat_sessions (
        id TEXT PRIMARY KEY,
        title TEXT,
        created_at TEXT,
        updated_at TEXT
    )
    """)

    # 3. Chat Messages table (storing conversational memory turns)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS chat_messages (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        context_logs_json TEXT,
        threat_intel_json TEXT,
        created_at TEXT,
        FOREIGN KEY(session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_messages(session_id)")

    # 4. Threat Intel Cache (VirusTotal lookups)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel_cache (
        indicator TEXT PRIMARY KEY,
        ioc_type TEXT NOT NULL,
        malicious_count INTEGER DEFAULT 0,
        suspicious_count INTEGER DEFAULT 0,
        harmless_count INTEGER DEFAULT 0,
        undetected_count INTEGER DEFAULT 0,
        reputation INTEGER DEFAULT 0,
        engine_details_json TEXT,
        tags_json TEXT,
        source TEXT DEFAULT 'VirusTotal v3',
        last_checked_at TEXT
    )
    """)

    # 5. Pipeline Evaluation Runs (LangSmith & Model Quality)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pipeline_eval_runs (
        id TEXT PRIMARY KEY,
        run_name TEXT,
        dataset_name TEXT,
        test_cases_count INTEGER,
        passed_count INTEGER,
        accuracy_score REAL,
        avg_latency_ms REAL,
        results_json TEXT,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()

# Log Management Functions
def insert_logs(logs: List[Dict[str, Any]]) -> int:
    """Batch insert normalized SIEM logs into SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    count = 0
    now_str = get_utc_now_str()

    for log in logs:
        log_id = log.get("id") or str(uuid.uuid4())
        details_json = json.dumps(log.get("details", {}))
        cursor.execute("""
        INSERT OR REPLACE INTO siem_logs (
            id, siem_source, timestamp, severity, event_type,
            src_ip, dest_ip, src_port, dest_port, user,
            file_hash, domain, alert_name, details_json, raw_log, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_id,
            log.get("siem_source", "Unknown"),
            log.get("timestamp", now_str),
            (log.get("severity") or "informational").upper(),
            log.get("event_type", "security_event"),
            log.get("src_ip"),
            log.get("dest_ip"),
            log.get("src_port"),
            log.get("dest_port"),
            log.get("user"),
            log.get("file_hash"),
            log.get("domain"),
            log.get("alert_name"),
            details_json,
            log.get("raw_log", ""),
            now_str
        ))
        count += 1
    conn.commit()
    conn.close()
    return count

def query_logs(
    siem_source: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> Dict[str, Any]:
    """Query logs with filters, search, and pagination."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM siem_logs WHERE 1=1"
    params = []

    if siem_source and siem_source.lower() != "all":
        query += " AND UPPER(siem_source) = UPPER(?)"
        params.append(siem_source)

    if severity and severity.lower() != "all":
        query += " AND UPPER(severity) = UPPER(?)"
        params.append(severity)

    if search:
        search_pattern = f"%{search}%"
        query += """ AND (
            raw_log LIKE ? OR alert_name LIKE ? OR src_ip LIKE ? OR
            dest_ip LIKE ? OR user LIKE ? OR file_hash LIKE ? OR domain LIKE ?
        )"""
        params.extend([search_pattern] * 7)

    # Count total matching
    count_query = f"SELECT COUNT(*) as total FROM ({query})"
    cursor.execute(count_query, params)
    total = cursor.fetchone()["total"]

    # Order and limit
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    results = []
    for r in rows:
        d = dict(r)
        if d.get("details_json"):
            try:
                d["details"] = json.loads(d["details_json"])
            except Exception:
                d["details"] = {}
        results.append(d)

    conn.close()
    return {"total": total, "logs": results}

def get_recent_security_logs(limit: int = 30) -> List[Dict[str, Any]]:
    """Retrieve top security logs prioritizing high/critical severity for LLM context."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM siem_logs 
    ORDER BY 
        CASE severity 
            WHEN 'CRITICAL' THEN 1 
            WHEN 'HIGH' THEN 2 
            WHEN 'MEDIUM' THEN 3 
            WHEN 'LOW' THEN 4 
            ELSE 5 
        END, timestamp DESC 
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats() -> Dict[str, Any]:
    """Get high-level dashboard statistics."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total_logs FROM siem_logs")
    total_logs = cursor.fetchone()["total_logs"]

    cursor.execute("SELECT COUNT(*) as critical_count FROM siem_logs WHERE UPPER(severity) IN ('CRITICAL', 'HIGH')")
    critical_count = cursor.fetchone()["critical_count"]

    cursor.execute("SELECT siem_source, COUNT(*) as count FROM siem_logs GROUP BY siem_source")
    by_source = {row["siem_source"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("SELECT severity, COUNT(*) as count FROM siem_logs GROUP BY severity")
    by_severity = {row["severity"]: row["count"] for row in cursor.fetchall()}

    cursor.execute("SELECT COUNT(*) as vt_cached FROM threat_intel_cache")
    vt_cached = cursor.fetchone()["vt_cached"]

    cursor.execute("SELECT COUNT(*) as vt_malicious FROM threat_intel_cache WHERE malicious_count > 0")
    vt_malicious = cursor.fetchone()["vt_malicious"]

    conn.close()
    return {
        "total_logs": total_logs,
        "critical_alerts": critical_count,
        "by_source": by_source,
        "by_severity": by_severity,
        "vt_cached": vt_cached,
        "vt_malicious": vt_malicious
    }

# Chat Memory Functions
def get_or_create_session(session_id: Optional[str] = None, title: str = "SOC Hunting Session") -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = get_utc_now_str()
    if not session_id:
        session_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO chat_sessions (id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
                       (session_id, title, now_str, now_str))
    else:
        cursor.execute("SELECT id FROM chat_sessions WHERE id = ?", (session_id,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO chat_sessions (id, title, created_at, updated_at) VALUES (?, ?, ?, ?)",
                           (session_id, title, now_str, now_str))
    conn.commit()
    conn.close()
    return session_id

def list_chat_sessions() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM chat_sessions ORDER BY updated_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def add_chat_message(
    session_id: str, 
    role: str, 
    content: str, 
    context_logs: Optional[List[Dict[str, Any]]] = None,
    threat_intel: Optional[Dict[str, Any]] = None
) -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    msg_id = str(uuid.uuid4())
    now_str = get_utc_now_str()

    cursor.execute("""
    INSERT INTO chat_messages (id, session_id, role, content, context_logs_json, threat_intel_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        msg_id,
        session_id,
        role,
        content,
        json.dumps(context_logs or []),
        json.dumps(threat_intel or {}),
        now_str
    ))

    cursor.execute("UPDATE chat_sessions SET updated_at = ? WHERE id = ?", (now_str, session_id))
    conn.commit()
    conn.close()
    return msg_id

def get_session_history(session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM chat_messages WHERE session_id = ? ORDER BY created_at ASC LIMIT ?
    """, (session_id, limit))
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        item = dict(r)
        if item.get("context_logs_json"):
            try:
                item["context_logs"] = json.loads(item["context_logs_json"])
            except Exception:
                item["context_logs"] = []
        if item.get("threat_intel_json"):
            try:
                item["threat_intel"] = json.loads(item["threat_intel_json"])
            except Exception:
                item["threat_intel"] = {}
        result.append(item)
    return result

# Threat Intel Cache Functions
def get_cached_threat_intel(indicator: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_intel_cache WHERE indicator = ?", (indicator.strip(),))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("engine_details_json"):
        try:
            d["engine_details"] = json.loads(d["engine_details_json"])
        except Exception:
            d["engine_details"] = {}
    if d.get("tags_json"):
        try:
            d["tags"] = json.loads(d["tags_json"])
        except Exception:
            d["tags"] = []
    return d

def save_threat_intel_cache(data: Dict[str, Any]):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = get_utc_now_str()
    cursor.execute("""
    INSERT OR REPLACE INTO threat_intel_cache (
        indicator, ioc_type, malicious_count, suspicious_count,
        harmless_count, undetected_count, reputation,
        engine_details_json, tags_json, source, last_checked_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("indicator", "").strip(),
        data.get("ioc_type", "unknown"),
        data.get("malicious_count", 0),
        data.get("suspicious_count", 0),
        data.get("harmless_count", 0),
        data.get("undetected_count", 0),
        data.get("reputation", 0),
        json.dumps(data.get("engine_details", {})),
        json.dumps(data.get("tags", [])),
        data.get("source", "VirusTotal v3"),
        now_str
    ))
    conn.commit()
    conn.close()

def get_all_cached_intel(limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_intel_cache ORDER BY malicious_count DESC, last_checked_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        if d.get("tags_json"):
            try:
                d["tags"] = json.loads(d["tags_json"])
            except Exception:
                d["tags"] = []
        if d.get("engine_details_json"):
            try:
                d["engine_details"] = json.loads(d["engine_details_json"])
            except Exception:
                d["engine_details"] = {}
        results.append(d)
    return results

# Evaluation Run Functions
def record_eval_run(run_data: Dict[str, Any]) -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    run_id = str(uuid.uuid4())
    now_str = get_utc_now_str()
    cursor.execute("""
    INSERT INTO pipeline_eval_runs (
        id, run_name, dataset_name, test_cases_count,
        passed_count, accuracy_score, avg_latency_ms,
        results_json, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        run_id,
        run_data.get("run_name", "LangSmith SOC Evaluation"),
        run_data.get("dataset_name", "Multi-SIEM Benchmark"),
        run_data.get("test_cases_count", 0),
        run_data.get("passed_count", 0),
        run_data.get("accuracy_score", 0.0),
        run_data.get("avg_latency_ms", 0.0),
        json.dumps(run_data.get("results", [])),
        now_str
    ))
    conn.commit()
    conn.close()
    return run_id

def get_eval_runs(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pipeline_eval_runs ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        if d.get("results_json"):
            try:
                d["results"] = json.loads(d["results_json"])
            except Exception:
                d["results"] = []
        results.append(d)
    return results
