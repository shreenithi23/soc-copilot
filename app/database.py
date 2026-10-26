import sqlite3
import json
import uuid
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.config import settings

try:
    import psycopg2
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None
    DictCursor = None

def get_utc_now_str() -> str:
    return datetime.now(timezone.utc).isoformat()

def adapt_sql_for_postgres(sql: str) -> str:
    """Translates SQLite SQL queries into standard PostgreSQL syntax."""
    s = sql.strip()
    s = s.replace("?", "%s")
    
    # Translate INSERT OR REPLACE INTO <table> (cols) VALUES (...)
    if re.match(r"(?i)^INSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)", s):
        m = re.match(r"(?i)^INSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)\s*\((.*?)\)\s*VALUES\s*\((.*?)\)", s, re.DOTALL)
        if m:
            tbl = m.group(1).lower()
            cols_raw = m.group(2)
            vals_raw = m.group(3)
            cols = [c.strip() for c in cols_raw.split(",")]
            pkey = "indicator" if tbl == "threat_intel_cache" else "id"
            quoted_cols = ['"user"' if c.lower() == "user" else c for c in cols]
            update_clauses = [f"{qc} = EXCLUDED.{qc}" for c, qc in zip(cols, quoted_cols) if c.lower() != pkey]
            s = f"INSERT INTO {tbl} ({', '.join(quoted_cols)}) VALUES ({vals_raw}) ON CONFLICT ({pkey}) DO UPDATE SET {', '.join(update_clauses)}"
    else:
        # Quote unquoted standalone user column name
        s = re.sub(r"(?<=[(,\s])user(?=[),\s])", '"user"', s, flags=re.IGNORECASE)
        # Make LIKE case-insensitive like SQLite
        s = re.sub(r"\bLIKE\b", "ILIKE", s)
        
    return s

from datetime import date

class PostgresRowWrapper:
    """Row wrapper that formats date/datetime fields as ISO strings for 100% JSON serialization."""
    def __init__(self, row):
        self._row = row

    def __getitem__(self, key):
        val = self._row[key]
        if isinstance(val, (datetime, date)):
            return val.isoformat()
        return val

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            return default

    def keys(self):
        return self._row.keys()

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._row)

    def items(self):
        for k in self.keys():
            yield k, self[k]

class PostgresCursorWrapper:
    """Cursor wrapper that translates query parameters and provides dict and index row access."""
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query: str, params=None):
        pg_query = adapt_sql_for_postgres(query)
        if params is not None:
            return self._cursor.execute(pg_query, params)
        return self._cursor.execute(pg_query)

    def executemany(self, query: str, params_list):
        pg_query = adapt_sql_for_postgres(query)
        return self._cursor.executemany(pg_query, params_list)

    def fetchone(self):
        row = self._cursor.fetchone()
        return PostgresRowWrapper(row) if row is not None else None

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [PostgresRowWrapper(r) for r in rows]

    def fetchmany(self, size=None):
        rows = self._cursor.fetchmany(size)
        return [PostgresRowWrapper(r) for r in rows]

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description

    def close(self):
        return self._cursor.close()


class PostgresConnectionWrapper:
    """Connection wrapper ensuring thread-safe Postgres connections."""
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return PostgresCursorWrapper(self._conn.cursor())

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()

def get_db_connection():
    """Create a thread-safe connection to Supabase PostgreSQL or fallback to SQLite."""
    if settings.USE_POSTGRES and psycopg2:
        conn = psycopg2.connect(settings.DATABASE_URL, cursor_factory=DictCursor)
        return PostgresConnectionWrapper(conn)
    conn = sqlite3.connect(str(settings.DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables and indexes for Supabase PostgreSQL or SQLite."""
    if settings.USE_POSTGRES and psycopg2:
        schema_file = settings.BASE_DIR / "scripts" / "supabase_schema.sql"
        if schema_file.exists():
            with psycopg2.connect(settings.DATABASE_URL) as raw_conn:
                with raw_conn.cursor() as cur:
                    with open(schema_file, "r") as f:
                        cur.execute(f.read())
                raw_conn.commit()
            return

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
        benchmark_version TEXT DEFAULT '1.0.0',
        test_cases_count INTEGER,
        passed_count INTEGER,
        accuracy_score REAL,
        avg_latency_ms REAL,
        results_json TEXT,
        aggregate_metrics_json TEXT,
        experiment_name TEXT,
        experiment_url TEXT,
        sync_status TEXT DEFAULT 'NOT_CONFIGURED',
        error_details TEXT,
        completed_at TEXT,
        created_at TEXT
    )
    """)

    # Backwards-compatible migrations for existing SQLite databases
    cursor.execute("PRAGMA table_info(pipeline_eval_runs)")
    existing_cols = {row["name"] for row in cursor.fetchall()}
    columns_to_add = [
        ("benchmark_version", "TEXT DEFAULT '1.0.0'"),
        ("aggregate_metrics_json", "TEXT"),
        ("experiment_name", "TEXT"),
        ("experiment_url", "TEXT"),
        ("sync_status", "TEXT DEFAULT 'NOT_CONFIGURED'"),
        ("error_details", "TEXT"),
        ("completed_at", "TEXT"),
    ]
    for col_name, col_def in columns_to_add:
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE pipeline_eval_runs ADD COLUMN {col_name} {col_def}")

    # Migrations for siem_logs canonical schema & normalization diagnostics
    cursor.execute("PRAGMA table_info(siem_logs)")
    siem_existing_cols = {row["name"] for row in cursor.fetchall()}
    siem_columns_to_add = [
        ("normalization_status", "TEXT DEFAULT 'success'"),
        ("mapping_version", "TEXT DEFAULT '2.0.0'"),
        ("unmapped_fields_json", "TEXT"),
        ("conflicting_fields_json", "TEXT"),
        ("validation_errors_json", "TEXT"),
        ("src_host", "TEXT"),
        ("dest_host", "TEXT"),
        ("src_user", "TEXT"),
        ("dest_user", "TEXT"),
        ("protocol", "TEXT"),
        ("action", "TEXT"),
        ("raw_event_json", "TEXT"),
        ("threat_intel_json", "TEXT")
    ]
    for col_name, col_def in siem_columns_to_add:
        if col_name not in siem_existing_cols:
            cursor.execute(f"ALTER TABLE siem_logs ADD COLUMN {col_name} {col_def}")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_normalization_status ON siem_logs(normalization_status)")

    # 6. Correlated Security Alerts (generated by Redis Stream correlation workers)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        entity_type TEXT,
        entity_value TEXT,
        user TEXT,
        host TEXT,
        src_ip TEXT,
        dest_ip TEXT,
        event_count INTEGER DEFAULT 1,
        first_seen TEXT,
        last_seen TEXT,
        contributing_event_ids_json TEXT,
        evidence_json TEXT,
        status TEXT DEFAULT 'OPEN',
        created_at TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_alert_rule ON security_alerts(rule_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_alert_severity ON security_alerts(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_alert_user ON security_alerts(user)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_alert_created ON security_alerts(created_at)")

    conn.commit()
    conn.close()

class IngestionResult(int):
    """Subclass of int carrying rich summary metrics for 100% backwards compatibility."""
    def __new__(cls, val: int, summary: Optional[Dict[str, Any]] = None):
        obj = super().__new__(cls, val)
        obj.summary = summary or {
            "processed": val,
            "success": val,
            "partial": 0,
            "failed": 0,
            "duplicates": 0
        }
        return obj

    def to_dict(self) -> Dict[str, Any]:
        return self.summary

# Log Management Functions
def insert_logs(logs: List[Dict[str, Any]], detect_duplicates: bool = False, store_raw_log: bool = True) -> IngestionResult:
    """
    Batch insert normalized SIEM logs into SQLite with canonical fields and diagnostics.
    If store_raw_log is False, only extracted analytical details and findings are saved,
    and raw log strings / raw events are excluded from the database.
    Returns an IngestionResult int with summary attributes.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = get_utc_now_str()

    processed_count = 0
    success_count = 0
    partial_count = 0
    failed_count = 0
    duplicate_count = 0

    for log in logs:
        log_id = log.get("id") or str(uuid.uuid4())
        norm_status = log.get("normalization_status") or "success"

        # Check for duplicates if requested
        if detect_duplicates:
            cursor.execute("SELECT id FROM siem_logs WHERE id = ?", (log_id,))
            if cursor.fetchone():
                duplicate_count += 1
                continue

        details_json = json.dumps(log.get("details", {}))
        unmapped_json = json.dumps(log.get("unmapped_fields", []))
        conflicts_json = json.dumps(log.get("conflicting_fields", []))
        validation_json = json.dumps(log.get("validation_errors", []))
        
        # When store_raw_log is False, do not store raw log data in database; keep only analyzed details
        raw_log_str = log.get("raw_log", "") if store_raw_log else ""
        raw_event_json = json.dumps(log.get("raw_event")) if (store_raw_log and log.get("raw_event") is not None) else None
        threat_intel_json = json.dumps(log.get("threat_intel")) if log.get("threat_intel") is not None else None

        cursor.execute("""
        INSERT OR REPLACE INTO siem_logs (
            id, siem_source, timestamp, severity, event_type,
            src_ip, dest_ip, src_port, dest_port, user,
            file_hash, domain, alert_name, details_json, raw_log, created_at,
            normalization_status, mapping_version, unmapped_fields_json,
            conflicting_fields_json, validation_errors_json, src_host, dest_host,
            src_user, dest_user, protocol, action, raw_event_json, threat_intel_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            raw_log_str,
            now_str,
            norm_status,
            log.get("mapping_version", "2.0.0"),
            unmapped_json,
            conflicts_json,
            validation_json,
            log.get("src_host"),
            log.get("dest_host"),
            log.get("src_user"),
            log.get("dest_user"),
            log.get("protocol"),
            log.get("action"),
            raw_event_json,
            threat_intel_json
        ))

        processed_count += 1
        if norm_status == "success":
            success_count += 1
        elif norm_status == "partial":
            partial_count += 1
        else:
            failed_count += 1

    conn.commit()
    conn.close()

    summary = {
        "processed": processed_count + duplicate_count,
        "success": success_count,
        "partial": partial_count,
        "failed": failed_count,
        "duplicates": duplicate_count,
        "ingested": processed_count
    }
    return IngestionResult(processed_count, summary)

def clear_all_logs() -> int:
    """Purge all logs from siem_logs across all functionalities."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM siem_logs")
    cnt = cursor.fetchone()["cnt"] or 0
    cursor.execute("DELETE FROM siem_logs")
    conn.commit()
    conn.close()
    return cnt

def clear_all_chat_sessions() -> int:
    """Purge all chat sessions and conversation history from AI threat hunting."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM chat_sessions")
    cnt = cursor.fetchone()["cnt"] or 0
    cursor.execute("DELETE FROM chat_messages")
    cursor.execute("DELETE FROM chat_sessions")
    conn.commit()
    conn.close()
    return cnt

def clear_threat_intel_cache() -> int:
    """Purge all cached VirusTotal v3 threat intelligence indicators."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM threat_intel_cache")
    cnt = cursor.fetchone()["cnt"] or 0
    cursor.execute("DELETE FROM threat_intel_cache")
    conn.commit()
    conn.close()
    return cnt

def clear_all_security_alerts() -> int:
    """Purge all correlated alerts from security_alerts."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM security_alerts")
    cnt = cursor.fetchone()["cnt"] or 0
    cursor.execute("DELETE FROM security_alerts")
    conn.commit()
    conn.close()
    return cnt

def insert_correlated_alert(alert: Dict[str, Any]) -> str:
    """
    Idempotently persists a correlated security alert generated by Redis correlation worker.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    alert_id = alert.get("id") or alert.get("alert_id") or str(uuid.uuid4())
    now_str = get_utc_now_str()

    contributing_ids = json.dumps(alert.get("contributing_event_ids") or [])
    evidence_json = json.dumps(alert.get("evidence") or {})

    cursor.execute("""
    INSERT OR REPLACE INTO security_alerts (
        id, rule_id, rule_name, severity, title, description,
        entity_type, entity_value, user, host, src_ip, dest_ip,
        event_count, first_seen, last_seen, contributing_event_ids_json,
        evidence_json, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_id,
        alert.get("rule_id", "CORR-UNKNOWN"),
        alert.get("rule_name", "Correlated Security Alert"),
        (alert.get("severity") or "HIGH").upper(),
        alert.get("title") or alert.get("rule_name", "Security Detection Alert"),
        alert.get("description", ""),
        alert.get("entity_type", "host"),
        alert.get("entity_value", ""),
        alert.get("user"),
        alert.get("host"),
        alert.get("src_ip"),
        alert.get("dest_ip"),
        alert.get("event_count", 1),
        alert.get("first_seen", now_str),
        alert.get("last_seen", now_str),
        contributing_ids,
        evidence_json,
        alert.get("status", "OPEN"),
        alert.get("created_at", now_str)
    ))
    conn.commit()
    conn.close()
    return alert_id

def query_security_alerts(
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    status: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """Query persisted correlated security alerts with pagination and filters."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM security_alerts WHERE 1=1"
    params = []

    if severity and severity.lower() != "all":
        query += " AND UPPER(severity) = UPPER(?)"
        params.append(severity)

    if rule_id and rule_id.lower() != "all":
        query += " AND rule_id = ?"
        params.append(rule_id)

    if status and status.lower() != "all":
        query += " AND UPPER(status) = UPPER(?)"
        params.append(status)

    if user and user.lower() != "all":
        query += " AND (user = ? OR user LIKE ?)"
        params.extend([user, f"%{user}%"])

    if host and host.lower() != "all":
        query += " AND (host = ? OR host LIKE ?)"
        params.extend([host, f"%{host}%"])

    if search:
        search_pattern = f"%{search}%"
        query += """ AND (
            title LIKE ? OR rule_name LIKE ? OR user LIKE ? OR
            host LIKE ? OR src_ip LIKE ? OR dest_ip LIKE ? OR description LIKE ?
        )"""
        params.extend([search_pattern] * 7)

    count_query = f"SELECT COUNT(*) as total FROM ({query})"
    cursor.execute(count_query, params)
    total = cursor.fetchone()["total"]

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()

    results = []
    for r in rows:
        d = dict(r)
        d["alert_id"] = d.get("id")
        try:
            d["contributing_event_ids"] = json.loads(d.get("contributing_event_ids_json") or "[]")
        except Exception:
            d["contributing_event_ids"] = []
        try:
            d["evidence"] = json.loads(d.get("evidence_json") or "{}")
        except Exception:
            d["evidence"] = {}
        results.append(d)

    conn.close()
    return {"total": total, "alerts": results}

def get_security_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    """Fetch single correlated security alert with full evidence."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["contributing_event_ids"] = json.loads(d.get("contributing_event_ids_json") or "[]")
    except Exception:
        d["contributing_event_ids"] = []
    try:
        d["evidence"] = json.loads(d.get("evidence_json") or "{}")
    except Exception:
        d["evidence"] = {}
    return d

def reset_all_platform_data(include_logs: bool = True, include_chats: bool = True, include_intel: bool = True, include_alerts: bool = True) -> Dict[str, int]:
    """
    Purges all operational data across all platform functionalities:
    - SIEM logs across all sources
    - Correlated security alerts
    - AI Threat Hunting conversations and conversational memory turns
    - Context-Rich Threat Intelligence (VirusTotal v3) cached indicators
    """
    cleared_logs = clear_all_logs() if include_logs else 0
    cleared_alerts = clear_all_security_alerts() if include_alerts else 0
    cleared_chats = clear_all_chat_sessions() if include_chats else 0
    cleared_intel = clear_threat_intel_cache() if include_intel else 0
    return {
        "cleared_logs": cleared_logs,
        "cleared_alerts": cleared_alerts,
        "cleared_chats": cleared_chats,
        "cleared_intel": cleared_intel
    }



def purge_raw_log_payloads() -> int:
    """Strips bulky raw_log and raw_event_json from all stored records, preserving only analytical findings and structured details."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE siem_logs SET raw_log = '', raw_event_json = NULL")
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected

def query_logs(
    siem_source: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> Dict[str, Any]:
    """Query logs with filters (including normalization status), search, and pagination."""
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

    if status and status.lower() != "all":
        query += " AND LOWER(normalization_status) = LOWER(?)"
        params.append(status)

    if search:
        search_pattern = f"%{search}%"
        query += """ AND (
            raw_log LIKE ? OR alert_name LIKE ? OR src_ip LIKE ? OR
            dest_ip LIKE ? OR user LIKE ? OR file_hash LIKE ? OR domain LIKE ? OR
            src_host LIKE ? OR dest_host LIKE ?
        )"""
        params.extend([search_pattern] * 9)

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
        # Parse JSON fields into objects for UI and API consumers
        for json_field, target_key in [
            ("details_json", "details"),
            ("unmapped_fields_json", "unmapped_fields"),
            ("conflicting_fields_json", "conflicting_fields"),
            ("validation_errors_json", "validation_errors"),
            ("raw_event_json", "raw_event"),
            ("threat_intel_json", "threat_intel")
        ]:
            if d.get(json_field):
                try:
                    d[target_key] = json.loads(d[json_field])
                except Exception:
                    d[target_key] = None if target_key == "raw_event" else ({} if "details" in target_key or "intel" in target_key else [])
            else:
                d[target_key] = None if target_key == "raw_event" else ({} if "details" in target_key or "intel" in target_key else [])

        results.append(d)

    conn.close()
    return {"total": total, "logs": results}

def get_mapping_coverage() -> Dict[str, Any]:
    """Computes field-mapping coverage across data sources and canonical fields."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM siem_logs")
    total_events = cursor.fetchone()["total"] or 0

    if total_events == 0:
        conn.close()
        return {
            "total_events": 0,
            "overall_status": {"success": 0, "partial": 0, "failed": 0},
            "sources": {},
            "canonical_field_coverage": {},
            "conflicts_count": 0,
            "top_unmapped_fields": []
        }

    # By source breakdown
    cursor.execute("""
    SELECT siem_source, 
           COUNT(*) as total,
           SUM(CASE WHEN normalization_status = 'success' THEN 1 ELSE 0 END) as success_count,
           SUM(CASE WHEN normalization_status = 'partial' THEN 1 ELSE 0 END) as partial_count,
           SUM(CASE WHEN normalization_status = 'failed' THEN 1 ELSE 0 END) as failed_count
    FROM siem_logs
    GROUP BY siem_source
    """)
    sources_data = {}
    for r in cursor.fetchall():
        sources_data[r["siem_source"]] = {
            "total": r["total"],
            "success": r["success_count"],
            "partial": r["partial_count"],
            "failed": r["failed_count"]
        }

    # Canonical field mapping coverage
    fields_to_check = [
        ("src_ip", "src_ip IS NOT NULL AND src_ip != ''"),
        ("dest_ip", "dest_ip IS NOT NULL AND dest_ip != ''"),
        ("src_port", "src_port IS NOT NULL"),
        ("dest_port", "dest_port IS NOT NULL"),
        ("user", "user IS NOT NULL AND user != ''"),
        ("domain", "domain IS NOT NULL AND domain != ''"),
        ("file_hash", "file_hash IS NOT NULL AND file_hash != ''"),
        ("timestamp", "timestamp IS NOT NULL AND timestamp != ''"),
        ("severity", "severity IS NOT NULL AND severity != ''"),
        ("src_host", "src_host IS NOT NULL AND src_host != ''"),
        ("dest_host", "dest_host IS NOT NULL AND dest_host != ''"),
        ("action", "action IS NOT NULL AND action != ''"),
        ("protocol", "protocol IS NOT NULL AND protocol != ''")
    ]
    coverage_percentages = {}
    for fname, cond in fields_to_check:
        cursor.execute(f"SELECT COUNT(*) as cnt FROM siem_logs WHERE {cond}")
        c = cursor.fetchone()["cnt"]
        pct = round((c / total_events) * 100, 1)
        coverage_percentages[fname] = {"count": c, "percentage": pct}

    # Conflicting fields & unmapped frequencies
    cursor.execute("SELECT unmapped_fields_json, conflicting_fields_json FROM siem_logs")
    rows = cursor.fetchall()
    unmapped_counter = {}
    conflicts_total = 0
    for r in rows:
        if r["conflicting_fields_json"]:
            try:
                c_list = json.loads(r["conflicting_fields_json"])
                conflicts_total += len(c_list)
            except Exception:
                pass
        if r["unmapped_fields_json"]:
            try:
                u_list = json.loads(r["unmapped_fields_json"])
                for uf in u_list:
                    unmapped_counter[uf] = unmapped_counter.get(uf, 0) + 1
            except Exception:
                pass

    top_unmapped = sorted(
        [{"field": k, "count": v} for k, v in unmapped_counter.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:10]

    # Overall statuses
    cursor.execute("""
    SELECT 
        SUM(CASE WHEN normalization_status = 'success' THEN 1 ELSE 0 END) as success,
        SUM(CASE WHEN normalization_status = 'partial' THEN 1 ELSE 0 END) as partial,
        SUM(CASE WHEN normalization_status = 'failed' THEN 1 ELSE 0 END) as failed
    FROM siem_logs
    """)
    stat_row = cursor.fetchone()
    conn.close()

    return {
        "total_events": total_events,
        "overall_status": {
            "success": stat_row["success"] or 0,
            "partial": stat_row["partial"] or 0,
            "failed": stat_row["failed"] or 0
        },
        "sources": sources_data,
        "canonical_field_coverage": coverage_percentages,
        "conflicts_count": conflicts_total,
        "top_unmapped_fields": top_unmapped
    }

def reprocess_stored_logs(log_ids: Optional[List[str]] = None, source: Optional[str] = None) -> Dict[str, Any]:
    """Reprocesses stored logs using the current mapping registry rules without losing IDs."""
    from app.normalization_engine import normalize_single_record
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT id, siem_source, details_json, raw_log, raw_event_json FROM siem_logs WHERE 1=1"
    params = []
    if log_ids:
        placeholders = ",".join("?" for _ in log_ids)
        query += f" AND id IN ({placeholders})"
        params.extend(log_ids)
    elif source and source.lower() != "all":
        query += " AND UPPER(siem_source) = UPPER(?)"
        params.append(source)

    cursor.execute(query, params)
    rows = cursor.fetchall()

    reprocessed = 0
    for r in rows:
        log_id = r["id"]
        source_hint = r["siem_source"]
        raw_obj = None
        if r["raw_event_json"]:
            try:
                raw_obj = json.loads(r["raw_event_json"])
            except Exception:
                raw_obj = None
        if raw_obj is None and r["details_json"]:
            try:
                raw_obj = json.loads(r["details_json"])
            except Exception:
                raw_obj = None
        if raw_obj is None:
            raw_obj = r["raw_log"]

        norm_event = normalize_single_record(raw_obj, source_hint)
        d = norm_event.to_dict()

        cursor.execute("""
        UPDATE siem_logs SET
            timestamp = ?, severity = ?, event_type = ?,
            src_ip = ?, dest_ip = ?, src_port = ?, dest_port = ?,
            user = ?, file_hash = ?, domain = ?, alert_name = ?,
            details_json = ?, normalization_status = ?, mapping_version = ?,
            unmapped_fields_json = ?, conflicting_fields_json = ?,
            validation_errors_json = ?, src_host = ?, dest_host = ?,
            protocol = ?, action = ?
        WHERE id = ?
        """, (
            d["timestamp"],
            d["severity"],
            d["event_type"],
            d["src_ip"],
            d["dest_ip"],
            d["src_port"],
            d["dest_port"],
            d["user"],
            d["file_hash"],
            d["domain"],
            d["alert_name"],
            json.dumps(d.get("details", {})),
            d["normalization_status"],
            d["mapping_version"],
            json.dumps(d.get("unmapped_fields", [])),
            json.dumps(d.get("conflicting_fields", [])),
            json.dumps(d.get("validation_errors", [])),
            d.get("src_host"),
            d.get("dest_host"),
            d.get("protocol"),
            d.get("action"),
            log_id
        ))
        reprocessed += 1

    conn.commit()
    conn.close()
    return {"reprocessed_count": reprocessed, "status": "success"}

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
    run_id = run_data.get("id") or str(uuid.uuid4())
    now_str = get_utc_now_str()
    completed_at = run_data.get("completed_at") or now_str
    cursor.execute("""
    INSERT OR REPLACE INTO pipeline_eval_runs (
        id, run_name, dataset_name, benchmark_version, test_cases_count,
        passed_count, accuracy_score, avg_latency_ms,
        results_json, aggregate_metrics_json, experiment_name,
        experiment_url, sync_status, error_details, completed_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        run_id,
        run_data.get("run_name", "LangSmith SOC Evaluation"),
        run_data.get("dataset_name", "SOC-Copilot-Multi-SIEM-Threat-Intel-v1"),
        run_data.get("benchmark_version", "1.0.0"),
        run_data.get("test_cases_count", 0),
        run_data.get("passed_count", 0),
        run_data.get("accuracy_score", 0.0),
        run_data.get("avg_latency_ms", 0.0),
        json.dumps(run_data.get("results", [])),
        json.dumps(run_data.get("aggregate_metrics", {})),
        run_data.get("experiment_name"),
        run_data.get("experiment_url"),
        run_data.get("sync_status", "NOT_CONFIGURED"),
        run_data.get("error_details"),
        completed_at,
        run_data.get("created_at") or now_str
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
        if d.get("aggregate_metrics_json"):
            try:
                d["aggregate_metrics"] = json.loads(d["aggregate_metrics_json"])
            except Exception:
                d["aggregate_metrics"] = {}
        # Backwards compatibility flags
        d["langsmith_synced"] = (d.get("sync_status") == "SYNCED")
        results.append(d)
    return results

def get_eval_run_by_id(run_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pipeline_eval_runs WHERE id = ?", (run_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("results_json"):
        try:
            d["results"] = json.loads(d["results_json"])
        except Exception:
            d["results"] = []
    if d.get("aggregate_metrics_json"):
        try:
            d["aggregate_metrics"] = json.loads(d["aggregate_metrics_json"])
        except Exception:
            d["aggregate_metrics"] = {}
    d["langsmith_synced"] = (d.get("sync_status") == "SYNCED")
    return d

def delete_chat_session(session_id: str) -> bool:
    """Safely delete an isolated chat session and its turns for clean evaluation teardown."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM chat_messages WHERE session_id = ?", (session_id,))
    cursor.execute("DELETE FROM chat_sessions WHERE id = ?", (session_id,))
    conn.commit()
    conn.close()
    return True

# Identity & Access (IAM) Aggregation
def get_iam_data() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT user, siem_source, severity, alert_name, src_ip, dest_ip, timestamp, details_json
    FROM siem_logs
    WHERE user IS NOT NULL AND TRIM(user) != ''
    ORDER BY timestamp DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    users_map = {}
    policy_events = []

    for r in rows:
        u = r["user"].strip()
        if not u:
            continue
        if u not in users_map:
            is_svc = u.lower().startswith("svc") or u.endswith("$") or u.lower() in ("krbtgt", "system")
            is_priv = u.lower() in ("admin", "administrator", "root") or "admin" in u.lower()
            role = "Service Account" if is_svc else "Privileged Account" if is_priv else "Standard User"
            users_map[u] = {
                "username": u,
                "role": role,
                "risk_level": "LOW",
                "alert_count": 0,
                "last_seen": r["timestamp"],
                "source_ips": set(),
                "recent_alerts": [],
                "mfa_status": "N/A" if is_svc else "Unknown"
            }
        
        users_map[u]["alert_count"] += 1
        if r["src_ip"]:
            users_map[u]["source_ips"].add(r["src_ip"])
        users_map[u]["recent_alerts"].append(r["alert_name"] or "Security Event")

        # Escalate risk if critical/high
        sev = (r["severity"] or "").upper()
        if sev == "CRITICAL":
            users_map[u]["risk_level"] = "CRITICAL"
        elif sev == "HIGH" and users_map[u]["risk_level"] != "CRITICAL":
            users_map[u]["risk_level"] = "HIGH"

        # Determine authorization decision
        alert_lower = (r["alert_name"] or "").lower()
        if "brute" in alert_lower or "spray" in alert_lower or "unauthorized" in alert_lower:
            decision = "DENY"
            reason = "Excessive failed authentications or untrusted IP"
        elif "mimikatz" in alert_lower or "pass-the-hash" in alert_lower or "ticket" in alert_lower:
            decision = "STEP-UP REQUIRED"
            reason = "Suspicious Kerberos ticket request from unmanaged host"
        elif "c2" in alert_lower or "beacon" in alert_lower:
            decision = "DENY"
            reason = "Compromised credential beaconing to known malicious infrastructure"
        else:
            decision = "ALLOW"
            reason = "Authenticated within baseline network segment"

        policy_events.append({
            "id": f"pol-{len(policy_events)+1:03d}",
            "timestamp": r["timestamp"],
            "identity": u,
            "resource": r["dest_ip"] or r["src_ip"] or "Internal Subnet",
            "decision": decision,
            "reason": reason,
            "siem_source": r["siem_source"],
            "alert": r["alert_name"]
        })

    identities = []
    for u, data in users_map.items():
        data["source_ips"] = list(data["source_ips"])
        data["recent_alerts"] = data["recent_alerts"][:5]
        identities.append(data)

    return {
        "identities": identities,
        "policy_evaluations": policy_events[:50]
    }

# Audit Logs Functions
def get_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Collect audit entries from chat messages, eval runs, and logs
    cursor.execute("""
    SELECT id, created_at, role, content FROM chat_messages ORDER BY created_at DESC LIMIT 30
    """)
    chat_rows = cursor.fetchall()

    cursor.execute("""
    SELECT id, created_at, run_name, accuracy_score, passed_count, test_cases_count FROM pipeline_eval_runs ORDER BY created_at DESC LIMIT 20
    """)
    eval_rows = cursor.fetchall()

    cursor.execute("""
    SELECT id, timestamp, siem_source, alert_name, severity, user, src_ip, dest_ip FROM siem_logs ORDER BY created_at DESC LIMIT 50
    """)
    log_rows = cursor.fetchall()
    conn.close()

    audit_records = []

    # Chat queries
    for r in chat_rows:
        audit_records.append({
            "id": f"aud-chat-{r['id'][:8]}",
            "timestamp": r["created_at"],
            "actor": "senior_analyst" if r["role"] == "user" else "soc_copilot",
            "action": "QUERY_INVOCATION" if r["role"] == "user" else "COPILOT_RESPONSE_GENERATED",
            "target": "LLM_PIPELINE / CONVERSATION_MEMORY",
            "outcome": "SUCCESS",
            "correlation_id": r["id"],
            "evidence": r["content"][:80] + "..." if len(r["content"]) > 80 else r["content"]
        })

    # Evaluation benchmarks
    for r in eval_rows:
        audit_records.append({
            "id": f"aud-eval-{r['id'][:8]}",
            "timestamp": r["created_at"],
            "actor": "langsmith_eval_engine",
            "action": "BENCHMARK_EVALUATION_RUN",
            "target": r["run_name"] or "LangSmith Benchmark",
            "outcome": f"PASSED ({r['passed_count']}/{r['test_cases_count']})",
            "correlation_id": r["id"],
            "evidence": f"Accuracy: {r['accuracy_score']}%"
        })

    # Log ingestion audit
    for r in log_rows:
        audit_records.append({
            "id": f"aud-siem-{r['id'][:8]}",
            "timestamp": r["timestamp"],
            "actor": f"siem_agent/{r['siem_source']}",
            "action": "SECURITY_EVENT_INGESTION",
            "target": f"{r['src_ip'] or 'host'} -> {r['dest_ip'] or 'target'}",
            "outcome": "NORMALIZED",
            "correlation_id": r["id"],
            "evidence": f"[{r['severity']}] {r['alert_name']}"
        })

    # Sort all by timestamp descending
    audit_records.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    return audit_records[:limit]

