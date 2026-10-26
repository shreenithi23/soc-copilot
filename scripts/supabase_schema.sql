-- =====================================================================
-- Aegis SOC Copilot: Supabase (PostgreSQL) Production Schema
-- Compatible with Supabase SQL Editor and direct psql / psycopg2 migrations
-- =====================================================================

-- 1. SIEM Logs (Normalized Canonical Telemetry)
CREATE TABLE IF NOT EXISTS public.siem_logs (
    id TEXT PRIMARY KEY,
    siem_source TEXT NOT NULL,
    timestamp TIMESTAMPTZ,
    severity TEXT,
    event_type TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    src_port INTEGER,
    dest_port INTEGER,
    "user" TEXT,
    file_hash TEXT,
    domain TEXT,
    alert_name TEXT,
    details_json TEXT,
    raw_log TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    normalization_status TEXT DEFAULT 'success',
    mapping_version TEXT DEFAULT '2.0.0',
    unmapped_fields_json TEXT,
    conflicting_fields_json TEXT,
    validation_errors_json TEXT,
    src_host TEXT,
    dest_host TEXT,
    src_user TEXT,
    dest_user TEXT,
    protocol TEXT,
    action TEXT,
    raw_event_json TEXT,
    threat_intel_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_siem_logs_source ON public.siem_logs(siem_source);
CREATE INDEX IF NOT EXISTS idx_siem_logs_severity ON public.siem_logs(severity);
CREATE INDEX IF NOT EXISTS idx_siem_logs_src_ip ON public.siem_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_siem_logs_dest_ip ON public.siem_logs(dest_ip);
CREATE INDEX IF NOT EXISTS idx_siem_logs_norm_status ON public.siem_logs(normalization_status);
CREATE INDEX IF NOT EXISTS idx_siem_logs_created_at ON public.siem_logs(created_at DESC);

-- 2. Chat Sessions (Conversational Memory Sessions)
CREATE TABLE IF NOT EXISTS public.chat_sessions (
    id TEXT PRIMARY KEY,
    title TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Chat Messages (Multi-Turn Threat Hunting Conversations)
CREATE TABLE IF NOT EXISTS public.chat_messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES public.chat_sessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    context_logs_json TEXT,
    threat_intel_json TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON public.chat_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_created ON public.chat_messages(created_at);

-- 4. Threat Intel Cache (VirusTotal IOC Reputation Cache)
CREATE TABLE IF NOT EXISTS public.threat_intel_cache (
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
    last_checked_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON public.threat_intel_cache(ioc_type);

-- 5. Pipeline Evaluation Runs (LangSmith & Benchmark Metrics)
CREATE TABLE IF NOT EXISTS public.pipeline_eval_runs (
    id TEXT PRIMARY KEY,
    run_name TEXT,
    dataset_name TEXT,
    benchmark_version TEXT DEFAULT '1.0.0',
    test_cases_count INTEGER,
    passed_count INTEGER,
    accuracy_score DOUBLE PRECISION,
    avg_latency_ms DOUBLE PRECISION,
    results_json TEXT,
    aggregate_metrics_json TEXT,
    experiment_name TEXT,
    experiment_url TEXT,
    sync_status TEXT DEFAULT 'NOT_CONFIGURED',
    error_details TEXT,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_eval_runs_created ON public.pipeline_eval_runs(created_at DESC);

-- 6. Security Alerts (Redis Stream Sliding-Window Correlated Incidents)
CREATE TABLE IF NOT EXISTS public.security_alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    entity_type TEXT,
    entity_value TEXT,
    "user" TEXT,
    host TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    event_count INTEGER DEFAULT 1,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    contributing_event_ids_json TEXT,
    evidence_json TEXT,
    status TEXT DEFAULT 'OPEN',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sec_alerts_rule ON public.security_alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_sec_alerts_sev ON public.security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_sec_alerts_user ON public.security_alerts("user");
CREATE INDEX IF NOT EXISTS idx_sec_alerts_created ON public.security_alerts(created_at DESC);
