#!/usr/bin/env python3
"""
Aegis SOC Copilot: SQLite to Supabase (PostgreSQL) Migration Script
Migrates all existing records from local soc_copilot.db into Supabase PostgreSQL.
"""

import sys
import os
import sqlite3
import argparse
from pathlib import Path
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

def get_sqlite_conn(db_path: Path):
    if not db_path.exists():
        print(f"[!] SQLite database not found at {db_path}")
        sys.exit(1)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

def get_pg_conn(pg_url: str):
    try:
        conn = psycopg2.connect(pg_url)
        conn.autocommit = False
        return conn
    except Exception as e:
        print(f"[!] Failed to connect to Supabase PostgreSQL: {e}")
        sys.exit(1)

def apply_schema(pg_conn):
    schema_file = BASE_DIR / "scripts" / "supabase_schema.sql"
    if not schema_file.exists():
        print(f"[!] Schema file not found at {schema_file}")
        sys.exit(1)
    print("[-] Ensuring Supabase tables and indexes exist...")
    with open(schema_file, "r") as f:
        sql = f.read()
    with pg_conn.cursor() as cur:
        cur.execute(sql)
    pg_conn.commit()
    print("[+] Supabase schema applied successfully.")

def migrate_table(sqlite_conn, pg_conn, table_name: str, pkey: str = "id"):
    s_cur = sqlite_conn.cursor()
    
    # Check if table exists in SQLite
    s_cur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
    if not s_cur.fetchone():
        print(f"[*] Table '{table_name}' does not exist in SQLite, skipping.")
        return 0

    s_cur.execute(f"PRAGMA table_info({table_name})")
    cols = [row["name"] for row in s_cur.fetchall()]
    
    # Fetch all rows from SQLite
    s_cur.execute(f"SELECT * FROM {table_name}")
    rows = s_cur.fetchall()
    if not rows:
        print(f"[*] Table '{table_name}' is empty (0 rows).")
        return 0

    col_names_quoted = [f'"{c}"' if c == "user" else c for c in cols]
    cols_str = ", ".join(col_names_quoted)
    
    # Convert sqlite rows to tuples
    row_data = [tuple(r[c] for c in cols) for r in rows]

    # Batch insert into Postgres with ON CONFLICT DO NOTHING
    insert_sql = f"""
        INSERT INTO public.{table_name} ({cols_str})
        VALUES %s
        ON CONFLICT ({pkey}) DO NOTHING
    """

    with pg_conn.cursor() as p_cur:
        execute_values(p_cur, insert_sql, row_data, page_size=500)
    pg_conn.commit()
    print(f"[+] Migrated {len(rows)} records into public.{table_name}")
    return len(rows)

def main():
    parser = argparse.ArgumentParser(description="Migrate SOC Copilot SQLite database to Supabase")
    parser.add_argument("--url", help="Supabase PostgreSQL connection string (or set DATABASE_URL in .env)")
    parser.add_argument("--sqlite", default=str(BASE_DIR / "soc_copilot.db"), help="Path to local soc_copilot.db")
    args = parser.parse_args()

    pg_url = args.url or os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL")
    if not pg_url:
        print("[!] No Supabase PostgreSQL URL provided.")
        print("    Usage: python scripts/migrate_to_supabase.py --url 'postgresql://postgres:[PASSWORD]@[HOST]:[PORT]/postgres'")
        print("    Or define DATABASE_URL in your .env file.")
        sys.exit(1)

    print("=======================================================")
    print("   AEGIS SOC COPILOT -> SUPABASE MIGRATION WIZARD")
    print("=======================================================")
    sqlite_conn = get_sqlite_conn(Path(args.sqlite))
    pg_conn = get_pg_conn(pg_url)

    # 1. Apply Schema
    apply_schema(pg_conn)

    # 2. Migrate in dependency order
    tables = [
        ("chat_sessions", "id"),
        ("chat_messages", "id"),
        ("threat_intel_cache", "indicator"),
        ("pipeline_eval_runs", "id"),
        ("siem_logs", "id"),
        ("security_alerts", "id")
    ]

    total_migrated = 0
    for tbl, pkey in tables:
        count = migrate_table(sqlite_conn, pg_conn, tbl, pkey)
        total_migrated += count

    sqlite_conn.close()
    pg_conn.close()

    print("=======================================================")
    print(f"[✓] Migration complete! Successfully transferred {total_migrated} total records to Supabase.")
    print("=======================================================")

if __name__ == "__main__":
    main()
