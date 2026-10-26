import os
from pathlib import Path
from typing import Optional
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"

if ENV_FILE.exists():
    load_dotenv(ENV_FILE)
else:
    load_dotenv()

class Settings:
    BASE_DIR: Path = BASE_DIR
    DB_PATH: Path = BASE_DIR / os.getenv("DATABASE_PATH", "soc_copilot.db")
    DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL")
    USE_POSTGRES: bool = bool(DATABASE_URL and ("postgres" in DATABASE_URL.lower()))
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "").strip().strip('"\'')

    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "").strip().strip('"\'')
    
    # LangSmith tracing & evaluation
    LANGCHAIN_API_KEY: str = (os.getenv("LANGCHAIN_API_KEY") or os.getenv("LANGSMITH_API_KEY") or "").strip().strip('"\'')
    LANGCHAIN_PROJECT: str = (os.getenv("LANGCHAIN_PROJECT") or os.getenv("LANGSMITH_PROJECT") or "soc-copilot").strip().strip('"\'')
    LANGCHAIN_ENDPOINT: str = (os.getenv("LANGCHAIN_ENDPOINT") or os.getenv("LANGSMITH_ENDPOINT") or "https://api.smith.langchain.com").strip().strip('"\'')
    LANGCHAIN_TRACING_V2: str = os.getenv("LANGCHAIN_TRACING_V2", "true").strip().strip('"\'')

    @classmethod
    def is_langsmith_configured(cls) -> bool:
        """Returns True if a valid LangSmith API key is present."""
        return bool(cls.LANGCHAIN_API_KEY and len(cls.LANGCHAIN_API_KEY) > 8 and not cls.LANGCHAIN_API_KEY.startswith("placeholder"))

    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")

    # Redis Streams Configuration
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_PASSWORD: Optional[str] = os.getenv("REDIS_PASSWORD", None)
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_URL: str = os.getenv("REDIS_URL", f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/0")

    # Stream Names
    STREAM_RAW: str = os.getenv("STREAM_RAW", "security:raw")
    STREAM_NORMALIZED: str = os.getenv("STREAM_NORMALIZED", "security:normalized")
    STREAM_ALERTS: str = os.getenv("STREAM_ALERTS", "security:alerts")
    STREAM_DLQ: str = os.getenv("STREAM_DLQ", "security:dlq")

    # Consumer Group Names
    GROUP_NORMALIZERS: str = os.getenv("GROUP_NORMALIZERS", "group:normalizers")
    GROUP_CORRELATORS: str = os.getenv("GROUP_CORRELATORS", "group:correlators")
    GROUP_PERSISTERS: str = os.getenv("GROUP_PERSISTERS", "group:persisters")

    # Worker Tuning
    STREAM_BATCH_SIZE: int = int(os.getenv("STREAM_BATCH_SIZE", "20"))
    STREAM_BLOCK_MS: int = int(os.getenv("STREAM_BLOCK_MS", "1000"))
    STREAM_CLAIM_MIN_IDLE_MS: int = int(os.getenv("STREAM_CLAIM_MIN_IDLE_MS", "15000"))
    STREAM_RETRY_MAX: int = int(os.getenv("STREAM_RETRY_MAX", "3"))


    @classmethod
    def update_keys(cls, gemini_key: str = None, vt_key: str = None, langsmith_key: str = None):
        """Update API keys dynamically in memory and persist to .env"""
        if gemini_key is not None:
            cls.GEMINI_API_KEY = gemini_key.strip()
            os.environ["GEMINI_API_KEY"] = cls.GEMINI_API_KEY
        if vt_key is not None:
            cls.VIRUSTOTAL_API_KEY = vt_key.strip()
            os.environ["VIRUSTOTAL_API_KEY"] = cls.VIRUSTOTAL_API_KEY
        if langsmith_key is not None:
            cls.LANGCHAIN_API_KEY = langsmith_key.strip()
            os.environ["LANGCHAIN_API_KEY"] = cls.LANGCHAIN_API_KEY
            if cls.LANGCHAIN_API_KEY:
                os.environ["LANGCHAIN_TRACING_V2"] = "true"
                os.environ["LANGCHAIN_PROJECT"] = cls.LANGCHAIN_PROJECT

        # Persist to .env
        env_content = f"""# Google Gemini API Key
GEMINI_API_KEY={cls.GEMINI_API_KEY}

# VirusTotal API v3 Key
VIRUSTOTAL_API_KEY={cls.VIRUSTOTAL_API_KEY}

# LangSmith Configuration
LANGCHAIN_TRACING_V2={cls.LANGCHAIN_TRACING_V2}
LANGCHAIN_API_KEY={cls.LANGCHAIN_API_KEY}
LANGCHAIN_PROJECT={cls.LANGCHAIN_PROJECT}
LANGCHAIN_ENDPOINT={cls.LANGCHAIN_ENDPOINT}

HOST={cls.HOST}
PORT={cls.PORT}
DATABASE_PATH=soc_copilot.db
DEBUG={cls.DEBUG}
"""
        with open(ENV_FILE, "w", encoding="utf-8") as f:
            f.write(env_content)

settings = Settings()

# Module-level exports for direct import
STREAM_RAW = settings.STREAM_RAW
STREAM_NORMALIZED = settings.STREAM_NORMALIZED
STREAM_ALERTS = settings.STREAM_ALERTS
STREAM_DLQ = settings.STREAM_DLQ

GROUP_NORMALIZERS = settings.GROUP_NORMALIZERS
GROUP_CORRELATORS = settings.GROUP_CORRELATORS
GROUP_PERSISTERS = settings.GROUP_PERSISTERS

STREAM_BATCH_SIZE = settings.STREAM_BATCH_SIZE
STREAM_BLOCK_MS = settings.STREAM_BLOCK_MS
STREAM_CLAIM_MIN_IDLE_MS = settings.STREAM_CLAIM_MIN_IDLE_MS
STREAM_RETRY_MAX = settings.STREAM_RETRY_MAX
