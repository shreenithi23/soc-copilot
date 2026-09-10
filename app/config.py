import os
from pathlib import Path
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
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "").strip().strip('"\'')
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "").strip().strip('"\'')
    
    # LangSmith tracing & evaluation
    LANGCHAIN_TRACING_V2: str = os.getenv("LANGCHAIN_TRACING_V2", "true")
    LANGCHAIN_API_KEY: str = os.getenv("LANGCHAIN_API_KEY", "").strip().strip('"\'')
    LANGCHAIN_PROJECT: str = os.getenv("LANGCHAIN_PROJECT", "soc-copilot")
    LANGCHAIN_ENDPOINT: str = os.getenv("LANGCHAIN_ENDPOINT", "https://api.smith.langchain.com")

    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")

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
