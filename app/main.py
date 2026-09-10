import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db, get_stats
from app.seed_data import generate_multi_siem_seed_logs
from app.api.routes import router as api_router

app = FastAPI(
    title="Multi-SIEM SOC Copilot",
    description="LLM-powered Threat Hunting & Multi-SIEM Security Operations Center Assistant",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(api_router, prefix="/api")

# Static files directory
STATIC_DIR = settings.BASE_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.on_event("startup")
def on_startup():
    """Initialize database and seed baseline dataset if empty."""
    init_db()
    stats = get_stats()
    if stats["total_logs"] == 0:
        print("[Startup] Initializing realistic Multi-SIEM attack scenarios...")
        generate_multi_siem_seed_logs()
        print("[Startup] Seeded Multi-SIEM attack logs and IOC cache successfully.")

@app.get("/")
def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "SOC Copilot API is running. Static frontend not found."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
