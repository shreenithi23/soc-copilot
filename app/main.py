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

from contextlib import asynccontextmanager
from app.api.stream_routes import router as stream_router
from app.streaming.manager import stream_manager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    stats = get_stats()
    if stats["total_logs"] == 0:
        print("[Startup] Initializing realistic Multi-SIEM attack scenarios...")
        generate_multi_siem_seed_logs()
        print("[Startup] Seeded Multi-SIEM attack logs and IOC cache successfully.")
    
    # Initialize Redis streams and launch processing workers
    try:
        await stream_manager.start_all(start_producer=False)
        print("[Startup] Redis Streams processing pipeline initialized successfully.")
    except Exception as e:
        print(f"[Startup] Warning: Could not initialize Redis streams: {e}")

    yield

    # Shutdown
    try:
        await stream_manager.stop_all()
        print("[Shutdown] Redis Streams workers shut down cleanly.")
    except Exception as e:
        print(f"[Shutdown] Error during stream manager shutdown: {e}")

app = FastAPI(
    title="Multi-SIEM SOC Copilot",
    description="LLM-powered Threat Hunting & Multi-SIEM Security Operations Center Assistant",
    version="1.0.0",
    lifespan=lifespan,
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
app.include_router(stream_router, prefix="/api")

# Static files directory
STATIC_DIR = settings.BASE_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "SOC Copilot API is running. Static frontend not found."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
