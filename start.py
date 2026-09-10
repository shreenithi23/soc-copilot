#!/usr/bin/env python3
"""
Entry point to launch the Multi-SIEM SOC Copilot server.
"""
import os
import sys
import uvicorn
from app.config import settings

if __name__ == "__main__":
    print(f"""
    ===============================================================
    🛡️  MULTI-SIEM SOC COPILOT & THREAT INTELLIGENCE ENGINE
    ===============================================================
    • SIEM Ingestion: Splunk, Elastic, Sentinel, QRadar, Wazuh
    • Threat Intel:   VirusTotal v3 Real-Time IOC Scanner
    • LangChain LLM:  Gemini API with Conversational Memory
    • LangSmith:      Pipeline Evaluation & Tracing
    • Local Web UI:   http://localhost:{settings.PORT}
    ===============================================================
    """)
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
