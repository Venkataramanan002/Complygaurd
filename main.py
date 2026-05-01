"""
main.py — Application entry point.

Wires together:
  · All API routers
  · Security middleware (rate limit, logging, upload size, security headers)
  · CORS
  · Graceful startup / shutdown
"""

import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import logging
import os

import uvicorn
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

# ── Configure logging before any app imports ─────────────────────────────────
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)-5s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

from backend_topology import app as topology_app
from database.connection import init_db

# Routers
from api.ip_analysis import router as ip_analysis_router
from api.syslog_api import router as syslog_router
from api.collector_api import router as collector_router
from api.backup_api import router as backup_router
from api.lifecycle_api import router as lifecycle_router
from api.threat_intel_api import router as threat_intel_router
from api.change_mgmt_api import router as change_mgmt_router
from api.drift_alerts_api import router as drift_alerts_router
from api.auth import router as auth_router
from api.hardening_api import router as hardening_router
from api.simulation_api import router as simulation_router
from api.reports_api import router as reports_router
from api.segmentation_api import router as segmentation_router
from api.integrations_api import router as integrations_router
from api.device_analysis_api import router as device_analysis_router

# Security middleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_logging import RequestLoggingMiddleware
from app.middleware.upload_limit import UploadSizeLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

app = topology_app

# ── Register API routers ─────────────────────────────────────────────────────
# enterprise_router is already included in backend_topology.py
app.include_router(ip_analysis_router)
app.include_router(syslog_router)
app.include_router(collector_router)
app.include_router(backup_router)
app.include_router(lifecycle_router)
app.include_router(threat_intel_router)
app.include_router(change_mgmt_router)
app.include_router(drift_alerts_router)
app.include_router(auth_router)
app.include_router(hardening_router)
app.include_router(simulation_router)
app.include_router(reports_router)
app.include_router(segmentation_router)
app.include_router(integrations_router)
app.include_router(device_analysis_router)

# ── Security middleware (order matters — outermost first) ─────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(UploadSizeLimitMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestLoggingMiddleware)

# ── CORS ──────────────────────────────────────────────────────────────────────
_raw_origins = os.getenv("CORS_ORIGINS", "").strip()
if _raw_origins == "*":
    _allowed_origins = ["*"]
elif _raw_origins:
    _allowed_origins = [o.strip() for o in _raw_origins.split(",")]
else:
    _allowed_origins = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:8080",
        "http://localhost:8081",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    # SECURITY: removed allow_origin_regex to prevent any-port localhost bypass
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

# ── Startup ──────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    await init_db()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
