"""
Syslog Collection API — start / stop / status endpoints.

SECURITY: All endpoints require authentication. Start/stop require admin role.
"""

from fastapi import APIRouter, Depends
from collectors.syslog_server import get_syslog_server
from app.dependencies import require_auth, require_role

router = APIRouter(prefix="/api/syslog", tags=["Syslog"])


@router.post("/start")
async def start_syslog(user: dict = Depends(require_role("admin"))):
    """Start the syslog UDP+TCP listener and batch consumer."""
    server = get_syslog_server()
    if server._running:
        return {"message": "Syslog server is already running", **server.status()}
    await server.start()
    return {"message": "Syslog server started", **server.status()}


@router.post("/stop")
async def stop_syslog(user: dict = Depends(require_role("admin"))):
    """Gracefully stop the syslog server and drain remaining messages."""
    server = get_syslog_server()
    if not server._running:
        return {"message": "Syslog server is not running", **server.status()}
    await server.stop()
    return {"message": "Syslog server stopped", **server.status()}


@router.get("/status")
async def syslog_status(user: dict = Depends(require_auth)):
    """Return current syslog server statistics."""
    server = get_syslog_server()
    return server.status()
