"""
Device Collector API — poll, status, schedule, and device management endpoints.

SECURITY: All endpoints require authentication. Mutating ops require admin role.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
from collectors.api_client import get_device_collector, DeviceConfig
from app.dependencies import require_auth, require_role

router = APIRouter(prefix="/api/collectors", tags=["Collectors"])


class PollRequest(BaseModel):
    device_name: str


class AddDeviceRequest(BaseModel):
    name: str
    host: str
    vendor: str  # paloalto | fortinet | cisco
    auth_type: str  # apikey | token | basic
    credentials_env_var: str
    poll_interval_minutes: int = 15
    enabled: bool = True
    verify_ssl: bool = False


@router.post("/poll-now")
async def poll_now(req: PollRequest, user: dict = Depends(require_role("admin"))):
    """Trigger an immediate poll for a specific device."""
    collector = get_device_collector()
    result = await collector.poll(req.device_name)
    return {
        "device_name": result.device_name,
        "vendor": result.vendor,
        "success": result.success,
        "rules_collected": result.rules_collected,
        "health_collected": result.health_collected,
        "error": result.error,
        "timestamp": result.timestamp,
    }


@router.get("/status")
async def collector_status(user: dict = Depends(require_auth)):
    """Return status of all configured devices and their last poll results."""
    collector = get_device_collector()
    return collector.status()


@router.post("/schedule")
async def toggle_schedule(user: dict = Depends(require_role("admin"))):
    """Start or stop scheduled polling for all enabled devices."""
    collector = get_device_collector()
    if collector._scheduling_active:
        await collector.stop_scheduled_polling()
        return {"message": "Scheduled polling stopped", "scheduling_active": False}
    else:
        await collector.start_scheduled_polling()
        return {"message": "Scheduled polling started", "scheduling_active": True}


@router.post("/devices")
async def add_device(req: AddDeviceRequest, user: dict = Depends(require_role("admin"))):
    """Add a new device to the configuration."""
    collector = get_device_collector()
    device = DeviceConfig(
        name=req.name,
        host=req.host,
        vendor=req.vendor,
        auth_type=req.auth_type,
        credentials_env_var=req.credentials_env_var,
        poll_interval_minutes=req.poll_interval_minutes,
        enabled=req.enabled,
        verify_ssl=req.verify_ssl,
    )
    collector.add_device(device)
    return {"message": f"Device '{req.name}' added", "device": req.dict()}


@router.get("/devices")
async def list_devices(user: dict = Depends(require_auth)):
    """List all configured devices (credentials excluded)."""
    collector = get_device_collector()
    return {
        "devices": [
            {
                "name": d.name,
                "host": d.host,
                "vendor": d.vendor,
                "auth_type": d.auth_type,
                "poll_interval_minutes": d.poll_interval_minutes,
                "enabled": d.enabled,
                "verify_ssl": d.verify_ssl,
            }
            for d in collector.get_devices()
        ]
    }
