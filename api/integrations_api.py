"""
Integrations API — manage and test SIEM/webhook integrations.
"""

import logging
from fastapi import APIRouter, HTTPException
from services.siem_integrator import SIEMIntegrator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["Integrations"])

_integrator = SIEMIntegrator()


@router.get("/integrations")
async def list_integrations():
    """List all configured SIEM integration targets."""
    targets = []
    for t in _integrator.targets:
        targets.append({
            "name": t.get("name", "unnamed"),
            "type": t.get("type", "unknown"),
            "endpoint": t.get("endpoint", ""),
            "enabled": t.get("enabled", False),
            "events_sent": 0,
        })
    return {"targets": targets}


@router.post("/integrations/test/{target_name}")
async def test_integration(target_name: str):
    """Send a test event to a specific integration target."""
    target = None
    for t in _integrator.targets:
        if t.get("name") == target_name:
            target = t
            break
    if not target:
        raise HTTPException(status_code=404, detail=f"Integration target '{target_name}' not found")

    try:
        result = await _integrator.send_event(
            event_type="test",
            severity=1,
            details={"message": "Test event from Fortress Lens"},
        )
        return {"message": f"Test event sent to {target_name}", "success": True}
    except Exception as e:
        return {"message": f"Test failed: {str(e)}", "success": False}
