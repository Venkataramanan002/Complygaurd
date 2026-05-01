"""
Drift Detection & Alerts API.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import DriftEvent, Alert
from utils.drift_detector import DriftDetector

router = APIRouter(prefix="/api", tags=["Drift & Alerts"])


class AcknowledgeRequest(BaseModel):
    acknowledged_by: str


# ── Drift Events ─────────────────────────────────────────────────────────────

@router.get("/drift/events")
async def list_drift_events(
    device_name: Optional[str] = None,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(DriftEvent).order_by(desc(DriftEvent.detected_at)).limit(100)
    if device_name:
        stmt = stmt.where(DriftEvent.device_name == device_name)
    if severity:
        stmt = stmt.where(DriftEvent.severity == severity)
    if acknowledged is not None:
        stmt = stmt.where(DriftEvent.acknowledged == acknowledged)
    result = await db.execute(stmt)
    events = result.scalars().all()
    return {"events": [
        {
            "id": e.id,
            "device_name": e.device_name,
            "detected_at": e.detected_at.isoformat(),
            "severity": e.severity,
            "drift_summary": e.drift_summary,
            "acknowledged": e.acknowledged,
            "acknowledged_by": e.acknowledged_by,
            "remediation_action": e.remediation_action,
        }
        for e in events
    ]}


@router.post("/drift/events/{event_id}/acknowledge")
async def acknowledge_drift(event_id: str, req: AcknowledgeRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DriftEvent).where(DriftEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Drift event not found")
    event.acknowledged = True
    event.acknowledged_by = req.acknowledged_by
    await db.commit()
    return {"message": "Drift event acknowledged"}


@router.get("/drift/check-now/{device_name}")
async def check_drift_now(device_name: str):
    """Trigger immediate drift check for a device."""
    from dataclasses import asdict
    detector = DriftDetector()
    report = await detector.detect_drift(device_name)
    return asdict(report)


# ── Alerts ───────────────────────────────────────────────────────────────────

@router.get("/alerts")
async def list_alerts(
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
    if alert_type:
        stmt = stmt.where(Alert.alert_type == alert_type)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if acknowledged is not None:
        stmt = stmt.where(Alert.acknowledged == acknowledged)
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    return {"alerts": [
        {
            "id": a.id,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "title": a.title,
            "message": a.message,
            "source_device": a.source_device,
            "created_at": a.created_at.isoformat(),
            "acknowledged": a.acknowledged,
        }
        for a in alerts
    ]}


@router.get("/alerts/unread-count")
async def unread_alert_count(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(func.count(Alert.id)).where(Alert.acknowledged == False))
    return {"count": result.scalar() or 0}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, req: AcknowledgeRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    alert.acknowledged_by = req.acknowledged_by
    await db.commit()
    return {"message": "Alert acknowledged"}
