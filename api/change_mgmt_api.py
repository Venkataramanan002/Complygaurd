"""
Change Management API — request, review, approve, deploy, rollback workflow.
"""

import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import ChangeRequest, ChangeComment, FirewallRule, AdminAudit
from database.operations import insert_admin_audit

router = APIRouter(prefix="/api/changes", tags=["Change Management"])

# Valid status transitions
VALID_TRANSITIONS = {
    "draft": ["pending_review"],
    "pending_review": ["approved", "rejected"],
    "approved": ["implementing", "deployed"],
    "implementing": ["deployed", "failed"],
    "deployed": ["rolled_back"],
    "rejected": ["draft"],
    "failed": ["draft"],
    "rolled_back": ["draft"],
}


class CreateChangeRequest(BaseModel):
    title: str
    description: str = ""
    requester_name: str
    requester_email: str = ""
    priority: str = "medium"
    device_name: str = ""
    change_type: str = "add_rule"
    proposed_changes: list = []


class ReviewRequest(BaseModel):
    reviewer_name: str
    notes: str = ""


class CommentRequest(BaseModel):
    author: str
    comment: str


@router.post("")
async def create_change(req: CreateChangeRequest, db: AsyncSession = Depends(get_db)):
    """Create a new change request with auto risk assessment."""
    # Auto-calculate risk score from proposed changes
    risk_score = 0.0
    for rule in req.proposed_changes:
        if rule.get("action") == "allow":
            if rule.get("source_ip", "").lower() in ("any", "0.0.0.0/0"):
                risk_score += 2
            if rule.get("dest_ip", "").lower() in ("any", "0.0.0.0/0"):
                risk_score += 2
            if rule.get("dest_port", "").lower() in ("any", "1-65535"):
                risk_score += 1.5

    cr = ChangeRequest(
        title=req.title,
        description=req.description,
        requester_name=req.requester_name,
        requester_email=req.requester_email,
        status="pending_review",
        priority=req.priority,
        device_name=req.device_name,
        change_type=req.change_type,
        proposed_changes=req.proposed_changes,
        risk_score=min(risk_score, 10.0),
        risk_assessment={"risk_score": risk_score, "rules_count": len(req.proposed_changes)},
    )
    db.add(cr)
    await db.commit()
    await db.refresh(cr)
    return {"id": cr.id, "status": cr.status, "risk_score": cr.risk_score}


@router.get("")
async def list_changes(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    device: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List change requests with filters."""
    stmt = select(ChangeRequest).order_by(desc(ChangeRequest.request_date))
    if status:
        stmt = stmt.where(ChangeRequest.status == status)
    if priority:
        stmt = stmt.where(ChangeRequest.priority == priority)
    if device:
        stmt = stmt.where(ChangeRequest.device_name == device)
    result = await db.execute(stmt)
    changes = result.scalars().all()
    return {"changes": [_cr_to_dict(c) for c in changes], "total": len(changes)}


@router.get("/dashboard")
async def change_dashboard(db: AsyncSession = Depends(get_db)):
    """KPI summary for change management."""
    now = datetime.datetime.utcnow()
    week_ago = now - datetime.timedelta(days=7)

    total = (await db.execute(select(func.count(ChangeRequest.id)))).scalar() or 0
    pending = (await db.execute(select(func.count(ChangeRequest.id)).where(ChangeRequest.status == "pending_review"))).scalar() or 0
    deployed_week = (await db.execute(select(func.count(ChangeRequest.id)).where(
        ChangeRequest.status == "deployed", ChangeRequest.deployment_date >= week_ago
    ))).scalar() or 0
    rollbacks = (await db.execute(select(func.count(ChangeRequest.id)).where(ChangeRequest.status == "rolled_back"))).scalar() or 0

    return {"total": total, "pending_review": pending, "deployed_this_week": deployed_week, "rollbacks": rollbacks}


@router.get("/{change_id}")
async def get_change(change_id: str, db: AsyncSession = Depends(get_db)):
    """Get full change request detail with comments."""
    cr = await _get_cr(db, change_id)
    comments_r = await db.execute(
        select(ChangeComment).where(ChangeComment.change_request_id == change_id).order_by(ChangeComment.created_at)
    )
    comments = [{"id": c.id, "author": c.author, "comment": c.comment, "created_at": c.created_at.isoformat()} for c in comments_r.scalars().all()]
    d = _cr_to_dict(cr)
    d["comments"] = comments
    return d


@router.post("/{change_id}/approve")
async def approve_change(change_id: str, req: ReviewRequest, db: AsyncSession = Depends(get_db)):
    """Approve a pending change request."""
    cr = await _get_cr(db, change_id)
    _enforce_transition(cr.status, "approved")
    cr.status = "approved"
    cr.reviewer_name = req.reviewer_name
    cr.review_date = datetime.datetime.utcnow()
    cr.review_notes = req.notes
    await db.commit()
    await _audit(db, cr.device_name or "system", req.reviewer_name, "change_approved", f"Change '{cr.title}' approved")
    return {"message": "Change approved", "id": cr.id, "status": "approved"}


@router.post("/{change_id}/reject")
async def reject_change(change_id: str, req: ReviewRequest, db: AsyncSession = Depends(get_db)):
    """Reject a pending change request."""
    cr = await _get_cr(db, change_id)
    _enforce_transition(cr.status, "rejected")
    cr.status = "rejected"
    cr.reviewer_name = req.reviewer_name
    cr.review_date = datetime.datetime.utcnow()
    cr.review_notes = req.notes
    await db.commit()
    await _audit(db, cr.device_name or "system", req.reviewer_name, "change_rejected", f"Change '{cr.title}' rejected")
    return {"message": "Change rejected", "id": cr.id, "status": "rejected"}


@router.post("/{change_id}/deploy")
async def deploy_change(change_id: str, db: AsyncSession = Depends(get_db)):
    """Deploy an approved change (insert rules into DB)."""
    cr = await _get_cr(db, change_id)
    _enforce_transition(cr.status, "deployed")

    try:
        # Store existing rules as rollback data
        existing_r = await db.execute(select(FirewallRule).where(FirewallRule.device_name == cr.device_name))
        existing = existing_r.scalars().all()
        cr.rollback_data = [{"id": r.id, "rule_name": r.rule_name, "source_ip": r.source_ip, "dest_ip": r.dest_ip, "dest_port": r.dest_port, "protocol": r.protocol, "action": r.action} for r in existing]

        # Apply proposed changes
        for rule_def in (cr.proposed_changes or []):
            if cr.change_type == "add_rule":
                new_rule = FirewallRule(
                    device_name=cr.device_name,
                    rule_name=rule_def.get("rule_name", ""),
                    source_ip=rule_def.get("source_ip", "any"),
                    dest_ip=rule_def.get("dest_ip", "any"),
                    dest_port=rule_def.get("dest_port", "any"),
                    protocol=rule_def.get("protocol", "any"),
                    action=rule_def.get("action", "allow"),
                    rule_position=rule_def.get("position", len(existing) + 1),
                    is_enabled=True,
                )
                db.add(new_rule)

        cr.status = "deployed"
        cr.deployment_date = datetime.datetime.utcnow()
        await db.commit()
        await _audit(db, cr.device_name or "system", cr.requester_name, "change_deployed", f"Change '{cr.title}' deployed")
        return {"message": "Change deployed", "id": cr.id, "status": "deployed"}

    except Exception as e:
        cr.status = "failed"
        await db.commit()
        return {"message": f"Deployment failed: {e}", "id": cr.id, "status": "failed"}


@router.post("/{change_id}/rollback")
async def rollback_change(change_id: str, db: AsyncSession = Depends(get_db)):
    """Rollback a deployed change."""
    cr = await _get_cr(db, change_id)
    _enforce_transition(cr.status, "rolled_back")
    cr.status = "rolled_back"
    await db.commit()
    await _audit(db, cr.device_name or "system", "system", "change_rolled_back", f"Change '{cr.title}' rolled back")
    return {"message": "Change rolled back", "id": cr.id, "status": "rolled_back"}


@router.post("/{change_id}/comment")
async def add_comment(change_id: str, req: CommentRequest, db: AsyncSession = Depends(get_db)):
    """Add a comment to a change request."""
    await _get_cr(db, change_id)  # verify exists
    comment = ChangeComment(change_request_id=change_id, author=req.author, comment=req.comment)
    db.add(comment)
    await db.commit()
    return {"message": "Comment added"}


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _get_cr(db: AsyncSession, change_id: str) -> ChangeRequest:
    result = await db.execute(select(ChangeRequest).where(ChangeRequest.id == change_id))
    cr = result.scalar_one_or_none()
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")
    return cr


def _enforce_transition(current: str, target: str):
    allowed = VALID_TRANSITIONS.get(current, [])
    if target not in allowed:
        raise HTTPException(status_code=400, detail=f"Cannot transition from '{current}' to '{target}'. Allowed: {allowed}")


def _cr_to_dict(cr: ChangeRequest) -> dict:
    return {
        "id": cr.id,
        "title": cr.title,
        "description": cr.description,
        "requester_name": cr.requester_name,
        "status": cr.status,
        "priority": cr.priority,
        "device_name": cr.device_name,
        "change_type": cr.change_type,
        "proposed_changes": cr.proposed_changes,
        "risk_score": cr.risk_score,
        "risk_assessment": cr.risk_assessment,
        "reviewer_name": cr.reviewer_name,
        "review_date": cr.review_date.isoformat() if cr.review_date else None,
        "review_notes": cr.review_notes,
        "deployment_date": cr.deployment_date.isoformat() if cr.deployment_date else None,
        "request_date": cr.request_date.isoformat() if cr.request_date else None,
    }


async def _audit(db: AsyncSession, device: str, user: str, action: str, detail: str):
    audit = AdminAudit(device_name=device, admin_username=user, action_type=action, change_after=detail)
    db.add(audit)
    await db.commit()
