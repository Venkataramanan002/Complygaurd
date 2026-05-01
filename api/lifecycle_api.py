"""
Rule Lifecycle Management API — ownership, certification, and recertification workflows.
"""

import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import FirewallRule, RuleOwner, CertificationReview

router = APIRouter(prefix="/api", tags=["Rule Lifecycle"])


# ── Request models ───────────────────────────────────────────────────────────

class AssignOwnerRequest(BaseModel):
    owner_name: str
    owner_email: str
    department: str = ""


class CertifyRequest(BaseModel):
    reviewer_name: str
    decision: str  # certify | modify | decommission
    justification: str = ""
    next_review_months: int = 6
    risk_accepted: bool = False


class BulkAssignRequest(BaseModel):
    rule_ids: List[str]
    owner_name: str
    owner_email: str
    department: str = ""


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/rules/{rule_id}/assign-owner")
async def assign_owner(rule_id: str, req: AssignOwnerRequest, db: AsyncSession = Depends(get_db)):
    """Assign or update ownership for a firewall rule."""
    rule = await _get_rule(db, rule_id)

    # Check if owner already exists for this rule
    existing = await db.execute(
        select(RuleOwner).where(RuleOwner.rule_id == rule_id)
    )
    owner = existing.scalar_one_or_none()

    now = datetime.datetime.utcnow()
    due = now + datetime.timedelta(days=180)  # default 6-month review

    if owner:
        owner.owner_name = req.owner_name
        owner.owner_email = req.owner_email
        owner.department = req.department
        owner.assigned_date = now
        owner.status = "active"
    else:
        owner = RuleOwner(
            rule_id=rule_id,
            owner_name=req.owner_name,
            owner_email=req.owner_email,
            department=req.department,
            assigned_date=now,
            certification_due_date=due,
            status="active",
        )
        db.add(owner)

    await db.commit()
    return {"message": f"Owner assigned to rule '{rule.rule_name}'", "rule_id": rule_id, "owner": req.owner_name}


@router.get("/rules/due-for-review")
async def rules_due_for_review(
    days_until_due: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    """Get rules where certification expires within N days."""
    cutoff = datetime.datetime.utcnow() + datetime.timedelta(days=days_until_due)
    stmt = (
        select(RuleOwner, FirewallRule)
        .join(FirewallRule, RuleOwner.rule_id == FirewallRule.id)
        .where(
            and_(
                RuleOwner.certification_due_date <= cutoff,
                RuleOwner.status.in_(["active", "pending_review"]),
            )
        )
        .order_by(RuleOwner.certification_due_date)
    )
    result = await db.execute(stmt)
    rows = result.all()

    return {
        "due_count": len(rows),
        "rules": [
            {
                "rule_id": rule.id,
                "rule_name": rule.rule_name,
                "device_name": rule.device_name,
                "owner_name": owner.owner_name,
                "owner_email": owner.owner_email,
                "department": owner.department,
                "last_certified_date": owner.last_certified_date.isoformat() if owner.last_certified_date else None,
                "certification_due_date": owner.certification_due_date.isoformat() if owner.certification_due_date else None,
                "status": owner.status,
                "days_until_due": (owner.certification_due_date - datetime.datetime.utcnow()).days if owner.certification_due_date else None,
            }
            for owner, rule in rows
        ],
    }


@router.post("/rules/{rule_id}/certify")
async def certify_rule(rule_id: str, req: CertifyRequest, db: AsyncSession = Depends(get_db)):
    """Submit a certification review for a rule."""
    rule = await _get_rule(db, rule_id)
    now = datetime.datetime.utcnow()
    next_review = now + datetime.timedelta(days=req.next_review_months * 30)

    # Create review record
    review = CertificationReview(
        rule_id=rule_id,
        reviewer_name=req.reviewer_name,
        review_date=now,
        decision=req.decision,
        justification=req.justification,
        risk_accepted=req.risk_accepted,
        next_review_date=next_review,
    )
    db.add(review)

    # Update owner record
    owner_result = await db.execute(
        select(RuleOwner).where(RuleOwner.rule_id == rule_id)
    )
    owner = owner_result.scalar_one_or_none()
    if owner:
        owner.last_certified_date = now
        owner.certification_due_date = next_review
        if req.decision == "decommission":
            owner.status = "decommissioned"
        elif req.decision == "certify":
            owner.status = "active"
        else:
            owner.status = "pending_review"

    await db.commit()
    return {
        "message": f"Rule '{rule.rule_name}' reviewed: {req.decision}",
        "rule_id": rule_id,
        "next_review_date": next_review.isoformat(),
    }


@router.get("/rules/{rule_id}/lifecycle")
async def rule_lifecycle(rule_id: str, db: AsyncSession = Depends(get_db)):
    """Get full lifecycle history of a rule: ownership + reviews."""
    rule = await _get_rule(db, rule_id)

    owner_result = await db.execute(
        select(RuleOwner).where(RuleOwner.rule_id == rule_id)
    )
    owner = owner_result.scalar_one_or_none()

    reviews_result = await db.execute(
        select(CertificationReview)
        .where(CertificationReview.rule_id == rule_id)
        .order_by(CertificationReview.review_date.desc())
    )
    reviews = reviews_result.scalars().all()

    return {
        "rule": {
            "id": rule.id,
            "rule_name": rule.rule_name,
            "device_name": rule.device_name,
            "action": rule.action,
            "source_ip": rule.source_ip,
            "dest_ip": rule.dest_ip,
        },
        "owner": {
            "owner_name": owner.owner_name,
            "owner_email": owner.owner_email,
            "department": owner.department,
            "assigned_date": owner.assigned_date.isoformat() if owner else None,
            "last_certified_date": owner.last_certified_date.isoformat() if owner and owner.last_certified_date else None,
            "certification_due_date": owner.certification_due_date.isoformat() if owner and owner.certification_due_date else None,
            "status": owner.status,
        } if owner else None,
        "reviews": [
            {
                "id": r.id,
                "reviewer_name": r.reviewer_name,
                "review_date": r.review_date.isoformat(),
                "decision": r.decision,
                "justification": r.justification,
                "risk_accepted": r.risk_accepted,
                "next_review_date": r.next_review_date.isoformat() if r.next_review_date else None,
            }
            for r in reviews
        ],
    }


@router.post("/rules/bulk-assign")
async def bulk_assign_owner(req: BulkAssignRequest, db: AsyncSession = Depends(get_db)):
    """Assign the same owner to multiple rules at once."""
    now = datetime.datetime.utcnow()
    due = now + datetime.timedelta(days=180)
    count = 0

    for rid in req.rule_ids:
        existing = await db.execute(select(RuleOwner).where(RuleOwner.rule_id == rid))
        owner = existing.scalar_one_or_none()
        if owner:
            owner.owner_name = req.owner_name
            owner.owner_email = req.owner_email
            owner.department = req.department
            owner.assigned_date = now
        else:
            db.add(RuleOwner(
                rule_id=rid,
                owner_name=req.owner_name,
                owner_email=req.owner_email,
                department=req.department,
                assigned_date=now,
                certification_due_date=due,
                status="active",
            ))
        count += 1

    await db.commit()
    return {"message": f"Owner assigned to {count} rules", "assigned_count": count}


@router.get("/lifecycle/dashboard")
async def lifecycle_dashboard(db: AsyncSession = Depends(get_db)):
    """Summary dashboard for rule lifecycle status."""
    # Total rules
    total_result = await db.execute(select(func.count(FirewallRule.id)))
    total_rules = total_result.scalar() or 0

    # Count owned rules
    owned_result = await db.execute(select(func.count(RuleOwner.id)))
    total_owned = owned_result.scalar() or 0

    # Count by status
    now = datetime.datetime.utcnow()
    soon = now + datetime.timedelta(days=30)

    certified_result = await db.execute(
        select(func.count(RuleOwner.id)).where(RuleOwner.status == "active")
    )
    certified = certified_result.scalar() or 0

    expired_result = await db.execute(
        select(func.count(RuleOwner.id)).where(
            and_(RuleOwner.certification_due_date < now, RuleOwner.status != "decommissioned")
        )
    )
    expired = expired_result.scalar() or 0

    due_soon_result = await db.execute(
        select(func.count(RuleOwner.id)).where(
            and_(
                RuleOwner.certification_due_date >= now,
                RuleOwner.certification_due_date <= soon,
                RuleOwner.status != "decommissioned",
            )
        )
    )
    due_soon = due_soon_result.scalar() or 0

    decommissioned_result = await db.execute(
        select(func.count(RuleOwner.id)).where(RuleOwner.status == "decommissioned")
    )
    decommissioned = decommissioned_result.scalar() or 0

    unowned = total_rules - total_owned

    return {
        "total_rules": total_rules,
        "certified": certified,
        "expired": expired,
        "due_soon": due_soon,
        "unowned": unowned,
        "decommissioned": decommissioned,
        "certified_pct": round(certified / max(total_rules, 1) * 100, 1),
        "expired_pct": round(expired / max(total_rules, 1) * 100, 1),
        "due_soon_pct": round(due_soon / max(total_rules, 1) * 100, 1),
        "unowned_pct": round(unowned / max(total_rules, 1) * 100, 1),
    }


@router.get("/lifecycle/rules")
async def lifecycle_rules(
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List all rules with their lifecycle status for the table view."""
    stmt = select(FirewallRule).order_by(FirewallRule.device_name, FirewallRule.rule_position).limit(limit)
    result = await db.execute(stmt)
    rules = result.scalars().all()

    # Fetch all owners in one query
    owner_result = await db.execute(select(RuleOwner))
    owners_by_rule = {o.rule_id: o for o in owner_result.scalars().all()}

    items = []
    for r in rules:
        owner = owners_by_rule.get(r.id)
        owner_status = owner.status if owner else "unowned"

        if status and status != "all":
            if status == "unowned" and owner:
                continue
            elif status != "unowned" and (not owner or owner.status != status):
                continue

        if search:
            s = search.lower()
            name_match = s in (r.rule_name or "").lower()
            owner_match = owner and s in (owner.owner_name or "").lower()
            if not name_match and not owner_match:
                continue

        items.append({
            "rule_id": r.id,
            "rule_name": r.rule_name,
            "device_name": r.device_name,
            "action": r.action,
            "source_ip": r.source_ip,
            "dest_ip": r.dest_ip,
            "owner_name": owner.owner_name if owner else None,
            "owner_email": owner.owner_email if owner else None,
            "department": owner.department if owner else None,
            "last_certified_date": owner.last_certified_date.isoformat() if owner and owner.last_certified_date else None,
            "certification_due_date": owner.certification_due_date.isoformat() if owner and owner.certification_due_date else None,
            "status": owner_status,
        })

    return {"rules": items, "total": len(items)}


async def _get_rule(db: AsyncSession, rule_id: str) -> FirewallRule:
    result = await db.execute(select(FirewallRule).where(FirewallRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    return rule
