"""
api/hardening_api.py
Device hardening assessment endpoints.

Runs the HardeningEngine against all (or a single) device and returns
scored results with per-check details.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import FirewallRule, NetworkTopology
from utils.hardening_engine import HardeningEngine

router = APIRouter(prefix="/api/hardening", tags=["Hardening"])

_engine = HardeningEngine()


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class HardeningSummaryItem(BaseModel):
    device_name: str
    score: float
    grade: str


class HardeningCheckItem(BaseModel):
    check_id: str
    check_name: str
    status: str
    severity: str
    description: str
    remediation: str | None = None


class HardeningDetailResponse(BaseModel):
    device_name: str
    score: float
    grade: str
    checks: List[HardeningCheckItem]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _load_rules_and_topology(db: AsyncSession):
    """Fetch all enabled firewall rules and topology rows in one pass."""
    rules_result = await db.execute(
        select(FirewallRule).where(FirewallRule.is_enabled == True)
    )
    rules: List[FirewallRule] = list(rules_result.scalars().all())

    topo_result = await db.execute(select(NetworkTopology))
    topo_rows: List[NetworkTopology] = list(topo_result.scalars().all())

    # Build a quick lookup: device_name -> first topology row
    topo_map: Dict[str, NetworkTopology] = {}
    for t in topo_rows:
        if t.device_name not in topo_map:
            topo_map[t.device_name] = t

    return rules, topo_map


def _unique_device_names(rules: List[FirewallRule]) -> List[str]:
    seen: set[str] = set()
    names: List[str] = []
    for r in rules:
        if r.device_name not in seen:
            seen.add(r.device_name)
            names.append(r.device_name)
    names.sort()
    return names


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/summary", response_model=List[HardeningSummaryItem])
async def hardening_summary(db: AsyncSession = Depends(get_db)):
    """Run hardening checks on every device and return a scored summary list."""
    rules, topo_map = await _load_rules_and_topology(db)
    device_names = _unique_device_names(rules)

    results: List[HardeningSummaryItem] = []
    for name in device_names:
        report = _engine.check_device(name, rules, topo_map.get(name))
        results.append(
            HardeningSummaryItem(
                device_name=report["device_name"],
                score=report["score"],
                grade=report["grade"],
            )
        )

    # Sort worst-first so the dashboard highlights the weakest devices
    results.sort(key=lambda r: r.score)
    return results


@router.get("/{device_name}", response_model=HardeningDetailResponse)
async def hardening_detail(device_name: str, db: AsyncSession = Depends(get_db)):
    """Full hardening check results for a single device."""
    rules_result = await db.execute(
        select(FirewallRule).where(
            FirewallRule.device_name == device_name,
            FirewallRule.is_enabled == True,
        )
    )
    rules: List[FirewallRule] = list(rules_result.scalars().all())

    if not rules:
        raise HTTPException(status_code=404, detail=f"No enabled rules found for device '{device_name}'")

    topo_result = await db.execute(
        select(NetworkTopology).where(NetworkTopology.device_name == device_name)
    )
    topology = topo_result.scalars().first()

    report = _engine.check_device(device_name, rules, topology)

    return HardeningDetailResponse(
        device_name=report["device_name"],
        score=report["score"],
        grade=report["grade"],
        checks=[HardeningCheckItem(**c) for c in report["checks"]],
    )
