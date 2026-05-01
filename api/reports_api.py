"""
Reports API — generate, list, and download firewall analysis reports.
"""

import os
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import (
    FirewallRule,
    RuleRiskAnalysis,
    Connection,
    NetworkTopology,
    Threat,
)
from utils.compliance_engine import ComplianceEngine
from utils.report_generator import ReportGenerator, REPORTS_DIR, VALID_TEMPLATES, VALID_FORMATS

router = APIRouter(prefix="/api/reports", tags=["Reports"])

_generator = ReportGenerator()
_compliance = ComplianceEngine()


# ── Request / response schemas ──────────────────────────────────────────────

class GenerateReportRequest(BaseModel):
    template: str = Field(..., description="One of: executive_summary, compliance_audit, risk_assessment")
    format: str = Field("pdf", description="Output format: pdf, json, or html")
    options: dict = Field(default_factory=dict, description="Optional parameters (reserved for future use)")


# ── Helpers ─────────────────────────────────────────────────────────────────

async def _gather_report_data(db: AsyncSession, template: str) -> dict:
    """Query the database and build the data dict the report generator needs."""

    # Firewall rules
    rules_result = await db.execute(select(FirewallRule))
    rules = rules_result.scalars().all()

    # Risk analyses (eagerly join rule to avoid lazy-load in async)
    risk_result = await db.execute(
        select(RuleRiskAnalysis).options(selectinload(RuleRiskAnalysis.rule)).order_by(desc(RuleRiskAnalysis.risk_score)).limit(50)
    )
    risk_analyses = risk_result.scalars().all()

    # Connections count
    conn_count_result = await db.execute(select(func.count(Connection.id)))
    connections_count = conn_count_result.scalar() or 0

    # Threats
    threats_result = await db.execute(select(Threat).order_by(desc(Threat.timestamp)).limit(100))
    threats = threats_result.scalars().all()

    # Topology
    topo_result = await db.execute(select(NetworkTopology))
    topology = topo_result.scalars().all()

    # Risk summary buckets
    risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for ra in risk_analyses:
        level = (ra.risk_level or "low").lower()
        if level in risk_summary:
            risk_summary[level] += 1

    # Top findings (highest risk first)
    top_findings = [
        {
            "rule_id": ra.rule_id,
            "risk_score": float(ra.risk_score),
            "risk_level": ra.risk_level,
            "risk_category": ra.risk_category,
            "rule_name": ra.rule.rule_name if ra.rule else "Unknown",
            "reason": ra.reason,
            "recommendation": ra.recommendation,
        }
        for ra in risk_analyses[:20]
    ]

    data = {
        "rules_count": len(rules),
        "connections_count": connections_count,
        "threats_count": len(threats),
        "topology_devices": len(topology),
        "risk_summary": risk_summary,
        "top_findings": top_findings,
    }

    # Template-specific enrichments
    if template == "compliance_audit":
        connections_result = await db.execute(select(Connection).limit(500))
        connections = connections_result.scalars().all()
        compliance_results = _compliance.evaluate_all(rules, topology, connections, threats)
        data["compliance_results"] = [
            {
                "framework": cr.framework,
                "overall_score": cr.overall_score,
                "status": cr.status,
                "total_checks": cr.total_checks,
                "passed": cr.passed,
                "failed": cr.failed,
                "warnings": cr.warnings,
                "checks": [
                    {
                        "check_id": ch.check_id,
                        "check_name": ch.check_name,
                        "status": ch.status,
                        "evidence": ch.evidence,
                        "remediation_suggestion": ch.remediation_suggestion,
                    }
                    for ch in cr.checks
                ],
            }
            for cr in compliance_results
        ]

    elif template == "risk_assessment":
        data["risk_breakdown"] = {
            "overly_permissive": sum(1 for ra in risk_analyses if ra.risk_category == "overly_permissive"),
            "insecure_service": sum(1 for ra in risk_analyses if ra.risk_category == "insecure_service"),
            "unused": sum(1 for ra in risk_analyses if ra.risk_category == "unused"),
            "shadowed": sum(1 for ra in risk_analyses if ra.risk_category == "shadowed"),
        }
        data["high_risk_threats"] = [
            {
                "threat_name": t.threat_name,
                "severity": t.severity,
                "src_ip": t.src_ip,
                "dst_ip": t.dst_ip,
                "threat_type": t.threat_type,
            }
            for t in threats
            if (t.severity or "").lower() in ("critical", "high")
        ][:15]

    elif template == "executive_summary":
        allow_count = sum(1 for r in rules if (r.action or "").lower() == "allow")
        deny_count = sum(1 for r in rules if (r.action or "").lower() == "deny")
        data["action_breakdown"] = {"allow": allow_count, "deny": deny_count}
        enabled = sum(1 for r in rules if r.is_enabled)
        disabled = len(rules) - enabled
        data["enabled_vs_disabled"] = {"enabled": enabled, "disabled": disabled}

    return data


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/generate")
async def generate_report(req: GenerateReportRequest, db: AsyncSession = Depends(get_db)):
    """Generate a report from live database data."""
    if req.template not in VALID_TEMPLATES:
        raise HTTPException(status_code=400, detail=f"Invalid template. Choose from: {sorted(VALID_TEMPLATES)}")
    if req.format not in VALID_FORMATS:
        raise HTTPException(status_code=400, detail=f"Invalid format. Choose from: {sorted(VALID_FORMATS)}")

    try:
        data = await _gather_report_data(db, req.template)
        result = _generator.generate_report(req.template, req.format, data)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")

    return {
        "report_id": result["report_id"],
        "format": req.format,
        "file_path": result["file_path"],
        "file_size": result["file_size"],
    }


@router.get("/list")
async def list_reports():
    """Return a list of previously generated reports found on disk."""
    reports_dir = REPORTS_DIR
    if not reports_dir.exists():
        return {"reports": []}

    reports = []
    for entry in sorted(reports_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if entry.is_file():
            stat = entry.stat()
            # Derive report_id from filename pattern: template_timestamp_shortid.ext
            parts = entry.stem.rsplit("_", 1)
            short_id = parts[-1] if len(parts) > 1 else entry.stem
            reports.append({
                "filename": entry.name,
                "report_id": short_id,
                "file_size": stat.st_size,
                "created_at": stat.st_mtime,
                "format": entry.suffix.lstrip("."),
            })

    return {"reports": reports}


@router.get("/download/{report_id}")
async def download_report(report_id: str):
    """Download a report file by its short report_id (first 8 chars of UUID)."""
    reports_dir = REPORTS_DIR
    if not reports_dir.exists():
        raise HTTPException(status_code=404, detail="No reports directory found")

    # Search for a file whose name contains the report_id fragment
    for entry in reports_dir.iterdir():
        if entry.is_file() and report_id in entry.name:
            # Path traversal protection
            real_path = os.path.realpath(entry)
            base_path = os.path.realpath(reports_dir)
            if not real_path.startswith(base_path):
                raise HTTPException(status_code=403, detail="Access denied")

            media_types = {
                ".pdf": "application/pdf",
                ".json": "application/json",
                ".html": "text/html",
            }
            media_type = media_types.get(entry.suffix, "application/octet-stream")
            return FileResponse(real_path, media_type=media_type, filename=entry.name)

    raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")
