"""
Threat Intelligence API — IP reputation checking, bulk enrichment, IOC summary.

HARDENED: IP format validation, bounded list inputs, error handling.
"""

import ipaddress
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from typing import List
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import Connection
from services.threat_intel import get_threat_intel_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])


def _validate_ip(v: str) -> str:
    v = v.strip()
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(f"Invalid IP address: {v}")
    return v


class BulkCheckRequest(BaseModel):
    ips: List[str] = Field(..., max_length=100, description="Max 100 IPs per request")

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v: List[str]) -> List[str]:
        if len(v) > 100:
            raise ValueError("Maximum 100 IPs per bulk check request")
        return [_validate_ip(ip) for ip in v]


@router.get("/check/{ip}")
async def check_ip(ip: str):
    """Check a single IP across all enabled threat intelligence feeds."""
    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")
    service = get_threat_intel_service()
    try:
        return await service.check_ip(ip.strip())
    except Exception as e:
        logger.error("Threat intel check failed for %s: %s", ip, e)
        raise HTTPException(status_code=502, detail="Threat intelligence service unavailable")


@router.post("/bulk-check")
async def bulk_check(req: BulkCheckRequest):
    """Check multiple IPs across all feeds (max 100 per request)."""
    service = get_threat_intel_service()
    try:
        results = await service.bulk_check(req.ips)
        return {"results": results, "checked_count": len(results)}
    except Exception as e:
        logger.error("Bulk threat intel check failed: %s", e)
        raise HTTPException(status_code=502, detail="Threat intelligence service unavailable")


@router.get("/enrich-connections")
async def enrich_connections(db: AsyncSession = Depends(get_db)):
    """Scan unique source IPs from connections table against threat feeds."""
    stmt = select(Connection.src_ip).distinct().limit(50)
    result = await db.execute(stmt)
    ips = [row[0] for row in result.all() if row[0]]

    service = get_threat_intel_service()
    try:
        results = await service.bulk_check(ips)
    except Exception as e:
        logger.error("Connection enrichment failed: %s", e)
        raise HTTPException(status_code=502, detail="Threat intelligence service unavailable")

    malicious = [r for r in results if r.get("is_malicious")]
    return {
        "total_ips_checked": len(results),
        "malicious_count": len(malicious),
        "results": results,
    }


@router.get("/ioc-summary")
async def ioc_summary():
    """Top malicious IPs from cached threat intel data."""
    service = get_threat_intel_service()
    try:
        summary = await service.get_ioc_summary()
        return {"iocs": summary, "total": len(summary)}
    except Exception as e:
        logger.error("IOC summary failed: %s", e)
        raise HTTPException(status_code=502, detail="Threat intelligence service unavailable")
