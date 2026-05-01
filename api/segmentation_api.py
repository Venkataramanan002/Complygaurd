"""Zone Trust Matrix & Segmentation API."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import FirewallRule, Connection, NetworkTopology
from utils.segmentation_engine import build_zone_trust_matrix, recommend_microsegmentation

router = APIRouter(prefix="/api/zones", tags=["Segmentation"])


@router.get("/trust-matrix")
async def zone_trust_matrix(db: AsyncSession = Depends(get_db)):
    rules = list((await db.execute(select(FirewallRule))).scalars().all())
    conns = list((await db.execute(select(Connection).limit(5000))).scalars().all())
    return build_zone_trust_matrix(rules, conns)


@router.get("/segmentation-recommendations")
async def segmentation_recommendations(db: AsyncSession = Depends(get_db)):
    rules = list((await db.execute(select(FirewallRule))).scalars().all())
    conns = list((await db.execute(select(Connection).limit(5000))).scalars().all())
    topo = list((await db.execute(select(NetworkTopology))).scalars().all())
    recs = recommend_microsegmentation(rules, conns, topo)
    return {"recommendations": recs}
