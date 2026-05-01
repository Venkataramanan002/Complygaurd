"""
Device Analysis API — Switch & Router security analysis endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database.connection import get_db
from database.models import NetworkTopology
from utils.switch_analysis_engine import analyze_switch
from utils.router_analysis_engine import analyze_router
from typing import Optional
import logging

router = APIRouter(prefix="/api", tags=["device-analysis"])
logger = logging.getLogger(__name__)


@router.get("/device-analysis/{device_name}")
async def get_device_analysis(device_name: str, db: AsyncSession = Depends(get_db)):
    """
    Analyse a specific switch or router by device name.
    Returns security score, grade, and detailed findings.
    """
    result = await db.execute(
        select(NetworkTopology).where(NetworkTopology.device_name == device_name)
    )
    nodes = result.scalars().all()
    if not nodes:
        raise HTTPException(status_code=404, detail=f"Device '{device_name}' not found")

    # Find the primary node (the one with the richest data)
    primary = nodes[0]
    for n in nodes:
        if n.device_type == "switch" and n.vlans:
            primary = n
            break
        if n.device_type == "router" and n.routing_protocol:
            primary = n
            break

    node_dict = _node_to_dict(primary)

    if primary.device_type == "switch":
        return analyze_switch(node_dict)
    elif primary.device_type == "router":
        return analyze_router(node_dict)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Device '{device_name}' is a {primary.device_type} — only switch and router analysis is supported."
        )


@router.get("/device-analysis")
async def get_all_device_analysis(
    device_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Analyse all switches and routers, or filter by device_type.
    Returns a list of analysis reports.
    """
    stmt = select(NetworkTopology).where(
        NetworkTopology.device_type.in_(["switch", "router"])
    )
    if device_type:
        stmt = select(NetworkTopology).where(NetworkTopology.device_type == device_type)

    result = await db.execute(stmt)
    all_nodes = result.scalars().all()

    # Group by device name → pick the richest node per device
    devices = {}
    for n in all_nodes:
        dn = n.device_name
        if dn not in devices:
            devices[dn] = n
        else:
            # Prefer the node with VLAN or routing data
            if n.device_type == "switch" and n.vlans and not devices[dn].vlans:
                devices[dn] = n
            elif n.device_type == "router" and n.routing_protocol and not devices[dn].routing_protocol:
                devices[dn] = n

    reports = []
    for dn, node in sorted(devices.items()):
        node_dict = _node_to_dict(node)
        if node.device_type == "switch":
            reports.append(analyze_switch(node_dict))
        elif node.device_type == "router":
            reports.append(analyze_router(node_dict))

    return {
        "devices": reports,
        "total": len(reports),
        "switches": sum(1 for r in reports if r["device_type"] == "switch"),
        "routers": sum(1 for r in reports if r["device_type"] == "router"),
    }


def _node_to_dict(node: NetworkTopology) -> dict:
    """Convert a SQLAlchemy model to a plain dict for the analysis engines."""
    return {
        "device_name": node.device_name,
        "device_type": node.device_type,
        "zone": node.zone,
        "ip_address": str(node.ip_address) if node.ip_address else None,
        "vlans": node.vlans,
        "trunk_ports": node.trunk_ports,
        "access_ports": node.access_ports,
        "stp_mode": node.stp_mode,
        "stp_root_for": node.stp_root_for,
        "port_security": node.port_security,
        "acls": node.acls,
        "interfaces": node.interfaces,
        "routing_protocol": node.routing_protocol,
        "ospf_area": node.ospf_area,
        "bgp_asn": node.bgp_asn,
        "bgp_neighbors": node.bgp_neighbors,
        "static_routes": node.static_routes,
        "nat_rules": node.nat_rules,
    }
