"""
Service layer for config upload and background processing.

Extracted from the monolithic backend_topology.py — contains all business
logic for parsing configs, running risk analysis, and building attack paths.
"""

from __future__ import annotations

import datetime
import logging
import uuid
from typing import Any, Dict, List

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import AsyncSessionLocal
from database.models import (
    AttackPath,
    CertificationReview,
    ConfigUpload,
    Connection,
    FirewallRule,
    NetworkTopology,
    RuleOwner,
    RuleRiskAnalysis,
    Threat,
)
from parsers.config_parsers import CiscoASAParser, FortinetParser, PaloAltoXMLParser
from utils.risk_engine import calculate_rule_risk

logger = logging.getLogger(__name__)

PARSERS = {
    "paloalto": PaloAltoXMLParser(),
    "cisco": CiscoASAParser(),
    "fortinet": FortinetParser(),
}

VULNERABLE_PORTS: Dict[int, Dict[str, str]] = {
    21: {"service": "FTP", "risk": "high", "reason": "Unencrypted credentials"},
    22: {"service": "SSH", "risk": "low", "reason": "Secure but verify key auth"},
    23: {"service": "Telnet", "risk": "critical", "reason": "Unencrypted remote access"},
    25: {"service": "SMTP", "risk": "medium", "reason": "Mail relay abuse"},
    80: {"service": "HTTP", "risk": "medium", "reason": "Unencrypted web traffic"},
    135: {"service": "RPC", "risk": "medium", "reason": "Windows remote exploits"},
    139: {"service": "NetBIOS", "risk": "medium", "reason": "Information disclosure"},
    443: {"service": "HTTPS", "risk": "low", "reason": "Monitor for SSL inspection bypass"},
    445: {"service": "SMB", "risk": "high", "reason": "Ransomware vector (WannaCry, NotPetya)"},
    1433: {"service": "MS-SQL", "risk": "high", "reason": "Database exposure"},
    3306: {"service": "MySQL", "risk": "high", "reason": "Database exposure"},
    3389: {"service": "RDP", "risk": "high", "reason": "Brute force target, ransomware entry"},
    5432: {"service": "PostgreSQL", "risk": "high", "reason": "Database exposure"},
    8080: {"service": "HTTP-Alt", "risk": "medium", "reason": "Unencrypted web traffic"},
}


async def wipe_config_data(db: AsyncSession) -> None:
    """Delete prior config-projected data.  Scoped to config_projection source."""
    await db.execute(delete(CertificationReview).where(
        CertificationReview.rule_id.in_(
            select(FirewallRule.id)
        )
    ))
    await db.execute(delete(RuleOwner).where(
        RuleOwner.rule_id.in_(
            select(FirewallRule.id)
        )
    ))
    await db.execute(delete(RuleRiskAnalysis))
    await db.execute(delete(AttackPath))
    await db.execute(delete(FirewallRule))
    await db.execute(delete(NetworkTopology))
    await db.execute(delete(Connection).where(Connection.source == "config_projection"))
    await db.execute(delete(Threat).where(Threat.source == "config_projection"))
    await db.execute(delete(ConfigUpload))
    await db.commit()


async def process_config_background(upload_id: str, content: str = "") -> None:
    """Parse a firewall config end-to-end (rules → topology → risk → attack paths)."""
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(
                select(ConfigUpload).where(ConfigUpload.id == upload_id)
            )
            upload = result.scalars().first()
            if not upload:
                logger.error("Upload %s not found", upload_id)
                return

            upload.ingestion_status = "processing"
            upload.progress_percent = 5
            await db.commit()

            parser = PARSERS.get(upload.vendor)
            if not parser:
                raise ValueError(f"No parser for vendor: {upload.vendor}")

            device_name = f"{upload.vendor}-fw-01"

            # Step 1 — Parse rules
            rules_data = parser.parse_rules(content)
            rules_objs: List[FirewallRule] = []
            for r in rules_data:
                rules_objs.append(FirewallRule(
                    device_name=device_name,
                    rule_name=r.get("rule_name"),
                    rule_position=r.get("rule_position"),
                    source_ip=r.get("source_ip", "any"),
                    source_port=r.get("source_port", "any"),
                    dest_ip=r.get("dest_ip", "any"),
                    dest_port=r.get("dest_port", "any"),
                    protocol=r.get("protocol", "any"),
                    action=r.get("action", "deny"),
                    service_name=r.get("service_name"),
                    is_enabled=r.get("is_enabled", True),
                ))
            db.add_all(rules_objs)
            upload.progress_percent = 20
            upload.configs_processed = len(rules_objs)
            await db.commit()

            # Step 2 — Parse topology
            topology_data = parser.parse_topology(content)
            topo_objs: List[NetworkTopology] = []
            for t in topology_data:
                topo_objs.append(NetworkTopology(
                    device_name=device_name,
                    device_type=t.get("device_type", "firewall"),
                    zone=t.get("zone"),
                    ip_address=t.get("ip_address"),
                    ports_open=t.get("ports_open", []),
                    connected_to=[],
                    is_entry_point=t.get("is_entry_point", False),
                ))
            db.add_all(topo_objs)
            upload.progress_percent = 35
            await db.commit()

            # Step 3 — Risk analysis
            all_rules = (await db.execute(select(FirewallRule))).scalars().all()
            for rule in all_rules:
                analysis = calculate_rule_risk(rule, all_rules, VULNERABLE_PORTS)
                db.add(RuleRiskAnalysis(
                    rule_id=rule.id,
                    risk_score=analysis["risk_score"],
                    risk_level=analysis["risk_level"],
                    risk_category=analysis["risk_category"],
                    reason=analysis["reason"],
                    cvss_color=analysis["cvss_color"],
                    recommendation=analysis["recommendation"],
                    calculated_at=datetime.datetime.utcnow(),
                ))
            upload.progress_percent = 55
            await db.commit()

            # Step 4 — Synthetic connections & threats
            synthetic = parser.derive_synthetic_data(rules_data, topology_data, device_name)
            for sc in synthetic.get("connections", []):
                ts = sc["timestamp"]
                db.add(Connection(
                    timestamp=datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S") if isinstance(ts, str) else ts,
                    src_ip=sc["src_ip"], dst_ip=sc["dst_ip"],
                    src_port=sc["src_port"], dst_port=sc["dst_port"],
                    protocol=sc["protocol"], action=sc["action"],
                    rule_id=sc.get("rule_id"),
                    bytes_sent=sc.get("bytes_sent"), bytes_received=sc.get("bytes_received"),
                    packets_sent=sc.get("packets_sent"), packets_received=sc.get("packets_received"),
                    app_name=sc.get("app_name"), app_category=sc.get("app_category"),
                    domain=sc.get("domain"), device_name=sc.get("device_name"),
                    zone_from=sc.get("zone_from"), zone_to=sc.get("zone_to"),
                    geo_src_country=sc.get("geo_src_country"), geo_dst_country=sc.get("geo_dst_country"),
                    session_end=datetime.datetime.strptime(sc["session_end"], "%Y-%m-%d %H:%M:%S") if isinstance(sc.get("session_end"), str) else sc.get("session_end"),
                    duration_seconds=sc.get("duration_seconds"),
                    interface_in=sc.get("interface_in"), interface_out=sc.get("interface_out"),
                    threat_detected=sc.get("threat_detected", False),
                    source="config_projection",
                ))
            for st in synthetic.get("threats", []):
                ts = st["timestamp"]
                db.add(Threat(
                    timestamp=datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S") if isinstance(ts, str) else ts,
                    device_name=st.get("device_name"),
                    src_ip=st["src_ip"], dst_ip=st["dst_ip"],
                    threat_type=st.get("threat_type"), threat_name=st.get("threat_name"),
                    severity=st.get("severity"), risk_score=st.get("risk_score"),
                    source="config_projection",
                ))
            upload.progress_percent = 75
            await db.commit()

            # Step 5 — Attack paths via zone-graph DFS
            _build_attack_paths(db, upload, topo_objs, all_rules,
                                {str(r.rule_id): float(r.risk_score)
                                 for r in (await db.execute(select(RuleRiskAnalysis))).scalars().all()})
            # (deferred commit inside _build_attack_paths)

            upload.progress_percent = 100
            upload.ingestion_status = "completed"
            upload.completed_at = datetime.datetime.utcnow()
            await db.commit()
            logger.info(
                "Config %s processed: %d rules, %d zones",
                upload_id, len(rules_objs), len(topo_objs),
            )

        except Exception as e:
            logger.error("Config processing failed %s: %s", upload_id, e, exc_info=True)
            try:
                result = await db.execute(
                    select(ConfigUpload).where(ConfigUpload.id == upload_id)
                )
                upload = result.scalars().first()
                if upload:
                    upload.ingestion_status = "failed"
                    upload.error_messages = [str(e)]
                    await db.commit()
            except Exception:
                pass


def _build_attack_paths(
    db: AsyncSession,
    upload: ConfigUpload,
    topo_nodes: list,
    rules: list,
    risk_map: dict,
) -> None:
    """Build zone-adjacency graph and run DFS to discover attack paths."""
    zone_names = list({n.zone for n in topo_nodes if n.zone})
    entry_zones = {n.zone for n in topo_nodes if n.is_entry_point}
    if not entry_zones:
        entry_zones = {zone_names[0]} if zone_names else {"internet_edge"}

    graph: Dict[str, List[Dict]] = {}
    for rule in rules:
        if rule.action.lower() != "allow":
            continue
        src = rule.source_ip if rule.source_ip != "any" else None
        dst = rule.dest_ip if rule.dest_ip != "any" else None

        src_zones = (
            [z for z in zone_names if src and z.lower() in src.lower()]
            or ([src] if src else list(entry_zones))
        )
        dst_zones = (
            [z for z in zone_names if dst and z.lower() in dst.lower()]
            or ([dst] if dst else zone_names)
        )

        rule_risk = risk_map.get(str(rule.id), 1.0)
        for sz in src_zones:
            graph.setdefault(sz, [])
            for dz in dst_zones:
                if sz != dz:
                    graph[sz].append({
                        "target": dz,
                        "rule_name": rule.rule_name,
                        "port": rule.dest_port,
                        "risk": rule_risk,
                    })

    target_keywords = ["database", "db", "core", "app_server", "application"]
    target_zones = {z for z in zone_names if any(k in z.lower() for k in target_keywords)}
    if not target_zones:
        target_zones = {zone_names[-1]} if zone_names else {"database_servers"}

    found_paths: List[list] = []

    def _dfs(current: str, hops: list, visited: set, depth: int = 0):
        if depth > 8:
            return
        if current in target_zones and hops:
            found_paths.append(list(hops))
            return
        if current in visited:
            return
        visited = visited | {current}
        for edge in graph.get(current, []):
            _dfs(edge["target"], hops + [{**edge, "from": current}], visited, depth + 1)

    for entry in entry_zones:
        _dfs(entry, [], set())

    for path_hops in found_paths:
        total_risk = min(sum(h["risk"] for h in path_hops), 10.0)
        level = (
            "critical" if total_risk >= 8
            else "high" if total_risk >= 6
            else "medium" if total_risk >= 3
            else "low"
        )
        nodes = [path_hops[0].get("from", list(entry_zones)[0])] + [
            h["target"] for h in path_hops
        ]
        db.add(AttackPath(
            id=str(uuid.uuid4()),
            entry_point=nodes[0],
            target=nodes[-1],
            path_hops=path_hops,
            total_risk_score=total_risk,
            risk_level=level,
            attack_difficulty=max(0.0, 10.0 - total_risk),
            vulnerable_ports_in_path=[h["port"] for h in path_hops if h["risk"] > 5],
            weakest_link=max(path_hops, key=lambda h: h["risk"])["rule_name"] if path_hops else "",
            calculated_at=datetime.datetime.utcnow(),
        ))


async def run_risk_analysis_task() -> None:
    """Re-run risk analysis on all rules (background task)."""
    async with AsyncSessionLocal() as db:
        try:
            all_rules = (await db.execute(select(FirewallRule))).scalars().all()
            if not all_rules:
                return
            await db.execute(delete(RuleRiskAnalysis))
            await db.commit()
            for rule in all_rules:
                analysis = calculate_rule_risk(rule, all_rules, VULNERABLE_PORTS)
                db.add(RuleRiskAnalysis(
                    rule_id=rule.id,
                    risk_score=analysis["risk_score"],
                    risk_level=analysis["risk_level"],
                    risk_category=analysis["risk_category"],
                    reason=analysis["reason"],
                    cvss_color=analysis["cvss_color"],
                    recommendation=analysis["recommendation"],
                    calculated_at=datetime.datetime.utcnow(),
                ))
            await db.commit()
            logger.info("Re-analysed %d rules", len(all_rules))
        except Exception as e:
            logger.error("Risk analysis error: %s", e)
            await db.rollback()
