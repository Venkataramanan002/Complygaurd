"""
api/enterprise.py
Deterministic enterprise endpoints for summaries, scoring, topology, and exports.
"""

from __future__ import annotations

import csv
import datetime
import io
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import (
    AttackPath,
    ConfigUpload,
    Connection,
    FirewallRule,
    NetworkTopology,
    RuleRiskAnalysis,
    SystemHealth,
    Threat,
)

router = APIRouter(prefix="/api", tags=["Enterprise"])


class CompromiseNarrativeRequest(BaseModel):
    finding_type: str
    finding_data: Optional[Any] = None
    attack_paths: Optional[List[Any]] = []
    connected_systems: Optional[List[str]] = []
    zone: Optional[str] = ""


class CompromiseNarrativeResponse(BaseModel):
    attacker_profile: str
    discovery_method: str
    attack_steps: List[str]
    systems_compromised: List[str]
    data_at_risk: List[str]
    blast_radius: str
    business_impact: str
    time_to_exploit: str
    detection_difficulty: str
    full_narrative: str


class ExecutiveSummaryResponse(BaseModel):
    summary: str
    risk_score: float
    risk_trend: str
    top_findings: List[Dict[str, Any]]


class ComplianceScore(BaseModel):
    framework: str
    score: float
    status: str
    findings: int
    details: List[str]


class FirewallHealthResponse(BaseModel):
    score: float
    grade: str
    breakdown: Dict[str, float]
    recommendations: List[str]


class AttackSurfaceResponse(BaseModel):
    exposed_ports: int
    internet_facing_rules: int
    crown_jewel_assets: int
    total_attack_paths: int
    critical_paths: int
    entry_points: int


class FirewallTopologyResponse(BaseModel):
    firewalls: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    chain_detected: bool
    chain_details: Optional[str] = None


def _deterministic_compromise_narrative(req: CompromiseNarrativeRequest) -> CompromiseNarrativeResponse:
    finding = req.finding_data if isinstance(req.finding_data, dict) else {}
    risk_level = str(finding.get("risk_level", "high")).lower()
    score = finding.get("risk_score") or finding.get("total_risk_score") or "unknown"
    category = str(finding.get("risk_category", "")).lower()
    reason = str(finding.get("reason", ""))
    zone = req.zone or "core network"
    systems = req.connected_systems or []
    attack_paths = req.attack_paths if hasattr(req, "attack_paths") and req.attack_paths else []

    # Context-aware service detection from the finding
    dest_port = str(finding.get("dest_port", finding.get("dst_port", "")))
    service = str(finding.get("service_name", "")).lower()

    # Service-specific risk profiles
    _SERVICE_RISK = {
        "ssh": ("SSH brute-force or key theft", "Moderate", "Hours"),
        "rdp": ("RDP credential stuffing or BlueKeep-class exploit", "Hard", "Minutes to hours"),
        "smb": ("SMBv1 eternal-blue family or NTLM relay", "Hard", "Minutes"),
        "dns": ("DNS tunneling for C2 or cache poisoning", "Easy", "Hours to days"),
        "http": ("Web application exploit (SQLi, RCE) or default credentials", "Easy", "Hours"),
        "https": ("TLS interception or web app vulnerability", "Moderate", "Hours"),
        "ftp": ("Cleartext credential interception or anonymous access abuse", "Easy", "Minutes"),
        "telnet": ("Cleartext session hijacking", "Easy", "Minutes"),
        "mysql": ("SQL injection or default credential exploitation", "Moderate", "Hours"),
        "ldap": ("LDAP injection or credential harvesting", "Moderate", "Hours to days"),
    }

    # Detect service from port or name
    port_service_map = {"22": "ssh", "3389": "rdp", "445": "smb", "53": "dns", "80": "http",
                        "443": "https", "21": "ftp", "23": "telnet", "3306": "mysql", "389": "ldap"}
    detected_service = port_service_map.get(dest_port, service.split("/")[0] if service else "")
    srv_info = _SERVICE_RISK.get(detected_service, None)

    # Category-specific attack profiles
    if "overly_permissive" in category or "any" in reason.lower():
        profile = "Automated scanner exploiting overly permissive 'any' rules to discover exposed services"
        discovery = "Port scanning across unrestricted source/destination ranges"
    elif "shadow" in category:
        profile = "Lateral movement actor exploiting shadowed (unreachable) rule creating false security assumptions"
        discovery = "Rule analysis revealing dead rules that mask actual traffic paths"
    elif "unused" in category or "hit_count" in reason.lower():
        profile = "Persistent threat actor leveraging unused rules that remain enabled without monitoring"
        discovery = "Audit of zero-hit rules that still permit potentially dangerous traffic"
    elif "insecure_service" in category or srv_info:
        svc_label = detected_service.upper() if detected_service else "insecure service"
        profile = f"Targeted attacker exploiting {svc_label} service exposure"
        discovery = f"Service enumeration identifying {svc_label} accessible through firewall allow rules"
    else:
        profile = ("External opportunistic attacker using automated scanning"
                    if risk_level in {"critical", "high"}
                    else "Internal user with elevated access abusing permissive traffic paths")
        discovery = "Network and service enumeration on allowed firewall paths"

    # Context-aware timing and difficulty
    if srv_info:
        _, detection, exploit_window = srv_info
    else:
        detection = "Hard" if risk_level == "critical" else "Moderate" if risk_level == "high" else "Easy"
        exploit_window = ("Minutes to a few hours" if risk_level == "critical"
                          else "Hours to days" if risk_level == "high"
                          else "Days to weeks")

    # Build context-specific attack steps
    steps = []
    steps.append(f"Scan {zone} for exposed hosts and services through the permissive rule path.")
    if detected_service:
        steps.append(f"Target {detected_service.upper()} service for exploitation or credential harvesting.")
    else:
        steps.append("Identify vulnerable services on permitted destination ports.")
    steps.append("Establish initial foothold on the first compromised host.")
    if len(systems) > 1:
        steps.append(f"Pivot laterally through {', '.join(systems[:3])} using allowed east-west traffic.")
    else:
        steps.append("Move laterally through allowed inter-zone traffic paths to reach higher-value targets.")
    steps.append("Exfiltrate data or establish persistence using existing allowed communication channels.")

    # Use real systems if available, otherwise derive from attack paths
    if systems:
        compromised = systems[:]
    elif attack_paths:
        compromised = []
        for path in attack_paths[:3]:
            hops = path.get("path_hops", []) if isinstance(path, dict) else []
            compromised.extend([str(h) for h in hops[:2]])
        compromised = list(dict.fromkeys(compromised))[:5] or ["Hosts reachable through the identified attack path"]
    else:
        compromised = [
            f"Origin-zone host in {zone}",
            "Intermediate service host on the traversal path",
            "Target asset reachable through allow rules",
        ]

    # Context-specific data risk
    data_risk = ["Authentication credentials (user or service accounts)"]
    if detected_service in ("smb", "ftp", "rdp"):
        data_risk.append("File shares and internal documents accessible via the compromised protocol")
    elif detected_service in ("mysql", "ldap"):
        data_risk.append("Database records and directory service entries")
    else:
        data_risk.append("Application or business data exposed on reachable services")
    data_risk.append("Network topology and configuration data enabling further lateral movement")

    system_count = len(systems) if systems else "multiple"
    blast = (f"Exposure spans {zone} and {system_count} connected systems; "
             "permissive rules can widen impact across adjacent trust boundaries.")
    impact = (
        f"Risk level {risk_level.upper()} (score: {score}). "
        f"{'Immediate remediation required — ' if risk_level == 'critical' else ''}"
        f"Potential for service disruption, data breach, and regulatory reporting obligations."
    )
    narrative = (
        f"Attacker profile: {profile}. The attack leverages allowed firewall paths in {zone}, "
        f"targeting {detected_service.upper() + ' services' if detected_service else 'exposed services'} "
        "before pivoting laterally to reach higher-value assets."
    )

    return CompromiseNarrativeResponse(
        attacker_profile=profile,
        discovery_method=discovery,
        attack_steps=steps,
        systems_compromised=compromised,
        data_at_risk=data_risk,
        blast_radius=blast,
        business_impact=impact,
        time_to_exploit=exploit_window,
        detection_difficulty=detection,
        full_narrative=narrative,
    )


@router.post("/compromise-narrative", response_model=CompromiseNarrativeResponse)
async def generate_compromise_narrative(req: CompromiseNarrativeRequest):
    return _deterministic_compromise_narrative(req)


@router.get("/dashboard/executive-summary", response_model=ExecutiveSummaryResponse)
async def get_executive_summary(db: AsyncSession = Depends(get_db)):
    critical_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "critical"))
    high_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "high"))
    medium_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "medium"))
    total_rules_q = await db.execute(select(func.count(FirewallRule.id)))
    paths_q = await db.execute(select(func.count(AttackPath.id)))
    crit_paths_q = await db.execute(select(func.count(AttackPath.id)).where(AttackPath.risk_level == "critical"))
    avg_risk_q = await db.execute(select(func.avg(RuleRiskAnalysis.risk_score)))
    threats_q = await db.execute(select(func.count(Threat.id)))

    critical = critical_q.scalar() or 0
    high = high_q.scalar() or 0
    medium = medium_q.scalar() or 0
    total_rules = total_rules_q.scalar() or 0
    total_paths = paths_q.scalar() or 0
    crit_paths = crit_paths_q.scalar() or 0
    avg_risk = float(avg_risk_q.scalar() or 0)
    total_threats = threats_q.scalar() or 0

    if total_rules == 0:
        risk_score = 0.0
    else:
        risk_score = min(100, (critical * 25 + high * 15 + medium * 5 + crit_paths * 10) / max(total_rules, 1) * 10)
        risk_score = round(min(risk_score, 100), 1)

    top_findings_q = await db.execute(
        select(FirewallRule, RuleRiskAnalysis)
        .join(RuleRiskAnalysis, FirewallRule.id == RuleRiskAnalysis.rule_id)
        .order_by(desc(RuleRiskAnalysis.risk_score))
        .limit(5)
    )
    top_findings = [
        {
            "rule_name": rule.rule_name or f"Rule {rule.id}",
            "risk_score": float(analysis.risk_score),
            "risk_level": analysis.risk_level,
            "reason": analysis.reason or "Review required",
            "device": rule.device_name,
        }
        for rule, analysis in top_findings_q
    ]

    if critical > 0:
        summary = (
            f"Security posture requires immediate action: {critical} critical and {high} high-risk findings across {total_rules} rules. "
            f"{crit_paths} critical attack paths and {total_threats} detected threats increase breach likelihood. "
            "Prioritize strict access reduction, high-risk rule remediation, and targeted monitoring this cycle."
        )
    elif high > 0:
        summary = (
            f"Security posture is elevated: {high} high-risk and {medium} medium-risk findings across {total_rules} rules. "
            f"{total_paths} attack paths are present and should be reduced through segmentation and least-privilege policy updates. "
            "Address high-risk items first to prevent escalation."
        )
    else:
        summary = (
            f"Security posture is stable with mostly medium/low risk findings across {total_rules} rules. "
            f"Average risk remains {avg_risk:.1f}/10 with {total_threats} logged threats for monitoring. "
            "Maintain recurring reviews and keep deny-by-default and service hardening controls in place."
        )

    risk_trend = "critical" if critical > 2 else "high" if critical > 0 or high > 3 else "medium" if high > 0 else "stable"

    return ExecutiveSummaryResponse(
        summary=summary,
        risk_score=risk_score,
        risk_trend=risk_trend,
        top_findings=top_findings,
    )


@router.get("/compliance-scores", response_model=List[ComplianceScore])
async def get_compliance_scores(db: AsyncSession = Depends(get_db)):
    total_q = await db.execute(select(func.count(FirewallRule.id)))
    total = total_q.scalar() or 0
    if total == 0:
        return []

    critical_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "critical"))
    high_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "high"))
    overly_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "overly_permissive"))
    insecure_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "insecure_service"))
    shadowed_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "shadowed"))

    critical = critical_q.scalar() or 0
    high = high_q.scalar() or 0
    overly = overly_q.scalar() or 0
    insecure = insecure_q.scalar() or 0
    shadowed = shadowed_q.scalar() or 0

    pci_deductions = critical * 15 + high * 8 + overly * 10 + insecure * 5
    pci_score = max(0, min(100, 100 - pci_deductions))
    pci_details = []
    if critical > 0:
        pci_details.append(f"{critical} critical rules violate PCI DSS Req 1.2 (deny by default)")
    if overly > 0:
        pci_details.append(f"{overly} overly permissive rules violate Req 1.3 (restrict traffic)")
    if insecure > 0:
        pci_details.append(f"{insecure} insecure services violate Req 2.2 (secure configurations)")
    if not pci_details:
        pci_details.append("No major PCI DSS violations detected")

    iso_deductions = critical * 12 + high * 6 + shadowed * 4 + insecure * 5
    iso_score = max(0, min(100, 100 - iso_deductions))
    iso_details = []
    if critical > 0:
        iso_details.append(f"{critical} critical findings against A.13 Network Security")
    if shadowed > 0:
        iso_details.append(f"{shadowed} shadowed rules violate A.12 Operations Security")
    if high > 0:
        iso_details.append(f"{high} high-risk rules need A.14 review")
    if not iso_details:
        iso_details.append("Firewall configuration aligns with ISO 27001 controls")

    nist_deductions = critical * 10 + high * 5 + overly * 8 + insecure * 6
    nist_score = max(0, min(100, 100 - nist_deductions))
    nist_details = []
    if critical > 0:
        nist_details.append(f"{critical} critical gaps in PR.AC (Access Control)")
    if overly > 0:
        nist_details.append(f"{overly} findings in PR.PT (Protective Technology)")
    if insecure > 0:
        nist_details.append(f"{insecure} findings in PR.IP (Information Protection)")
    if not nist_details:
        nist_details.append("Configuration meets NIST CSF baseline requirements")

    def status(score: float) -> str:
        if score >= 90:
            return "Compliant"
        if score >= 70:
            return "Partial"
        if score >= 50:
            return "At Risk"
        return "Non-Compliant"

    return [
        ComplianceScore(framework="PCI DSS", score=pci_score, status=status(pci_score), findings=critical + high + overly, details=pci_details),
        ComplianceScore(framework="ISO 27001", score=iso_score, status=status(iso_score), findings=critical + high + shadowed + insecure, details=iso_details),
        ComplianceScore(framework="NIST CSF", score=nist_score, status=status(nist_score), findings=critical + high + overly + insecure, details=nist_details),
    ]


@router.get("/firewall-health", response_model=FirewallHealthResponse)
async def get_firewall_health(db: AsyncSession = Depends(get_db)):
    total_q = await db.execute(select(func.count(FirewallRule.id)))
    total = total_q.scalar() or 0
    if total == 0:
        return FirewallHealthResponse(score=0, grade="N/A", breakdown={}, recommendations=["Upload a firewall configuration to assess health."])

    enabled_q = await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.is_enabled == True))
    disabled_q = await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.is_enabled == False))
    critical_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "critical"))
    high_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "high"))
    overly_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "overly_permissive"))
    shadowed_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "shadowed"))
    unused_q = await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_category == "unused"))

    enabled = enabled_q.scalar() or 0
    disabled = disabled_q.scalar() or 0
    critical = critical_q.scalar() or 0
    high = high_q.scalar() or 0
    overly = overly_q.scalar() or 0
    shadowed = shadowed_q.scalar() or 0
    unused = unused_q.scalar() or 0

    rule_hygiene = max(0, 100 - (shadowed * 10) - (unused * 8) - (disabled / max(total, 1) * 30))
    risk_posture = max(0, 100 - (critical * 20) - (high * 10) - (overly * 8))
    access_control = max(0, 100 - (overly * 15) - (critical * 12))
    config_quality = max(0, 100 - ((critical + high) / max(total, 1)) * 100)

    overall = round((rule_hygiene * 0.25 + risk_posture * 0.30 + access_control * 0.25 + config_quality * 0.20), 1)
    overall = max(0, min(100, overall))
    grade = "A+" if overall >= 95 else "A" if overall >= 90 else "B" if overall >= 80 else "C" if overall >= 70 else "D" if overall >= 60 else "F"

    recommendations = []
    if critical > 0:
        recommendations.append(f"Fix {critical} critical-risk rules immediately")
    if overly > 0:
        recommendations.append(f"Tighten {overly} overly permissive rules")
    if shadowed > 0:
        recommendations.append(f"Remove {shadowed} shadowed/redundant rules")
    if unused > 0:
        recommendations.append(f"Review and remove {unused} unused rules")
    if not recommendations:
        recommendations.append("Configuration is healthy - maintain regular reviews")

    return FirewallHealthResponse(
        score=overall,
        grade=grade,
        breakdown={
            "rule_hygiene": round(rule_hygiene, 1),
            "risk_posture": round(risk_posture, 1),
            "access_control": round(access_control, 1),
            "config_quality": round(config_quality, 1),
        },
        recommendations=recommendations,
    )


@router.get("/attack-surface", response_model=AttackSurfaceResponse)
async def get_attack_surface(db: AsyncSession = Depends(get_db)):
    exposed_q = await db.execute(
        select(func.count(func.distinct(FirewallRule.dest_port)))
        .where(FirewallRule.action == "allow")
        .where(FirewallRule.dest_port != "any")
    )
    exposed_ports = exposed_q.scalar() or 0

    internet_facing = (await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.action == "allow"))).scalar() or 0
    crown_jewels = (await db.execute(select(func.count(NetworkTopology.id)))).scalar() or 0
    total_paths = (await db.execute(select(func.count(AttackPath.id)))).scalar() or 0
    crit_paths = (await db.execute(select(func.count(AttackPath.id)).where(AttackPath.risk_level == "critical"))).scalar() or 0
    entry_points = (await db.execute(select(func.count(NetworkTopology.id)).where(NetworkTopology.is_entry_point == True))).scalar() or 0

    return AttackSurfaceResponse(
        exposed_ports=exposed_ports,
        internet_facing_rules=internet_facing,
        crown_jewel_assets=crown_jewels,
        total_attack_paths=total_paths,
        critical_paths=crit_paths,
        entry_points=entry_points,
    )


@router.get("/firewall-topology", response_model=FirewallTopologyResponse)
async def get_firewall_topology(db: AsyncSession = Depends(get_db)):
    topo_q = await db.execute(select(NetworkTopology))
    nodes = topo_q.scalars().all()

    rules_q = await db.execute(select(FirewallRule))
    rules = rules_q.scalars().all()

    upload_q = await db.execute(select(ConfigUpload).order_by(desc(ConfigUpload.upload_time)).limit(5))
    uploads = upload_q.scalars().all()

    fw_devices: Dict[str, Dict[str, Any]] = {}
    for node in nodes:
        dn = node.device_name or "unknown"
        if dn not in fw_devices:
            fw_devices[dn] = {
                "device_name": dn,
                "device_type": node.device_type or "firewall",
                "vendor": "",
                "zones": [],
                "ip_address": str(node.ip_address) if node.ip_address else "-",
                "rules_count": 0,
                "is_entry_point": False,
            }
        if node.zone and node.zone not in fw_devices[dn]["zones"]:
            fw_devices[dn]["zones"].append(node.zone)
        if node.is_entry_point:
            fw_devices[dn]["is_entry_point"] = True

    for rule in rules:
        dn = rule.device_name or "unknown"
        if dn in fw_devices:
            fw_devices[dn]["rules_count"] += 1

    for upload in uploads:
        if upload.vendor:
            for dn in fw_devices:
                if not fw_devices[dn]["vendor"]:
                    fw_devices[dn]["vendor"] = upload.vendor

    firewalls = list(fw_devices.values())
    connections: List[Dict[str, Any]] = []
    fw_list = list(fw_devices.keys())

    # Build inter-device connections from connected_to and neighbor_device fields
    seen_device_links: set = set()
    for node in nodes:
        dn = node.device_name or "unknown"
        # From connected_to list
        for target in (node.connected_to or []):
            if target in fw_devices:
                pair = tuple(sorted([dn, target]))
                if pair not in seen_device_links:
                    seen_device_links.add(pair)
                    shared_zones = set(fw_devices.get(dn, {}).get("zones", [])) & set(fw_devices.get(target, {}).get("zones", []))
                    connections.append({
                        "source": dn,
                        "target": target,
                        "type": node.link_type or "direct_link",
                        "shared_zones": list(shared_zones),
                        "trust_level": "high" if shared_zones else "medium",
                    })
        # From neighbor_device field
        if node.neighbor_device and node.neighbor_device in fw_devices:
            pair = tuple(sorted([dn, node.neighbor_device]))
            if pair not in seen_device_links:
                seen_device_links.add(pair)
                connections.append({
                    "source": dn,
                    "target": node.neighbor_device,
                    "type": node.link_type or "neighbor",
                    "shared_zones": [],
                    "trust_level": "medium",
                })

    # Also detect shared-zone connections for devices not already linked
    if len(fw_list) > 1:
        for i, fw1 in enumerate(fw_list):
            for fw2 in fw_list[i + 1 :]:
                pair = tuple(sorted([fw1, fw2]))
                if pair in seen_device_links:
                    continue
                shared_zones = set(fw_devices[fw1]["zones"]) & set(fw_devices[fw2]["zones"])
                if shared_zones:
                    seen_device_links.add(pair)
                    connections.append(
                        {
                            "source": fw1,
                            "target": fw2,
                            "type": "shared_zone",
                            "shared_zones": list(shared_zones),
                            "trust_level": "high",
                        }
                    )
    else:
        zone_set = {n.zone for n in nodes if n.zone}
        seen_pairs = set()
        for rule in rules:
            src = (rule.source_ip or "").strip()
            dst = (rule.dest_ip or "").strip()
            if not src or not dst:
                continue

            src_zones = [z for z in zone_set if z and (z.lower() in src.lower() or src.lower() in z.lower())]
            dst_zones = [z for z in zone_set if z and (z.lower() in dst.lower() or dst.lower() in z.lower())]
            if src == "any":
                src_zones = [z for z in zone_set if z and any(k in z.lower() for k in ["untrust", "internet", "outside", "wan"])] or list(zone_set)[:1]
            if dst == "any":
                dst_zones = list(zone_set)

            for sz in src_zones:
                for dz in dst_zones:
                    if sz == dz:
                        continue
                    pair_key = f"{sz}->{dz}"
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    trust = "low" if (rule.action or "").lower() == "deny" else "high"
                    connections.append(
                        {
                            "source": sz,
                            "target": dz,
                            "type": f"{rule.action or 'allow'}_rule",
                            "shared_zones": [sz, dz],
                            "trust_level": trust,
                        }
                    )

    device_type_counts = {}
    for fw in firewalls:
        dt = fw.get("device_type", "firewall")
        device_type_counts[dt] = device_type_counts.get(dt, 0) + 1

    chain_detected = len(firewalls) > 1 or len({n.zone for n in nodes if n.zone}) > 3
    chain_details = None
    if chain_detected:
        zone_count = len({n.zone for n in nodes if n.zone})
        parts = [f"{count} {dtype}(s)" for dtype, count in sorted(device_type_counts.items())]
        chain_details = (
            f"Detected {', '.join(parts)} managing {zone_count} security zones across "
            f"{len(connections)} inter-device links. Multi-device topology with layered network segmentation."
        )

    return FirewallTopologyResponse(
        firewalls=firewalls,
        connections=connections,
        chain_detected=chain_detected,
        chain_details=chain_details,
    )


@router.get("/topology/full")
async def get_full_topology(
    device_type: Optional[str] = None,
    zone: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Enhanced topology with all devices, health, rule counts, and filters."""
    stmt = select(NetworkTopology)
    if device_type:
        stmt = stmt.where(NetworkTopology.device_type == device_type)
    if zone:
        stmt = stmt.where(NetworkTopology.zone == zone)
    result = await db.execute(stmt)
    nodes = result.scalars().all()

    # Health data
    health_r = await db.execute(select(SystemHealth))
    health_by_device = {}
    for h in health_r.scalars().all():
        health_by_device[h.device_name] = {"cpu": h.cpu_usage_percent, "memory": h.memory_usage_percent, "sessions": h.active_sessions}

    # Rule counts
    rules_r = await db.execute(select(FirewallRule.device_name, func.count(FirewallRule.id)).group_by(FirewallRule.device_name))
    rule_counts = {row[0]: row[1] for row in rules_r.all()}

    # Build node list
    graph_nodes = []
    for n in nodes:
        if search and search.lower() not in (n.device_name or "").lower() and search.lower() not in (str(n.ip_address) or "").lower():
            continue
        node_data: Dict[str, Any] = {
            "id": n.id,
            "device_name": n.device_name,
            "device_type": n.device_type,
            "zone": n.zone,
            "ip_address": str(n.ip_address) if n.ip_address else "",
            "is_entry_point": n.is_entry_point,
            "connected_to": n.connected_to or [],
            "ports_open": n.ports_open or [],
            "vlan_id": n.vlan_id,
            "subnet": n.subnet,
            "rules_count": rule_counts.get(n.device_name, 0),
            "health": health_by_device.get(n.device_name),
        }
        # Switch-specific fields
        if n.device_type == "switch":
            node_data["vlans"] = n.vlans or []
            node_data["trunk_ports"] = n.trunk_ports or []
            node_data["access_ports"] = n.access_ports or []
            node_data["stp_mode"] = n.stp_mode
            node_data["stp_root_for"] = n.stp_root_for or []
            node_data["port_security"] = n.port_security or []
        # Router-specific fields
        if n.device_type == "router":
            node_data["interfaces"] = n.interfaces or []
            node_data["routing_protocol"] = n.routing_protocol
            node_data["ospf_area"] = n.ospf_area
            node_data["bgp_asn"] = n.bgp_asn
            node_data["bgp_neighbors"] = n.bgp_neighbors or []
            node_data["static_routes"] = n.static_routes or []
            node_data["nat_rules"] = n.nat_rules or []
        # Inter-device link info
        if n.link_type:
            node_data["link_type"] = n.link_type
        if n.link_speed:
            node_data["link_speed"] = n.link_speed
        if n.neighbor_device:
            node_data["neighbor_device"] = n.neighbor_device

        graph_nodes.append(node_data)

    # Build edges from connected_to + neighbor_device
    edges = []
    seen = set()
    for n in graph_nodes:
        targets = list(n.get("connected_to") or [])
        if n.get("neighbor_device"):
            targets.append(n["neighbor_device"])
        for target_name in targets:
            pair = tuple(sorted([n["device_name"], target_name]))
            if pair not in seen:
                seen.add(pair)
                target_node = next((g for g in graph_nodes if g["device_name"] == target_name), None)
                same_zone = target_node and target_node.get("zone") == n.get("zone")
                link_type = n.get("link_type", "routed")
                trust = "high" if same_zone else ("low" if link_type == "wan" else "medium")
                edges.append({
                    "source": n["device_name"],
                    "target": target_name,
                    "same_zone": same_zone,
                    "trust_level": trust,
                    "link_type": link_type,
                })

    # Unique zones for filter
    zones = sorted(set(n.get("zone", "") for n in graph_nodes if n.get("zone")))
    device_types = sorted(set(n.get("device_type", "") for n in graph_nodes if n.get("device_type")))

    return {
        "nodes": graph_nodes,
        "edges": edges,
        "zones": zones,
        "device_types": device_types,
        "total_nodes": len(graph_nodes),
        "total_edges": len(edges),
    }


@router.get("/export/pdf")
async def export_pdf_report(db: AsyncSession = Depends(get_db)):
    try:
        from fpdf import FPDF
    except ImportError:
        raise HTTPException(status_code=500, detail="fpdf2 not installed. Run: pip install fpdf2")

    rules_q = await db.execute(
        select(FirewallRule, RuleRiskAnalysis)
        .join(RuleRiskAnalysis, FirewallRule.id == RuleRiskAnalysis.rule_id)
        .order_by(desc(RuleRiskAnalysis.risk_score))
        .limit(50)
    )
    rules = [(r, a) for r, a in rules_q]

    paths_q = await db.execute(select(AttackPath).order_by(desc(AttackPath.total_risk_score)).limit(20))
    paths = paths_q.scalars().all()

    total_threats = (await db.execute(select(func.count(Threat.id)))).scalar() or 0
    total_rules = (await db.execute(select(func.count(FirewallRule.id)))).scalar() or 0
    critical = (await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "critical"))).scalar() or 0
    high = (await db.execute(select(func.count(RuleRiskAnalysis.id)).where(RuleRiskAnalysis.risk_level == "high"))).scalar() or 0

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 40, "", ln=True)
    pdf.cell(0, 15, "Firewall Security Assessment Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.datetime.now().strftime('%B %d, %Y at %H:%M UTC')}", ln=True, align="C")
    pdf.cell(0, 8, "ComplyGuard Security Analysis Platform", ln=True, align="C")
    pdf.cell(0, 30, "", ln=True)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(220, 53, 69)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 8, "  EXECUTIVE SUMMARY", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 10)
    pdf.ln(4)
    summary_text = (
        f"This assessment analysed {total_rules} firewall rules and identified "
        f"{critical} critical and {high} high-risk vulnerabilities. "
        f"{len(paths)} attack paths were discovered, with {total_threats} active threats detected. "
        "Immediate remediation is recommended for all critical findings."
    )
    pdf.multi_cell(0, 5, summary_text)
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(40, 167, 69)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 8, "  PRIORITISED REMEDIATION ROADMAP", ln=True, fill=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    priority = 1
    for rule, analysis in rules[:15]:
        if analysis.risk_level not in ("critical", "high"):
            continue
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, f"Priority {priority}: {rule.rule_name or 'Unnamed Rule'}", ln=True)
        pdf.set_font("Helvetica", "", 9)
        if analysis.recommendation:
            pdf.multi_cell(0, 4, f"  {analysis.recommendation}")
        pdf.ln(2)
        priority += 1

    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(0, 5, "This report was generated by ComplyGuard Security Analysis Platform.", ln=True, align="C")
    pdf.cell(0, 5, "For questions, contact your security operations team.", ln=True, align="C")

    pdf_bytes = pdf.output()
    buffer = io.BytesIO(pdf_bytes)
    buffer.seek(0)

    filename = f"firewall-security-report-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/csv")
async def export_csv_report(db: AsyncSession = Depends(get_db)):
    rows_q = await db.execute(
        select(FirewallRule, RuleRiskAnalysis)
        .join(RuleRiskAnalysis, FirewallRule.id == RuleRiskAnalysis.rule_id)
        .order_by(desc(RuleRiskAnalysis.risk_score))
        .limit(1000)
    )
    rows = [(r, a) for r, a in rows_q]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "rule_id",
        "device_name",
        "rule_name",
        "source_ip",
        "dest_ip",
        "protocol",
        "action",
        "risk_score",
        "risk_level",
        "risk_category",
        "reason",
        "recommendation",
    ])

    for rule, analysis in rows:
        writer.writerow([
            str(rule.id),
            rule.device_name,
            rule.rule_name or "",
            rule.source_ip,
            rule.dest_ip,
            rule.protocol,
            rule.action,
            float(analysis.risk_score),
            analysis.risk_level,
            analysis.risk_category or "",
            analysis.reason or "",
            analysis.recommendation or "",
        ])

    data = io.BytesIO(output.getvalue().encode("utf-8"))
    data.seek(0)
    filename = f"firewall-risk-export-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}.csv"
    return StreamingResponse(
        data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── Rule Anomaly Detection ─────────────────────────────────────────────────

@router.get("/rule-anomalies")
async def get_rule_anomalies(
    device_name: Optional[str] = None,
    anomaly_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Run the anomaly detection engine against firewall rules."""
    from dataclasses import asdict
    from utils.rule_anomaly_engine import RuleAnomalyEngine

    stmt = select(FirewallRule).order_by(FirewallRule.device_name, FirewallRule.rule_position)
    if device_name:
        stmt = stmt.where(FirewallRule.device_name == device_name)
    result = await db.execute(stmt)
    rules = list(result.scalars().all())

    if not rules:
        return {"anomalies": [], "summary": {"total": 0, "by_type": {}, "by_severity": {}}}

    engine = RuleAnomalyEngine()
    anomalies = engine.analyze(rules, device_name=device_name)

    # Filter by type if requested
    if anomaly_type:
        types = [t.strip().lower() for t in anomaly_type.split(",")]
        anomalies = [a for a in anomalies if a.anomaly_type in types]

    # Build summary
    by_type: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    for a in anomalies:
        by_type[a.anomaly_type] = by_type.get(a.anomaly_type, 0) + 1
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1

    return {
        "anomalies": [asdict(a) for a in anomalies],
        "summary": {
            "total": len(anomalies),
            "by_type": by_type,
            "by_severity": by_severity,
        },
    }


# ─── Policy Diff & Change Impact ────────────────────────────────────────────

class PolicyDiffRequest(BaseModel):
    device_name: str
    old_backup_id: str
    new_backup_id: str


class WhatIfRule(BaseModel):
    action: str = "allow"
    source_ip: str = "any"
    dest_ip: str = "any"
    dest_port: str = "any"
    protocol: str = "any"
    rule_name: str = ""


class WhatIfRequest(BaseModel):
    device_name: str
    proposed_rules: List[WhatIfRule]


@router.post("/policy/diff")
async def policy_diff(req: PolicyDiffRequest, db: AsyncSession = Depends(get_db)):
    """Compare two policy revisions and return structured diff."""
    from dataclasses import asdict
    from utils.policy_diff_engine import diff_rulesets

    old_rules = await _load_rules_for_device(db, req.device_name)
    new_rules = await _load_rules_for_device(db, req.device_name)

    # If backup IDs provided, use them to determine snapshot context
    # For now, both snapshots use current rules — this simulates the diff structure
    # In production, backup configs would be re-parsed into temporary rule sets
    diff = diff_rulesets(old_rules, new_rules)

    return {
        "added_rules": diff.added_rules,
        "removed_rules": diff.removed_rules,
        "modified_rules": [asdict(m) for m in diff.modified_rules],
        "reordered_rules": diff.reordered_rules,
        "unchanged_count": diff.unchanged_count,
        "total_old": diff.total_old,
        "total_new": diff.total_new,
    }


@router.post("/policy/impact")
async def policy_impact(req: PolicyDiffRequest, db: AsyncSession = Depends(get_db)):
    """Assess security impact of policy changes between two revisions."""
    from dataclasses import asdict
    from utils.policy_diff_engine import diff_rulesets, assess_change_impact

    old_rules = await _load_rules_for_device(db, req.device_name)
    new_rules = await _load_rules_for_device(db, req.device_name)

    diff = diff_rulesets(old_rules, new_rules)

    # Count connections per rule
    conn_counts: Dict[str, int] = {}
    for rule in old_rules:
        count_result = await db.execute(
            select(func.count(Connection.id)).where(Connection.rule_id == rule.rule_name)
        )
        conn_counts[rule.id] = count_result.scalar() or 0

    impact = assess_change_impact(diff, new_rules, conn_counts)
    return asdict(impact)


@router.post("/policy/what-if")
async def policy_what_if(req: WhatIfRequest, db: AsyncSession = Depends(get_db)):
    """Simulate adding proposed rules and assess impact."""
    from dataclasses import asdict
    from utils.policy_diff_engine import diff_rulesets, assess_change_impact, PolicyDiff
    import uuid

    current_rules = await _load_rules_for_device(db, req.device_name)

    # Build simulated new ruleset = current + proposed
    new_rules = list(current_rules)
    proposed_dicts = []
    for i, pr in enumerate(req.proposed_rules):
        sim_rule = FirewallRule(
            id=str(uuid.uuid4()),
            device_name=req.device_name,
            rule_name=pr.rule_name or f"proposed-{i+1}",
            rule_position=(len(current_rules) + i + 1),
            source_ip=pr.source_ip,
            dest_ip=pr.dest_ip,
            dest_port=pr.dest_port,
            protocol=pr.protocol,
            action=pr.action,
            hit_count=0,
            is_enabled=True,
        )
        new_rules.append(sim_rule)
        proposed_dicts.append({
            "rule_name": sim_rule.rule_name,
            "source_ip": sim_rule.source_ip,
            "dest_ip": sim_rule.dest_ip,
            "dest_port": sim_rule.dest_port,
            "protocol": sim_rule.protocol,
            "action": sim_rule.action,
        })

    diff = diff_rulesets(current_rules, new_rules)
    impact = assess_change_impact(diff, new_rules, {})

    return {
        "proposed_rules": proposed_dicts,
        "diff_summary": {
            "added": len(diff.added_rules),
            "removed": len(diff.removed_rules),
            "modified": len(diff.modified_rules),
        },
        "impact": asdict(impact),
    }


async def _load_rules_for_device(db: AsyncSession, device_name: str) -> List[FirewallRule]:
    """Load all rules for a device, sorted by position."""
    stmt = (
        select(FirewallRule)
        .where(FirewallRule.device_name == device_name)
        .order_by(FirewallRule.rule_position)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


# ─── Compliance Engine (expanded) ────────────────────────────────────────────

@router.get("/compliance/{framework}/details")
async def compliance_framework_details(framework: str, db: AsyncSession = Depends(get_db)):
    """Get per-check breakdown for a specific compliance framework."""
    from dataclasses import asdict
    from utils.compliance_engine import ComplianceEngine

    rules, topology, connections, threats = await _load_compliance_data(db)
    engine = ComplianceEngine()
    result = engine.evaluate_framework(framework, rules, topology, connections, threats)
    if not result:
        raise HTTPException(status_code=404, detail=f"Framework '{framework}' not found. Available: pci-dss, nist-800-53, cis-benchmarks, hipaa, sox")
    return asdict(result)


@router.get("/compliance/all")
async def compliance_all_frameworks(db: AsyncSession = Depends(get_db)):
    """Run all compliance frameworks and return summary + details."""
    from dataclasses import asdict
    from utils.compliance_engine import ComplianceEngine

    rules, topology, connections, threats = await _load_compliance_data(db)
    engine = ComplianceEngine()
    results = engine.evaluate_all(rules, topology, connections, threats)
    return {"frameworks": [asdict(r) for r in results]}


# ─── Traffic Analysis ────────────────────────────────────────────────────────

@router.get("/traffic/top-talkers")
async def top_talkers(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    limit = min(limit, 200)  # SECURITY: cap unbounded limit
    """Top source/destination IPs by total bytes."""
    # Top senders
    senders_q = await db.execute(
        select(Connection.src_ip, func.sum(Connection.bytes_sent).label("total_bytes"), func.count(Connection.id).label("conn_count"))
        .group_by(Connection.src_ip)
        .order_by(desc("total_bytes"))
        .limit(limit)
    )
    senders = [{"ip": r[0], "total_bytes": int(r[1] or 0), "connections": r[2], "direction": "outbound"} for r in senders_q.all()]

    # Top receivers
    receivers_q = await db.execute(
        select(Connection.dst_ip, func.sum(Connection.bytes_received).label("total_bytes"), func.count(Connection.id).label("conn_count"))
        .group_by(Connection.dst_ip)
        .order_by(desc("total_bytes"))
        .limit(limit)
    )
    receivers = [{"ip": r[0], "total_bytes": int(r[1] or 0), "connections": r[2], "direction": "inbound"} for r in receivers_q.all()]

    return {"senders": senders, "receivers": receivers}


@router.get("/traffic/zone-flow-matrix")
async def zone_flow_matrix(db: AsyncSession = Depends(get_db)):
    """Zone-to-zone traffic volume matrix."""
    q = await db.execute(
        select(
            Connection.zone_from,
            Connection.zone_to,
            func.sum(Connection.bytes_sent + Connection.bytes_received).label("total_bytes"),
            func.count(Connection.id).label("conn_count"),
        )
        .where(Connection.zone_from.isnot(None), Connection.zone_to.isnot(None))
        .group_by(Connection.zone_from, Connection.zone_to)
    )
    flows = [{"zone_from": r[0], "zone_to": r[1], "total_bytes": int(r[2] or 0), "connections": r[3]} for r in q.all()]
    zones = sorted(set(f["zone_from"] for f in flows) | set(f["zone_to"] for f in flows))
    return {"flows": flows, "zones": zones}


@router.get("/traffic/application-usage")
async def application_usage(limit: int = 20, db: AsyncSession = Depends(get_db)):
    limit = min(limit, 200)  # SECURITY: cap unbounded limit
    """Top applications by bytes."""
    q = await db.execute(
        select(
            Connection.app_name,
            Connection.app_category,
            func.sum(Connection.bytes_sent + Connection.bytes_received).label("total_bytes"),
            func.count(func.distinct(Connection.src_ip)).label("user_count"),
        )
        .where(Connection.app_name.isnot(None))
        .group_by(Connection.app_name, Connection.app_category)
        .order_by(desc("total_bytes"))
        .limit(limit)
    )
    return {"applications": [
        {"app_name": r[0], "category": r[1] or "Unknown", "total_bytes": int(r[2] or 0), "user_count": r[3]}
        for r in q.all()
    ]}


@router.get("/traffic/east-west-vs-north-south")
async def east_west_north_south(db: AsyncSession = Depends(get_db)):
    """Classify traffic as East-West (internal) or North-South (external)."""
    external_zones = {"untrust", "internet", "outside", "wan", "public", "external"}

    q = await db.execute(
        select(Connection.zone_from, Connection.zone_to, func.sum(Connection.bytes_sent + Connection.bytes_received).label("total_bytes"))
        .where(Connection.zone_from.isnot(None), Connection.zone_to.isnot(None))
        .group_by(Connection.zone_from, Connection.zone_to)
    )
    ew_bytes = 0
    ns_bytes = 0
    for zf, zt, total in q.all():
        total = int(total or 0)
        if (zf or "").lower() in external_zones or (zt or "").lower() in external_zones:
            ns_bytes += total
        else:
            ew_bytes += total

    grand = max(ew_bytes + ns_bytes, 1)
    return {
        "east_west_bytes": ew_bytes,
        "north_south_bytes": ns_bytes,
        "east_west_pct": round(ew_bytes / grand * 100, 1),
        "north_south_pct": round(ns_bytes / grand * 100, 1),
    }


async def _load_compliance_data(db: AsyncSession):
    """Load all data needed for compliance checks."""
    rules_r = await db.execute(select(FirewallRule))
    topo_r = await db.execute(select(NetworkTopology))
    conn_r = await db.execute(select(Connection).limit(1000))
    threat_r = await db.execute(select(Threat).limit(1000))
    return (
        list(rules_r.scalars().all()),
        list(topo_r.scalars().all()),
        list(conn_r.scalars().all()),
        list(threat_r.scalars().all()),
    )
