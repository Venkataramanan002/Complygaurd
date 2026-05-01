"""
Zone Trust & Micro-segmentation Engine.

Analyses firewall rules and connection logs to produce a zone trust matrix
and actionable micro-segmentation recommendations.
"""

import logging
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional

from database.models import FirewallRule, Connection, NetworkTopology

logger = logging.getLogger(__name__)


# ── Zone trust matrix ───────────────────────────────────────────────────────

def build_zone_trust_matrix(
    rules: List[FirewallRule],
    connections: List[Connection],
) -> Dict[str, Any]:
    """
    Build a zone-to-zone trust matrix from live firewall rules and traffic
    connection logs.

    Returns
    -------
    dict
        {
            "zones": ["DMZ", "Internal", ...],
            "matrix": [
                {
                    "zone_from": "DMZ",
                    "zone_to": "Internal",
                    "allow_rules": 12,
                    "deny_rules": 3,
                    "traffic_bytes": 1048576,
                    "trust_level": "medium",
                    "risk_level": "medium",
                },
                ...
            ],
        }
    """

    # --- collect zone names from rules (source/dest IP might also hint at
    #     zones, but the Connection model has explicit zone_from / zone_to) ---
    zones_set: set[str] = set()

    # --- aggregate rule counts per zone pair ---
    pair_allow: Dict[tuple, int] = defaultdict(int)
    pair_deny: Dict[tuple, int] = defaultdict(int)

    for rule in rules:
        # Rules don't store zones directly; derive from device_name or
        # fall back to generic labels based on IP wildcards.
        src_zone = _zone_from_rule(rule, "source")
        dst_zone = _zone_from_rule(rule, "dest")
        zones_set.update((src_zone, dst_zone))
        action = (rule.action or "").lower()
        pair = (src_zone, dst_zone)
        if action == "allow":
            pair_allow[pair] += 1
        elif action == "deny":
            pair_deny[pair] += 1

    # --- aggregate traffic from connections ---
    pair_bytes: Dict[tuple, int] = defaultdict(int)

    for conn in connections:
        z_from = (conn.zone_from or "unknown").strip() or "unknown"
        z_to = (conn.zone_to or "unknown").strip() or "unknown"
        zones_set.update((z_from, z_to))
        pair_bytes[(z_from, z_to)] += (conn.bytes_sent or 0) + (conn.bytes_received or 0)

    zones = sorted(zones_set)

    # --- build matrix entries for every ordered pair ---
    matrix: List[Dict[str, Any]] = []
    for z_from in zones:
        for z_to in zones:
            if z_from == z_to:
                continue
            pair = (z_from, z_to)
            allow = pair_allow.get(pair, 0)
            deny = pair_deny.get(pair, 0)
            traffic = pair_bytes.get(pair, 0)
            trust = _compute_trust_level(allow, deny, traffic)
            risk = _compute_risk_level(allow, deny, traffic)

            matrix.append({
                "zone_from": z_from,
                "zone_to": z_to,
                "allow_rules": allow,
                "deny_rules": deny,
                "traffic_bytes": traffic,
                "trust_level": trust,
                "risk_level": risk,
            })

    return {"zones": zones, "matrix": matrix}


# ── Micro-segmentation recommendations ─────────────────────────────────────

def recommend_microsegmentation(
    rules: List[FirewallRule],
    connections: List[Connection],
    topology: List[NetworkTopology],
) -> List[Dict[str, Any]]:
    """
    Analyse rules, traffic, and topology to produce micro-segmentation
    recommendations sorted by priority (highest first).

    Each recommendation:
        {
            "id": uuid,
            "priority": "critical" | "high" | "medium" | "low",
            "current_state": "description of current posture",
            "recommended_action": "what to do",
            "affected_zones": ["Zone-A", "Zone-B"],
            "estimated_risk_reduction": float  (0-100 scale)
        }
    """

    recommendations: List[Dict[str, Any]] = []

    # Build the trust matrix for analysis
    trust_data = build_zone_trust_matrix(rules, connections)
    matrix = trust_data["matrix"]

    # 1. Flag zone pairs with high allow / zero deny (no segmentation)
    for entry in matrix:
        if entry["allow_rules"] > 0 and entry["deny_rules"] == 0:
            priority = "critical" if entry["allow_rules"] >= 5 else "high"
            recommendations.append({
                "id": str(uuid.uuid4()),
                "priority": priority,
                "current_state": (
                    f"{entry['allow_rules']} allow rules from {entry['zone_from']} to "
                    f"{entry['zone_to']} with zero deny rules — no segmentation boundary."
                ),
                "recommended_action": (
                    f"Add explicit deny rules between {entry['zone_from']} and "
                    f"{entry['zone_to']} to enforce least-privilege. Allow only "
                    f"required services and ports."
                ),
                "affected_zones": [entry["zone_from"], entry["zone_to"]],
                "estimated_risk_reduction": min(entry["allow_rules"] * 8.0, 80.0),
            })

    # 2. High-traffic pairs with low trust suggest over-permissive paths
    for entry in matrix:
        if entry["traffic_bytes"] > 1_000_000 and entry["trust_level"] == "low":
            recommendations.append({
                "id": str(uuid.uuid4()),
                "priority": "high",
                "current_state": (
                    f"High traffic ({_fmt_bytes(entry['traffic_bytes'])}) from "
                    f"{entry['zone_from']} to {entry['zone_to']} despite low trust. "
                    f"Deny rules ({entry['deny_rules']}) outnumber allow rules ({entry['allow_rules']})."
                ),
                "recommended_action": (
                    f"Investigate traffic between {entry['zone_from']} and "
                    f"{entry['zone_to']}. Apply application-level micro-segmentation "
                    f"policies and consider a next-gen firewall profile for deep inspection."
                ),
                "affected_zones": [entry["zone_from"], entry["zone_to"]],
                "estimated_risk_reduction": 45.0,
            })

    # 3. Topology: entry-point devices without dedicated zone isolation
    entry_points = [t for t in topology if t.is_entry_point]
    zones_with_entry = {(t.zone or "unknown") for t in entry_points}
    non_entry_zones = {(t.zone or "unknown") for t in topology} - zones_with_entry
    for ep_zone in sorted(zones_with_entry):
        for internal_zone in sorted(non_entry_zones):
            # Check if there is a direct allow path from entry zone to internal zone
            pair_data = next(
                (m for m in matrix if m["zone_from"] == ep_zone and m["zone_to"] == internal_zone),
                None,
            )
            if pair_data and pair_data["allow_rules"] > 0 and pair_data["deny_rules"] == 0:
                recommendations.append({
                    "id": str(uuid.uuid4()),
                    "priority": "critical",
                    "current_state": (
                        f"Entry-point zone '{ep_zone}' has unrestricted allow rules "
                        f"({pair_data['allow_rules']}) into internal zone '{internal_zone}' "
                        f"with no deny rules."
                    ),
                    "recommended_action": (
                        f"Implement a DMZ or jump-host architecture between '{ep_zone}' and "
                        f"'{internal_zone}'. Add deny-by-default policy with explicit service "
                        f"allow-lists."
                    ),
                    "affected_zones": [ep_zone, internal_zone],
                    "estimated_risk_reduction": 75.0,
                })

    # 4. Overly permissive rules (any/any source or dest)
    any_any_rules = [
        r for r in rules
        if (r.action or "").lower() == "allow"
        and _is_any(r.source_ip) and _is_any(r.dest_ip)
    ]
    if any_any_rules:
        affected_devices = sorted({r.device_name for r in any_any_rules})
        recommendations.append({
            "id": str(uuid.uuid4()),
            "priority": "critical",
            "current_state": (
                f"{len(any_any_rules)} rules allow any-to-any traffic across devices: "
                f"{', '.join(affected_devices[:5])}."
            ),
            "recommended_action": (
                "Replace any/any allow rules with specific source-destination-port "
                "combinations. Map required application flows and create granular "
                "micro-segmentation policies."
            ),
            "affected_zones": affected_devices[:10],
            "estimated_risk_reduction": 90.0,
        })

    # Sort by priority weight
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recommendations.sort(key=lambda r: priority_order.get(r["priority"], 9))

    return recommendations


# ── Internal helpers ────────────────────────────────────────────────────────

def _zone_from_rule(rule: FirewallRule, direction: str) -> str:
    """
    Derive a pseudo-zone label from a rule.  Real zone info lives in
    Connection.zone_from / zone_to, but for rules we approximate from
    the device name and IP wildcards.
    """
    ip = rule.source_ip if direction == "source" else rule.dest_ip
    if _is_any(ip):
        return "any"
    device = (rule.device_name or "unknown").lower()
    if "dmz" in device:
        return "DMZ"
    if "ext" in device or "wan" in device or "outside" in device:
        return "external"
    if "int" in device or "lan" in device or "inside" in device:
        return "internal"
    return rule.device_name or "unknown"


def _is_any(val: str) -> bool:
    return (val or "").strip().lower() in ("any", "0.0.0.0/0", "*", "")


def _compute_trust_level(allow: int, deny: int, traffic_bytes: int) -> str:
    """
    Heuristic trust classification.

    * mostly deny → low trust
    * mostly allow with significant traffic → high trust
    * balanced → medium
    """
    total_rules = allow + deny
    if total_rules == 0:
        return "none"
    deny_ratio = deny / total_rules
    if deny_ratio >= 0.7:
        return "low"
    if deny_ratio <= 0.2 and traffic_bytes > 100_000:
        return "high"
    return "medium"


def _compute_risk_level(allow: int, deny: int, traffic_bytes: int) -> str:
    """
    Risk is roughly inverse of trust:
    * high trust + high traffic = low risk (well-understood flows)
    * low trust + high traffic = high risk (suspicious volume despite denials)
    * many allow + zero deny = high risk (no segmentation)
    """
    total_rules = allow + deny
    if total_rules == 0:
        return "low"
    if allow > 0 and deny == 0:
        # No segmentation at all
        return "critical" if allow >= 5 else "high"
    deny_ratio = deny / total_rules
    if deny_ratio >= 0.7 and traffic_bytes > 1_000_000:
        return "high"
    if deny_ratio <= 0.2:
        return "medium"
    return "low"


def _fmt_bytes(n: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"
