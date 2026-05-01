"""
Policy revision diff and change impact analysis engine.

Compares two rulesets, detects additions/removals/modifications/reorders,
and assesses risk impact of changes.
"""

import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from database.models import FirewallRule

logger = logging.getLogger(__name__)

COMPARE_FIELDS = ["source_ip", "dest_ip", "source_port", "dest_port", "protocol", "action", "service_name", "is_enabled"]


@dataclass
class FieldChange:
    field: str
    old_value: str
    new_value: str


@dataclass
class ModifiedRule:
    rule_name: str
    rule_id: str
    field_changes: List[FieldChange]


@dataclass
class PolicyDiff:
    added_rules: List[Dict[str, Any]]
    removed_rules: List[Dict[str, Any]]
    modified_rules: List[ModifiedRule]
    reordered_rules: List[Dict[str, Any]]
    unchanged_count: int
    total_old: int
    total_new: int


@dataclass
class ImpactAssessment:
    risk_delta: float
    new_attack_paths_opened: int
    attack_paths_closed: int
    affected_zones: List[str]
    connections_impacted_count: int
    risk_verdict: str  # safe | caution | dangerous
    added_risk_scores: List[Dict[str, Any]]
    removed_rule_impacts: List[Dict[str, Any]]


def _rule_to_dict(rule: FirewallRule) -> Dict[str, Any]:
    return {
        "id": rule.id,
        "rule_name": rule.rule_name,
        "device_name": rule.device_name,
        "rule_position": rule.rule_position,
        "source_ip": rule.source_ip,
        "dest_ip": rule.dest_ip,
        "source_port": rule.source_port,
        "dest_port": rule.dest_port,
        "protocol": rule.protocol,
        "action": rule.action,
        "service_name": rule.service_name,
        "is_enabled": rule.is_enabled,
    }


def _fuzzy_match_key(rule: FirewallRule) -> str:
    """Generate a fuzzy match key from source+dest+port+protocol for rename detection."""
    return (
        f"{(rule.source_ip or '').lower()}|"
        f"{(rule.dest_ip or '').lower()}|"
        f"{(rule.dest_port or '').lower()}|"
        f"{(rule.protocol or '').lower()}"
    )


def diff_rulesets(old_rules: List[FirewallRule], new_rules: List[FirewallRule]) -> PolicyDiff:
    """Compare two rulesets by rule_name (with fuzzy fallback on source+dest+port+protocol)."""

    old_by_name = {r.rule_name: r for r in old_rules if r.rule_name}
    new_by_name = {r.rule_name: r for r in new_rules if r.rule_name}

    old_names = set(old_by_name.keys())
    new_names = set(new_by_name.keys())

    # Direct name matches
    common_names = old_names & new_names
    only_old_names = old_names - new_names
    only_new_names = new_names - old_names

    # Fuzzy match: for unmatched old/new, try matching on src+dst+port+proto
    old_fuzzy = {_fuzzy_match_key(old_by_name[n]): n for n in only_old_names}
    fuzzy_matched = {}  # new_name -> old_name
    still_only_new = set()

    for nn in only_new_names:
        key = _fuzzy_match_key(new_by_name[nn])
        if key in old_fuzzy:
            fuzzy_matched[nn] = old_fuzzy.pop(key)
        else:
            still_only_new.add(nn)

    still_only_old = set(old_fuzzy.values())

    # Build results
    added = [_rule_to_dict(new_by_name[n]) for n in still_only_new]
    removed = [_rule_to_dict(old_by_name[n]) for n in still_only_old]

    # Check modifications (direct matches + fuzzy matches)
    modified = []
    reordered = []
    unchanged = 0

    for old_name in common_names:
        changes = _compare_rules(old_by_name[old_name], new_by_name[old_name])
        if changes:
            modified.append(ModifiedRule(
                rule_name=old_name,
                rule_id=old_by_name[old_name].id,
                field_changes=changes,
            ))
        elif (old_by_name[old_name].rule_position or 0) != (new_by_name[old_name].rule_position or 0):
            reordered.append({
                "rule_name": old_name,
                "old_position": old_by_name[old_name].rule_position,
                "new_position": new_by_name[old_name].rule_position,
            })
        else:
            unchanged += 1

    # Fuzzy-matched rules treated as modified (rename + possible field changes)
    for new_name, old_name in fuzzy_matched.items():
        changes = _compare_rules(old_by_name[old_name], new_by_name[new_name])
        changes.insert(0, FieldChange(field="rule_name", old_value=old_name, new_value=new_name))
        modified.append(ModifiedRule(
            rule_name=new_name,
            rule_id=old_by_name[old_name].id,
            field_changes=changes,
        ))

    return PolicyDiff(
        added_rules=added,
        removed_rules=removed,
        modified_rules=modified,
        reordered_rules=reordered,
        unchanged_count=unchanged,
        total_old=len(old_rules),
        total_new=len(new_rules),
    )


def _compare_rules(old: FirewallRule, new: FirewallRule) -> List[FieldChange]:
    """Compare two rules field-by-field, return list of changes."""
    changes = []
    for f in COMPARE_FIELDS:
        old_val = str(getattr(old, f, "") or "")
        new_val = str(getattr(new, f, "") or "")
        if old_val != new_val:
            changes.append(FieldChange(field=f, old_value=old_val, new_value=new_val))
    return changes


def assess_change_impact(
    diff: PolicyDiff,
    all_rules: List[FirewallRule],
    connections_by_rule: Dict[str, int],
) -> ImpactAssessment:
    """Assess the security impact of a policy diff."""
    from utils.risk_engine import calculate_rule_risk

    VULNERABLE_PORTS = {
        21: {"service": "FTP", "risk": "high"},
        23: {"service": "Telnet", "risk": "critical"},
        80: {"service": "HTTP", "risk": "medium"},
        445: {"service": "SMB", "risk": "high"},
        1433: {"service": "MSSQL", "risk": "high"},
        3306: {"service": "MySQL", "risk": "high"},
        3389: {"service": "RDP", "risk": "high"},
        5432: {"service": "PostgreSQL", "risk": "high"},
    }

    risk_delta = 0.0
    affected_zones = set()
    connections_impacted = 0
    added_scores = []
    removed_impacts = []
    paths_opened = 0
    paths_closed = 0

    # Assess added rules
    for rule_dict in diff.added_rules:
        # Create a temporary FirewallRule object for scoring
        tmp = FirewallRule(**{k: v for k, v in rule_dict.items() if k != "id"})
        tmp.id = rule_dict.get("id", "temp")
        tmp.hit_count = 0
        score = calculate_rule_risk(tmp, all_rules, VULNERABLE_PORTS)
        risk_delta += score["risk_score"]
        added_scores.append({
            "rule_name": rule_dict.get("rule_name"),
            "risk_score": score["risk_score"],
            "risk_level": score["risk_level"],
            "reason": score["reason"],
        })
        if (tmp.action or "").lower() == "allow":
            paths_opened += 1

        # Track affected zones
        for zone_field in ["source_ip", "dest_ip"]:
            z = rule_dict.get(zone_field, "")
            if z and z.lower() != "any":
                affected_zones.add(z)

    # Assess removed rules
    for rule_dict in diff.removed_rules:
        rule_id = rule_dict.get("id", "")
        conn_count = connections_by_rule.get(rule_id, 0)
        connections_impacted += conn_count
        if (rule_dict.get("action", "").lower()) == "deny":
            paths_opened += 1  # removing a deny = opens a path
        else:
            paths_closed += 1  # removing an allow = closes a path
        removed_impacts.append({
            "rule_name": rule_dict.get("rule_name"),
            "connections_affected": conn_count,
            "action_was": rule_dict.get("action"),
        })

    # Assess modified rules
    for mod in diff.modified_rules:
        for change in mod.field_changes:
            if change.field == "action" and change.old_value == "deny" and change.new_value == "allow":
                risk_delta += 3.0  # deny→allow is risky
                paths_opened += 1
            elif change.field == "action" and change.old_value == "allow" and change.new_value == "deny":
                risk_delta -= 2.0  # allow→deny is safer
                paths_closed += 1
            elif change.field in ("source_ip", "dest_ip") and change.new_value.lower() == "any":
                risk_delta += 2.0  # widening to any

    # Determine verdict
    if risk_delta >= 5 or paths_opened >= 3:
        verdict = "dangerous"
    elif risk_delta >= 1 or paths_opened >= 1:
        verdict = "caution"
    else:
        verdict = "safe"

    return ImpactAssessment(
        risk_delta=round(risk_delta, 1),
        new_attack_paths_opened=paths_opened,
        attack_paths_closed=paths_closed,
        affected_zones=sorted(affected_zones),
        connections_impacted_count=connections_impacted,
        risk_verdict=verdict,
        added_risk_scores=added_scores,
        removed_rule_impacts=removed_impacts,
    )
