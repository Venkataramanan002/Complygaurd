"""
Advanced rule anomaly detection engine.

Detects: shadow, redundant, overlap, duplicate, and overly permissive rules.
Uses Python's ipaddress module for CIDR comparison.
"""

import ipaddress
import logging
from dataclasses import dataclass, asdict
from typing import List, Optional

from database.models import FirewallRule

logger = logging.getLogger(__name__)


@dataclass
class RuleAnomaly:
    anomaly_type: str  # shadow | redundant | overlap | duplicate | overly_permissive
    rule_id: str
    rule_name: str
    rule_position: int
    device_name: str
    conflicting_rule_id: Optional[str]
    conflicting_rule_name: Optional[str]
    conflicting_rule_position: Optional[int]
    severity: str  # critical | high | medium | low
    explanation: str
    recommendation: str
    # Details for side-by-side view
    rule_source: str = ""
    rule_dest: str = ""
    rule_port: str = ""
    rule_protocol: str = ""
    rule_action: str = ""
    conflicting_source: str = ""
    conflicting_dest: str = ""
    conflicting_port: str = ""
    conflicting_protocol: str = ""
    conflicting_action: str = ""


def _normalize_ip(val: str) -> str:
    """Normalize IP/CIDR string for comparison."""
    if not val:
        return "any"
    v = val.strip().lower()
    if v in ("any", "0.0.0.0/0", "*", "all"):
        return "any"
    return v


def _normalize_port(val: str) -> str:
    """Normalize port string."""
    if not val:
        return "any"
    v = val.strip().lower()
    if v in ("any", "0-65535", "1-65535", "*", "all"):
        return "any"
    return v


def _ip_is_superset(container: str, contained: str) -> bool:
    """Check if 'container' IP/CIDR is a superset of (covers) 'contained'."""
    c1 = _normalize_ip(container)
    c2 = _normalize_ip(contained)

    if c1 == "any":
        return True
    if c2 == "any":
        return c1 == "any"

    try:
        if "/" not in c1:
            c1 += "/32"
        if "/" not in c2:
            c2 += "/32"
        net1 = ipaddress.ip_network(c1, strict=False)
        net2 = ipaddress.ip_network(c2, strict=False)
        return net1.supernet_of(net2)
    except ValueError:
        return c1 == c2  # fallback for named objects


def _ip_overlaps(a: str, b: str) -> bool:
    """Check if two IP/CIDR ranges overlap at all."""
    a_n = _normalize_ip(a)
    b_n = _normalize_ip(b)

    if a_n == "any" or b_n == "any":
        return True

    try:
        if "/" not in a_n:
            a_n += "/32"
        if "/" not in b_n:
            b_n += "/32"
        net_a = ipaddress.ip_network(a_n, strict=False)
        net_b = ipaddress.ip_network(b_n, strict=False)
        return net_a.overlaps(net_b)
    except ValueError:
        return a_n == b_n


def _port_is_superset(container: str, contained: str) -> bool:
    """Check if container port range covers the contained port range."""
    c1 = _normalize_port(container)
    c2 = _normalize_port(contained)

    if c1 == "any":
        return True
    if c2 == "any":
        return c1 == "any"

    try:
        def parse_range(p):
            if "-" in p:
                lo, hi = map(int, p.split("-"))
                return lo, hi
            return int(p), int(p)

        lo1, hi1 = parse_range(c1)
        lo2, hi2 = parse_range(c2)
        return lo1 <= lo2 and hi1 >= hi2
    except (ValueError, TypeError):
        return c1 == c2


def _port_overlaps(a: str, b: str) -> bool:
    """Check if two port ranges overlap."""
    a_n = _normalize_port(a)
    b_n = _normalize_port(b)

    if a_n == "any" or b_n == "any":
        return True

    try:
        def parse_range(p):
            if "-" in p:
                lo, hi = map(int, p.split("-"))
                return lo, hi
            return int(p), int(p)

        lo1, hi1 = parse_range(a_n)
        lo2, hi2 = parse_range(b_n)
        return lo1 <= hi2 and lo2 <= hi1
    except (ValueError, TypeError):
        return a_n == b_n


def _proto_match(a: str, b: str) -> bool:
    """Check if protocols match (any matches everything)."""
    a_n = (a or "any").strip().lower()
    b_n = (b or "any").strip().lower()
    if a_n == "any" or b_n == "any":
        return True
    return a_n == b_n


def _fields_identical(r1: FirewallRule, r2: FirewallRule) -> bool:
    """Check if two rules have identical matching fields."""
    return (
        _normalize_ip(r1.source_ip) == _normalize_ip(r2.source_ip)
        and _normalize_ip(r1.dest_ip) == _normalize_ip(r2.dest_ip)
        and _normalize_port(r1.dest_port or "") == _normalize_port(r2.dest_port or "")
        and _proto_match(r1.protocol, r2.protocol)
    )


def _make_anomaly(
    atype: str, rule: FirewallRule, conflicting: Optional[FirewallRule],
    severity: str, explanation: str, recommendation: str,
) -> RuleAnomaly:
    return RuleAnomaly(
        anomaly_type=atype,
        rule_id=rule.id,
        rule_name=rule.rule_name or f"rule-{rule.rule_position}",
        rule_position=rule.rule_position or 0,
        device_name=rule.device_name,
        conflicting_rule_id=conflicting.id if conflicting else None,
        conflicting_rule_name=(conflicting.rule_name or f"rule-{conflicting.rule_position}") if conflicting else None,
        conflicting_rule_position=conflicting.rule_position if conflicting else None,
        severity=severity,
        explanation=explanation,
        recommendation=recommendation,
        rule_source=rule.source_ip,
        rule_dest=rule.dest_ip,
        rule_port=rule.dest_port or "any",
        rule_protocol=rule.protocol,
        rule_action=rule.action,
        conflicting_source=conflicting.source_ip if conflicting else "",
        conflicting_dest=conflicting.dest_ip if conflicting else "",
        conflicting_port=(conflicting.dest_port or "any") if conflicting else "",
        conflicting_protocol=conflicting.protocol if conflicting else "",
        conflicting_action=conflicting.action if conflicting else "",
    )


class RuleAnomalyEngine:
    """Comprehensive rule anomaly detector."""

    def analyze(self, rules: List[FirewallRule], device_name: Optional[str] = None) -> List[RuleAnomaly]:
        """Run all anomaly checks on the given rules."""
        if device_name:
            rules = [r for r in rules if r.device_name == device_name]

        # Sort by device then position
        rules.sort(key=lambda r: (r.device_name, r.rule_position or 0))

        anomalies: List[RuleAnomaly] = []
        seen_ids = set()

        # Group rules by device
        by_device: dict = {}
        for r in rules:
            by_device.setdefault(r.device_name, []).append(r)

        for dev, dev_rules in by_device.items():
            anomalies.extend(self._detect_overly_permissive(dev_rules))
            anomalies.extend(self._detect_shadows(dev_rules))
            anomalies.extend(self._detect_redundant(dev_rules, seen_ids))
            anomalies.extend(self._detect_duplicates(dev_rules, seen_ids))
            anomalies.extend(self._detect_overlaps(dev_rules, seen_ids))

        return anomalies

    def _detect_overly_permissive(self, rules: List[FirewallRule]) -> List[RuleAnomaly]:
        """Rules with any/any source+dest, any port, action=allow."""
        results = []
        for r in rules:
            if (r.action or "").lower() != "allow":
                continue
            src = _normalize_ip(r.source_ip)
            dst = _normalize_ip(r.dest_ip)
            port = _normalize_port(r.dest_port or "")
            if src == "any" and dst == "any" and port == "any":
                results.append(_make_anomaly(
                    "overly_permissive", r, None, "critical",
                    f"Rule '{r.rule_name}' allows ALL traffic from ANY source to ANY destination on ANY port. This is a critical security risk.",
                    "Restrict source and destination to specific IP ranges and limit allowed ports to only required services.",
                ))
        return results

    def _detect_shadows(self, rules: List[FirewallRule]) -> List[RuleAnomaly]:
        """Rule R is shadowed if a higher-priority rule H covers all its traffic with a different action."""
        results = []
        for i, r in enumerate(rules):
            for h in rules[:i]:  # higher priority = earlier in sorted list
                if (h.rule_position or 0) >= (r.rule_position or 0):
                    continue
                # H must be a superset of R on all matching fields
                if (
                    _ip_is_superset(h.source_ip, r.source_ip)
                    and _ip_is_superset(h.dest_ip, r.dest_ip)
                    and _port_is_superset(h.dest_port or "any", r.dest_port or "any")
                    and _proto_match(h.protocol, r.protocol)
                    and (h.action or "").lower() != (r.action or "").lower()
                ):
                    results.append(_make_anomaly(
                        "shadow", r, h, "high",
                        f"Rule '{r.rule_name}' (pos {r.rule_position}) is shadowed by '{h.rule_name}' (pos {h.rule_position}). "
                        f"All traffic matching this rule is already handled by the higher-priority rule with action='{h.action}'.",
                        "Delete this rule or move it above the shadowing rule if the intent differs.",
                    ))
                    break  # Only report first shadow
        return results

    def _detect_redundant(self, rules: List[FirewallRule], seen: set) -> List[RuleAnomaly]:
        """Two rules are redundant if identical fields AND same action."""
        results = []
        for i, r in enumerate(rules):
            for h in rules[:i]:
                pair_key = f"redundant:{h.id}:{r.id}"
                if pair_key in seen:
                    continue
                if (
                    _fields_identical(r, h)
                    and (r.action or "").lower() == (h.action or "").lower()
                ):
                    seen.add(pair_key)
                    results.append(_make_anomaly(
                        "redundant", r, h, "medium",
                        f"Rule '{r.rule_name}' (pos {r.rule_position}) is redundant with '{h.rule_name}' (pos {h.rule_position}). Both have identical matching criteria and the same action.",
                        "Remove the lower-priority duplicate rule to simplify the ruleset.",
                    ))
                    break
        return results

    def _detect_duplicates(self, rules: List[FirewallRule], seen: set) -> List[RuleAnomaly]:
        """Exact field-match duplicates across ALL fields."""
        results = []
        for i, r in enumerate(rules):
            for j, r2 in enumerate(rules[i + 1:], start=i + 1):
                pair_key = f"duplicate:{r.id}:{r2.id}"
                if pair_key in seen:
                    continue
                if (
                    _normalize_ip(r.source_ip) == _normalize_ip(r2.source_ip)
                    and _normalize_ip(r.dest_ip) == _normalize_ip(r2.dest_ip)
                    and _normalize_port(r.dest_port or "") == _normalize_port(r2.dest_port or "")
                    and _normalize_port(r.source_port or "") == _normalize_port(r2.source_port or "")
                    and _proto_match(r.protocol, r2.protocol)
                    and (r.action or "").lower() == (r2.action or "").lower()
                    and (r.service_name or "").lower() == (r2.service_name or "").lower()
                ):
                    seen.add(pair_key)
                    results.append(_make_anomaly(
                        "duplicate", r2, r, "low",
                        f"Rule '{r2.rule_name}' is an exact duplicate of '{r.rule_name}'. All fields match.",
                        "Delete the duplicate rule.",
                    ))
        return results

    def _detect_overlaps(self, rules: List[FirewallRule], seen: set) -> List[RuleAnomaly]:
        """Partial overlap: CIDRs overlap and ports intersect but not identical."""
        results = []
        for i, r in enumerate(rules):
            for j, r2 in enumerate(rules[i + 1:], start=i + 1):
                pair_key = f"overlap:{r.id}:{r2.id}"
                if pair_key in seen:
                    continue
                # Skip if already detected as redundant or duplicate
                if f"redundant:{r.id}:{r2.id}" in seen or f"duplicate:{r.id}:{r2.id}" in seen:
                    continue

                if not _proto_match(r.protocol, r2.protocol):
                    continue

                src_overlaps = _ip_overlaps(r.source_ip, r2.source_ip)
                dst_overlaps = _ip_overlaps(r.dest_ip, r2.dest_ip)
                port_overlaps = _port_overlaps(r.dest_port or "any", r2.dest_port or "any")

                if src_overlaps and dst_overlaps and port_overlaps:
                    # Only if not fully identical
                    if _fields_identical(r, r2):
                        continue
                    seen.add(pair_key)
                    severity = "high" if (r.action or "").lower() != (r2.action or "").lower() else "medium"
                    results.append(_make_anomaly(
                        "overlap", r2, r, severity,
                        f"Rule '{r2.rule_name}' (pos {r2.rule_position}) partially overlaps with '{r.rule_name}' (pos {r.rule_position}). "
                        f"Source, destination, and port ranges intersect{'  with conflicting actions' if severity == 'high' else ''}.",
                        "Review both rules and consolidate or reorder to eliminate ambiguity.",
                    ))
        return results
