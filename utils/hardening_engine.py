"""
utils/hardening_engine.py
Device hardening assessment engine.

Runs a suite of security checks against a device's firewall rule-set and
optional topology metadata, producing a 0-100 score with per-check details.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from database.models import FirewallRule

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Check definitions  (id, name, severity, weight)
# ---------------------------------------------------------------------------
_CHECK_DEFS: List[Dict[str, Any]] = [
    {
        "check_id": "default_deny_exists",
        "check_name": "Default Deny Rule Exists",
        "severity": "critical",
        "weight": 25,
    },
    {
        "check_id": "no_any_any_allow",
        "check_name": "No Any-Any Allow Rule",
        "severity": "critical",
        "weight": 25,
    },
    {
        "check_id": "admin_access_restricted",
        "check_name": "Administrative Access Restricted",
        "severity": "high",
        "weight": 15,
    },
    {
        "check_id": "unused_rules_count",
        "check_name": "No Unused / Zero-Hit Rules",
        "severity": "medium",
        "weight": 10,
    },
    {
        "check_id": "insecure_services_blocked",
        "check_name": "Insecure Services Blocked",
        "severity": "high",
        "weight": 15,
    },
    {
        "check_id": "logging_enabled",
        "check_name": "Logging Enabled on All Rules",
        "severity": "medium",
        "weight": 10,
    },
]

# Ports considered insecure / high-risk
_INSECURE_PORTS = {21, 23, 69, 135, 137, 138, 139, 445, 514, 1900}

# Admin / management ports
_ADMIN_PORTS = {22, 23, 3389, 443, 8443, 8080}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _normalize(val: Optional[str]) -> str:
    if not val:
        return "any"
    v = val.strip().lower()
    if v in ("any", "0.0.0.0/0", "*", "all", "1-65535", "0-65535"):
        return "any"
    return v


def _port_set(port_str: str) -> set[int]:
    """Return a set of individual port numbers from a port string."""
    n = _normalize(port_str)
    if n == "any":
        return set()  # unbounded — caller must treat specially
    try:
        if "-" in n:
            lo, hi = map(int, n.split("-"))
            return set(range(lo, hi + 1))
        return {int(n)}
    except (ValueError, TypeError):
        return set()


def _is_any(val: Optional[str]) -> bool:
    return _normalize(val) == "any"


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------

def _check_default_deny(rules: List[FirewallRule]) -> Dict[str, Any]:
    """The last rule (highest position number) should be a deny-all."""
    if not rules:
        return _fail(
            "default_deny_exists",
            "No rules found — cannot verify a default-deny policy.",
            "Add an explicit deny-all rule at the end of the ruleset.",
        )

    last_rule = max(rules, key=lambda r: r.rule_position or 0)
    action = (last_rule.action or "").lower()
    src = _normalize(last_rule.source_ip)
    dst = _normalize(last_rule.dest_ip)
    port = _normalize(last_rule.dest_port)

    if action in ("deny", "drop", "reject") and src == "any" and dst == "any":
        return _pass("default_deny_exists", "Default deny-all rule found at the end of the ruleset.")

    return _fail(
        "default_deny_exists",
        f"Last rule (pos {last_rule.rule_position}) has action='{last_rule.action}' — expected deny/drop for any->any.",
        "Add an explicit deny-all rule at the bottom of the ruleset to enforce least-privilege.",
    )


def _check_no_any_any_allow(rules: List[FirewallRule]) -> Dict[str, Any]:
    """No rule should allow ANY source to ANY dest on ANY port."""
    offenders = []
    for r in rules:
        if (r.action or "").lower() != "allow":
            continue
        if _is_any(r.source_ip) and _is_any(r.dest_ip) and _is_any(r.dest_port):
            offenders.append(r.rule_name or f"pos-{r.rule_position}")

    if not offenders:
        return _pass("no_any_any_allow", "No any/any/any allow rules detected.")

    names = ", ".join(offenders[:5])
    suffix = f" (+{len(offenders) - 5} more)" if len(offenders) > 5 else ""
    return _fail(
        "no_any_any_allow",
        f"Found {len(offenders)} any/any/any allow rule(s): {names}{suffix}.",
        "Replace overly permissive rules with specific source/destination/port restrictions.",
    )


def _check_admin_access(rules: List[FirewallRule]) -> Dict[str, Any]:
    """Admin ports (SSH, RDP, HTTPS-mgmt) must not be open from 'any' source."""
    open_admin: List[str] = []
    for r in rules:
        if (r.action or "").lower() != "allow":
            continue
        if not _is_any(r.source_ip):
            continue

        ports = _port_set(r.dest_port or "any")
        if _is_any(r.dest_port):
            open_admin.append(r.rule_name or f"pos-{r.rule_position}")
            continue
        if ports & _ADMIN_PORTS:
            open_admin.append(r.rule_name or f"pos-{r.rule_position}")

    if not open_admin:
        return _pass("admin_access_restricted", "Administrative ports are not openly accessible from any source.")

    names = ", ".join(open_admin[:5])
    suffix = f" (+{len(open_admin) - 5} more)" if len(open_admin) > 5 else ""
    return _fail(
        "admin_access_restricted",
        f"Admin ports exposed from ANY source in rule(s): {names}{suffix}.",
        "Restrict management access to specific trusted IPs or a jump-box subnet.",
    )


def _check_unused_rules(rules: List[FirewallRule]) -> Dict[str, Any]:
    """Flag rules with zero hit count or null last_hit."""
    unused = [r for r in rules if r.hit_count == 0 or r.last_hit is None]
    total = len(rules)

    if not unused:
        return _pass("unused_rules_count", "All rules have recorded traffic hits.")

    pct = (len(unused) / total * 100) if total else 0
    if pct <= 10:
        return _warn(
            "unused_rules_count",
            f"{len(unused)} of {total} rules ({pct:.0f}%) have zero hits — minor clean-up recommended.",
            "Review and remove or disable unused rules to reduce attack surface.",
        )

    return _fail(
        "unused_rules_count",
        f"{len(unused)} of {total} rules ({pct:.0f}%) have zero hits.",
        "Audit unused rules and decommission those that are no longer needed.",
    )


def _check_insecure_services(rules: List[FirewallRule]) -> Dict[str, Any]:
    """Insecure services (FTP, Telnet, NetBIOS, etc.) should be blocked."""
    allowed_insecure: List[str] = []
    for r in rules:
        if (r.action or "").lower() != "allow":
            continue
        ports = _port_set(r.dest_port or "any")
        if _is_any(r.dest_port):
            # any-port allow implicitly exposes insecure services
            allowed_insecure.append(r.rule_name or f"pos-{r.rule_position}")
            continue
        if ports & _INSECURE_PORTS:
            allowed_insecure.append(r.rule_name or f"pos-{r.rule_position}")

    if not allowed_insecure:
        return _pass("insecure_services_blocked", "No rules explicitly allow insecure services (FTP, Telnet, NetBIOS, etc.).")

    names = ", ".join(allowed_insecure[:5])
    suffix = f" (+{len(allowed_insecure) - 5} more)" if len(allowed_insecure) > 5 else ""
    return _fail(
        "insecure_services_blocked",
        f"Insecure service ports allowed in rule(s): {names}{suffix}.",
        "Block or replace insecure protocols with secure alternatives (SSH over Telnet, SFTP over FTP).",
    )


def _check_logging(rules: List[FirewallRule], topology: Any) -> Dict[str, Any]:
    """
    Heuristic: if no topology entry exists for the device, assume logging
    status is unknown (warning).  Otherwise pass.  A future version can
    inspect syslog / log-forwarding configuration.
    """
    if topology is not None:
        return _pass("logging_enabled", "Device is present in topology — logging assumed configured.")

    return _warn(
        "logging_enabled",
        "No topology entry for this device — cannot confirm logging configuration.",
        "Ensure logging is enabled on all firewall rules and forwarded to a SIEM.",
    )


# ---------------------------------------------------------------------------
# Result builders
# ---------------------------------------------------------------------------

def _pass(check_id: str, description: str) -> Dict[str, Any]:
    defn = next(c for c in _CHECK_DEFS if c["check_id"] == check_id)
    return {
        "check_id": check_id,
        "check_name": defn["check_name"],
        "status": "pass",
        "severity": defn["severity"],
        "description": description,
        "remediation": None,
    }


def _fail(check_id: str, description: str, remediation: str) -> Dict[str, Any]:
    defn = next(c for c in _CHECK_DEFS if c["check_id"] == check_id)
    return {
        "check_id": check_id,
        "check_name": defn["check_name"],
        "status": "fail",
        "severity": defn["severity"],
        "description": description,
        "remediation": remediation,
    }


def _warn(check_id: str, description: str, remediation: str) -> Dict[str, Any]:
    defn = next(c for c in _CHECK_DEFS if c["check_id"] == check_id)
    return {
        "check_id": check_id,
        "check_name": defn["check_name"],
        "status": "warning",
        "severity": defn["severity"],
        "description": description,
        "remediation": remediation,
    }


# ---------------------------------------------------------------------------
# Score / grade helpers
# ---------------------------------------------------------------------------

_WEIGHT_MAP = {c["check_id"]: c["weight"] for c in _CHECK_DEFS}


def _compute_score(checks: List[Dict[str, Any]]) -> float:
    """Weighted score: pass = full weight, warning = half weight, fail = 0."""
    total_weight = sum(_WEIGHT_MAP.get(c["check_id"], 0) for c in checks)
    if total_weight == 0:
        return 0.0

    earned = 0.0
    for c in checks:
        w = _WEIGHT_MAP.get(c["check_id"], 0)
        if c["status"] == "pass":
            earned += w
        elif c["status"] == "warning":
            earned += w * 0.5

    return round((earned / total_weight) * 100, 1)


def _grade_from_score(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class HardeningEngine:
    """Run a suite of hardening checks against a single device's rule-set."""

    def check_device(
        self,
        device_name: str,
        rules: List[FirewallRule],
        topology: Any = None,
    ) -> Dict[str, Any]:
        """
        Parameters
        ----------
        device_name : str
            Identifier for the device being assessed.
        rules : list[FirewallRule]
            All enabled firewall rules belonging to *device_name*.
        topology : NetworkTopology | None
            Optional topology row for the device (used by the logging check).

        Returns
        -------
        dict with keys: device_name, score, grade, checks
        """
        # Filter to only enabled rules for this device (defensive — caller
        # should already do this, but belt-and-braces).
        device_rules = [
            r for r in rules
            if r.device_name == device_name and r.is_enabled
        ]
        device_rules.sort(key=lambda r: r.rule_position or 0)

        checks: List[Dict[str, Any]] = [
            _check_default_deny(device_rules),
            _check_no_any_any_allow(device_rules),
            _check_admin_access(device_rules),
            _check_unused_rules(device_rules),
            _check_insecure_services(device_rules),
            _check_logging(device_rules, topology),
        ]

        score = _compute_score(checks)
        grade = _grade_from_score(score)

        return {
            "device_name": device_name,
            "score": score,
            "grade": grade,
            "checks": checks,
        }
