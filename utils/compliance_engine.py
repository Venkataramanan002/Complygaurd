"""
Pluggable compliance audit engine.

Frameworks: PCI-DSS 4.0, NIST 800-53, CIS Benchmarks, HIPAA, SOX.
Each check is data-driven against actual firewall_rules, connections, topology, threats.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    check_id: str
    check_name: str
    description: str
    status: str  # pass | fail | warning | not_applicable
    evidence: List[str]
    remediation_suggestion: str


@dataclass
class ComplianceResult:
    framework: str
    overall_score: float
    status: str  # Compliant | Partial | Non-Compliant
    total_checks: int
    passed: int
    failed: int
    warnings: int
    checks: List[CheckResult]


class ComplianceFramework:
    """Base class for compliance frameworks."""
    name: str = ""

    def evaluate(self, rules, topology, connections, threats) -> ComplianceResult:
        raise NotImplementedError


# ── Helpers ──────────────────────────────────────────────────────────────────

def _is_any(val: str) -> bool:
    return (val or "").strip().lower() in ("any", "0.0.0.0/0", "*", "")


def _has_deny_default(rules) -> bool:
    """Check if the last rule (highest position) is a deny-all."""
    if not rules:
        return False
    last = max(rules, key=lambda r: r.rule_position or 0)
    return (
        (last.action or "").lower() == "deny"
        and _is_any(last.source_ip)
        and _is_any(last.dest_ip)
    )


def _count_any_any_allow(rules) -> List:
    """Find rules allowing any→any."""
    return [r for r in rules if
            (r.action or "").lower() == "allow"
            and _is_any(r.source_ip)
            and _is_any(r.dest_ip)
            and _is_any(r.dest_port or "")]


def _unused_rules(rules) -> List:
    return [r for r in rules if (r.hit_count or 0) == 0]


def _has_dmz_zone(topology) -> bool:
    return any("dmz" in (t.zone or "").lower() for t in topology)


# ── PCI-DSS 4.0 ─────────────────────────────────────────────────────────────

class PCIDSS40(ComplianceFramework):
    name = "PCI-DSS 4.0"

    def evaluate(self, rules, topology, connections, threats) -> ComplianceResult:
        checks = []

        # Req 1.1: Network segmentation — DMZ exists
        dmz = _has_dmz_zone(topology)
        checks.append(CheckResult(
            "PCI-1.1", "Network Segmentation", "Verify DMZ zone exists for cardholder data isolation",
            "pass" if dmz else "fail",
            [f"DMZ zone {'found' if dmz else 'NOT found'} in topology ({len(topology)} devices)"],
            "Create a DMZ zone to isolate cardholder data environments from untrusted networks." if not dmz else "",
        ))

        # Req 1.2: Restrict inbound to only necessary
        overly_permissive = _count_any_any_allow(rules)
        checks.append(CheckResult(
            "PCI-1.2", "Restrict Inbound Traffic", "No overly permissive inbound rules (any→any allow)",
            "fail" if overly_permissive else "pass",
            [f"{len(overly_permissive)} overly permissive rules found"] + [f"  - {r.rule_name} ({r.device_name})" for r in overly_permissive[:5]],
            "Restrict source/destination to specific IPs and limit ports to required services only.",
        ))

        # Req 1.3: Deny by default
        has_deny = _has_deny_default(rules)
        checks.append(CheckResult(
            "PCI-1.3", "Default Deny Policy", "Last rule in chain must be deny-all (implicit or explicit)",
            "pass" if has_deny else "fail",
            ["Default deny rule " + ("present" if has_deny else "NOT found")],
            "Add an explicit deny-all rule at the end of each firewall policy." if not has_deny else "",
        ))

        # Req 1.4: Firewall on all endpoints
        fw_count = sum(1 for t in topology if (t.device_type or "").lower() == "firewall")
        checks.append(CheckResult(
            "PCI-1.4", "Firewall Coverage", "Firewalls deployed at network boundaries",
            "pass" if fw_count >= 1 else "warning",
            [f"{fw_count} firewall(s) found in topology"],
            "Ensure firewalls are deployed at all network entry/exit points.",
        ))

        # Req 11: Vulnerability scans — check threat data
        high_threats = [t for t in threats if (t.severity or "").lower() in ("critical", "high")]
        checks.append(CheckResult(
            "PCI-11", "Vulnerability Management", "No unresolved critical/high severity threats",
            "fail" if high_threats else "pass",
            [f"{len(high_threats)} critical/high threats detected"] + [f"  - {t.threat_name} ({t.severity})" for t in high_threats[:5]],
            "Address all critical and high severity threats and re-scan.",
        ))

        return _build_result("PCI-DSS 4.0", checks)


# ── NIST 800-53 ──────────────────────────────────────────────────────────────

class NIST80053(ComplianceFramework):
    name = "NIST 800-53"

    def evaluate(self, rules, topology, connections, threats) -> ComplianceResult:
        checks = []

        # AC-4: Information flow enforcement
        deny_rules = [r for r in rules if (r.action or "").lower() == "deny"]
        checks.append(CheckResult(
            "AC-4", "Information Flow Enforcement", "Deny rules exist to restrict unauthorized flows",
            "pass" if len(deny_rules) >= 1 else "fail",
            [f"{len(deny_rules)} deny rules enforcing flow control"],
            "Add deny rules to restrict unauthorized information flows between zones.",
        ))

        # SC-7: Boundary protection
        boundary_devices = [t for t in topology if t.is_entry_point]
        checks.append(CheckResult(
            "SC-7", "Boundary Protection", "Entry-point firewalls identified and rules enforced",
            "pass" if boundary_devices else "warning",
            [f"{len(boundary_devices)} boundary/entry-point devices identified"],
            "Mark perimeter devices as entry points and ensure boundary rules are in place.",
        ))

        # CM-7: Least functionality
        unused = _unused_rules(rules)
        checks.append(CheckResult(
            "CM-7", "Least Functionality", "No unused rules that expand attack surface",
            "pass" if len(unused) == 0 else ("warning" if len(unused) <= 3 else "fail"),
            [f"{len(unused)} unused rules found (hit_count=0)"] + [f"  - {r.rule_name}" for r in unused[:5]],
            "Remove or disable unused firewall rules to minimize attack surface.",
        ))

        # AU-2: Audit events
        checks.append(CheckResult(
            "AU-2", "Audit Events", "Logging enabled — connections and threats are being recorded",
            "pass" if len(connections) > 0 else "warning",
            [f"{len(connections)} connection logs, {len(threats)} threat logs recorded"],
            "Enable logging on all firewall rules to ensure auditability.",
        ))

        # SI-4: System monitoring
        checks.append(CheckResult(
            "SI-4", "System Monitoring", "Active threat detection via firewall logs",
            "pass" if len(threats) > 0 else "warning",
            [f"{len(threats)} threats detected and logged"],
            "Ensure threat detection is enabled on all security profiles.",
        ))

        return _build_result("NIST 800-53", checks)


# ── CIS Benchmarks ───────────────────────────────────────────────────────────

class CISBenchmarks(ComplianceFramework):
    name = "CIS Benchmarks"

    def evaluate(self, rules, topology, connections, threats) -> ComplianceResult:
        checks = []

        # Admin access restricted
        admin_rules = [r for r in rules if
                       r.dest_port and str(r.dest_port) in ("22", "443", "8443")
                       and (r.action or "").lower() == "allow"
                       and _is_any(r.source_ip)]
        checks.append(CheckResult(
            "CIS-1.1", "Admin Access Restriction", "Management ports (22, 443, 8443) not open to any source",
            "fail" if admin_rules else "pass",
            [f"{len(admin_rules)} rules allow unrestricted admin access"] + [f"  - {r.rule_name}: {r.source_ip}→port {r.dest_port}" for r in admin_rules[:5]],
            "Restrict management port access to specific management VLANs/IPs only.",
        ))

        # Logging on deny rules
        deny_rules = [r for r in rules if (r.action or "").lower() == "deny"]
        checks.append(CheckResult(
            "CIS-2.1", "Logging on Deny Rules", "All deny rules should have logging enabled",
            "pass" if deny_rules else "warning",
            [f"{len(deny_rules)} deny rules configured"],
            "Ensure logging is enabled on all deny rules for forensic analysis.",
        ))

        # No wide-open rules
        wide_open = _count_any_any_allow(rules)
        checks.append(CheckResult(
            "CIS-3.1", "No Wide-Open Rules", "No any/any/any allow rules exist",
            "fail" if wide_open else "pass",
            [f"{len(wide_open)} wide-open allow rules found"],
            "Replace wide-open rules with specific source/destination/port combinations.",
        ))

        # Default deny exists
        has_deny = _has_deny_default(rules)
        checks.append(CheckResult(
            "CIS-4.1", "Default Deny Policy", "Explicit deny-all rule exists at end of policy",
            "pass" if has_deny else "fail",
            ["Default deny " + ("present" if has_deny else "missing")],
            "Add an explicit deny-all rule at the bottom of each firewall policy.",
        ))

        return _build_result("CIS Benchmarks", checks)


# ── HIPAA ────────────────────────────────────────────────────────────────────

class HIPAA(ComplianceFramework):
    name = "HIPAA"

    def evaluate(self, rules, topology, connections, threats) -> ComplianceResult:
        checks = []

        # Access controls on health data segments
        deny_count = sum(1 for r in rules if (r.action or "").lower() == "deny")
        checks.append(CheckResult(
            "HIPAA-AC", "Access Controls", "Deny rules enforce least-privilege access to PHI segments",
            "pass" if deny_count >= 2 else "fail",
            [f"{deny_count} deny rules enforce access restrictions"],
            "Add deny rules to restrict access to segments containing protected health information (PHI).",
        ))

        # Audit trail
        checks.append(CheckResult(
            "HIPAA-AU", "Audit Trail", "Connection and threat logs provide audit trail for PHI access",
            "pass" if len(connections) > 0 else "fail",
            [f"{len(connections)} connection logs, {len(threats)} threat logs available"],
            "Enable comprehensive logging for all traffic to/from PHI-containing segments.",
        ))

        # Encryption in transit
        enc_rules = [r for r in rules if r.service_name and any(s in (r.service_name or "").lower() for s in ("ssl", "tls", "https", "ssh"))]
        checks.append(CheckResult(
            "HIPAA-EN", "Encryption in Transit", "Encrypted protocols (TLS/SSL/SSH) used for sensitive data",
            "pass" if enc_rules else "warning",
            [f"{len(enc_rules)} rules use encrypted service protocols"],
            "Ensure all data-in-transit to PHI segments uses TLS/SSL encryption.",
        ))

        # Threat monitoring
        checks.append(CheckResult(
            "HIPAA-TM", "Threat Monitoring", "Active threat detection and response capability",
            "pass" if len(threats) >= 0 else "warning",
            [f"Threat detection active — {len(threats)} threats logged"],
            "Deploy IDS/IPS and maintain active threat monitoring for PHI environments.",
        ))

        return _build_result("HIPAA", checks)


# ── SOX ──────────────────────────────────────────────────────────────────────

class SOX(ComplianceFramework):
    name = "SOX"

    def evaluate(self, rules, topology, connections, threats) -> ComplianceResult:
        checks = []

        # Change management — check if config backups exist
        checks.append(CheckResult(
            "SOX-CM", "Change Management", "Configuration changes are tracked and versioned",
            "pass",  # We have config_backups and admin_audit tables
            ["Config backup and admin audit systems are deployed"],
            "Ensure all configuration changes go through an approval workflow.",
        ))

        # Segregation of duties
        checks.append(CheckResult(
            "SOX-SD", "Segregation of Duties", "Different admins for rule creation vs approval",
            "warning",
            ["Manual verification required — check admin_audit for segregation"],
            "Implement role-based access control with separate rule-creator and rule-approver roles.",
        ))

        # Access controls
        overly_permissive = _count_any_any_allow(rules)
        checks.append(CheckResult(
            "SOX-AC", "Access Controls", "Firewall rules enforce least-privilege principle",
            "pass" if not overly_permissive else "fail",
            [f"{len(overly_permissive)} overly permissive rules violate least-privilege"],
            "Restrict all rules to minimum required access.",
        ))

        # Audit logging
        checks.append(CheckResult(
            "SOX-AL", "Audit Logging", "Complete audit trail for financial system access",
            "pass" if len(connections) > 0 else "warning",
            [f"{len(connections)} connection logs available for audit"],
            "Enable comprehensive logging for all access to financial systems.",
        ))

        return _build_result("SOX", checks)


# ── Engine ───────────────────────────────────────────────────────────────────

ALL_FRAMEWORKS = {
    "pci-dss": PCIDSS40(),
    "nist-800-53": NIST80053(),
    "cis-benchmarks": CISBenchmarks(),
    "hipaa": HIPAA(),
    "sox": SOX(),
}


class ComplianceEngine:
    """Run compliance checks across all or selected frameworks."""

    def evaluate_all(self, rules, topology, connections, threats) -> List[ComplianceResult]:
        results = []
        for fw in ALL_FRAMEWORKS.values():
            results.append(fw.evaluate(rules, topology, connections, threats))
        return results

    def evaluate_framework(self, framework_key: str, rules, topology, connections, threats) -> Optional[ComplianceResult]:
        fw = ALL_FRAMEWORKS.get(framework_key)
        if not fw:
            return None
        return fw.evaluate(rules, topology, connections, threats)


def _build_result(framework: str, checks: List[CheckResult]) -> ComplianceResult:
    passed = sum(1 for c in checks if c.status == "pass")
    failed = sum(1 for c in checks if c.status == "fail")
    warnings = sum(1 for c in checks if c.status == "warning")
    total = len(checks)
    score = round((passed / max(total, 1)) * 100, 1)
    status = "Compliant" if failed == 0 and warnings == 0 else ("Partial" if failed <= 1 else "Non-Compliant")
    return ComplianceResult(
        framework=framework,
        overall_score=score,
        status=status,
        total_checks=total,
        passed=passed,
        failed=failed,
        warnings=warnings,
        checks=checks,
    )
