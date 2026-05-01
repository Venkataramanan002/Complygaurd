"""
utils/simulation_engine.py
What-if rule simulation engine.

Evaluates the impact of adding a proposed firewall rule *before* it is
committed, detecting risk changes, shadow/conflict anomalies, and producing
a human-readable verdict.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import FirewallRule
from utils.risk_engine import calculate_rule_risk
from utils.rule_anomaly_engine import RuleAnomalyEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known vulnerable ports (mirrors risk_engine.py)
# ---------------------------------------------------------------------------
VULNERABLE_PORTS: Dict[int, Dict[str, str]] = {
    21:   {"service": "FTP",      "risk": "Credentials sent in cleartext"},
    23:   {"service": "Telnet",   "risk": "Credentials sent in cleartext"},
    445:  {"service": "SMB",      "risk": "Ransomware / lateral-movement vector"},
    3389: {"service": "RDP",      "risk": "Brute-force / BlueKeep exploits"},
    1433: {"service": "MSSQL",    "risk": "Database exposure"},
    3306: {"service": "MySQL",    "risk": "Database exposure"},
    5432: {"service": "Postgres", "risk": "Database exposure"},
}


# ---------------------------------------------------------------------------
# Simulation result typing
# ---------------------------------------------------------------------------

class SimulationResult(dict):
    """
    A dict subclass for IDE auto-complete.  Keys:

    - risk_score_after : float   — risk score of the proposed rule
    - risk_delta       : float   — change vs. current avg device risk
    - verdict          : str     — "safe" | "warning" | "dangerous"
    - shadows          : list    — rules that shadow the proposed rule
    - conflicts        : list    — rules that conflict with the proposed rule
    - explanation      : str     — human-readable summary
    """


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class RuleSimulator:
    """Simulate the impact of adding a proposed rule to a device."""

    def __init__(self) -> None:
        self._anomaly_engine = RuleAnomalyEngine()

    async def simulate_add_rule(
        self,
        proposed_rule_dict: Dict[str, Any],
        device_name: str,
        db_session: AsyncSession,
    ) -> SimulationResult:
        """
        Parameters
        ----------
        proposed_rule_dict : dict
            Must contain at least: source_ip, dest_ip, dest_port, protocol,
            action.  Optional: rule_name, source_port, service_name.
        device_name : str
            The device the rule would be added to.
        db_session : AsyncSession
            Active database session for reading existing rules.

        Returns
        -------
        SimulationResult (dict) with keys listed in the class docstring.
        """
        # ------------------------------------------------------------------
        # 1.  Load existing rules for the device
        # ------------------------------------------------------------------
        result = await db_session.execute(
            select(FirewallRule).where(
                FirewallRule.device_name == device_name,
                FirewallRule.is_enabled == True,
            )
        )
        existing_rules: List[FirewallRule] = list(result.scalars().all())
        existing_rules.sort(key=lambda r: r.rule_position or 0)

        # ------------------------------------------------------------------
        # 2.  Build a transient FirewallRule for the proposed change
        # ------------------------------------------------------------------
        max_pos = max((r.rule_position or 0 for r in existing_rules), default=0)
        proposed = FirewallRule(
            id=str(uuid.uuid4()),
            device_name=device_name,
            rule_name=proposed_rule_dict.get("rule_name", "proposed-rule"),
            rule_position=proposed_rule_dict.get("rule_position", max_pos + 1),
            source_ip=proposed_rule_dict.get("source_ip", "any"),
            source_port=proposed_rule_dict.get("source_port", "any"),
            dest_ip=proposed_rule_dict.get("dest_ip", "any"),
            dest_port=proposed_rule_dict.get("dest_port", "any"),
            protocol=proposed_rule_dict.get("protocol", "any"),
            action=proposed_rule_dict.get("action", "allow"),
            service_name=proposed_rule_dict.get("service_name"),
            hit_count=0,
            last_hit=None,
            is_enabled=True,
        )

        # ------------------------------------------------------------------
        # 3.  Risk scoring — proposed rule in context of all rules
        # ------------------------------------------------------------------
        all_rules = existing_rules + [proposed]
        proposed_risk = calculate_rule_risk(proposed, all_rules, VULNERABLE_PORTS)
        risk_score_after: float = proposed_risk["risk_score"]

        # Compute current average device risk for delta calculation
        if existing_rules:
            existing_scores = [
                calculate_rule_risk(r, existing_rules, VULNERABLE_PORTS)["risk_score"]
                for r in existing_rules
            ]
            avg_existing = sum(existing_scores) / len(existing_scores)
        else:
            avg_existing = 0.0

        risk_delta = round(risk_score_after - avg_existing, 2)

        # ------------------------------------------------------------------
        # 4.  Anomaly detection — shadows & conflicts
        # ------------------------------------------------------------------
        anomalies = self._anomaly_engine.analyze(all_rules, device_name=device_name)

        shadows: List[Dict[str, Any]] = []
        conflicts: List[Dict[str, Any]] = []

        for a in anomalies:
            entry = asdict(a)
            # Only report anomalies that involve the proposed rule
            if a.rule_id == proposed.id or a.conflicting_rule_id == proposed.id:
                if a.anomaly_type == "shadow":
                    shadows.append(entry)
                elif a.anomaly_type in ("overlap", "redundant", "duplicate"):
                    conflicts.append(entry)

        # ------------------------------------------------------------------
        # 5.  Verdict
        # ------------------------------------------------------------------
        verdict = _determine_verdict(risk_score_after, shadows, conflicts)

        # ------------------------------------------------------------------
        # 6.  Explanation
        # ------------------------------------------------------------------
        explanation = _build_explanation(
            proposed_rule_dict,
            device_name,
            risk_score_after,
            risk_delta,
            verdict,
            shadows,
            conflicts,
        )

        return SimulationResult(
            risk_score_after=risk_score_after,
            risk_delta=risk_delta,
            verdict=verdict,
            shadows=shadows,
            conflicts=conflicts,
            explanation=explanation,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _determine_verdict(
    risk_score: float,
    shadows: List[Dict],
    conflicts: List[Dict],
) -> str:
    """Classify the overall result of the simulation."""
    if risk_score >= 7.0 or any(
        c.get("severity") == "critical" for c in conflicts
    ):
        return "dangerous"

    if (
        risk_score >= 4.0
        or shadows
        or any(c.get("severity") in ("high", "critical") for c in conflicts)
    ):
        return "warning"

    return "safe"


def _build_explanation(
    proposed: Dict[str, Any],
    device_name: str,
    risk_score: float,
    risk_delta: float,
    verdict: str,
    shadows: List[Dict],
    conflicts: List[Dict],
) -> str:
    """Produce a concise human-readable summary."""
    parts: List[str] = []

    action = proposed.get("action", "allow").upper()
    src = proposed.get("source_ip", "any")
    dst = proposed.get("dest_ip", "any")
    port = proposed.get("dest_port", "any")
    proto = proposed.get("protocol", "any")

    parts.append(
        f"Proposed rule: {action} {proto.upper()} {src} -> {dst}:{port} on device '{device_name}'."
    )

    delta_direction = "increase" if risk_delta > 0 else "decrease" if risk_delta < 0 else "no change"
    parts.append(
        f"Risk score: {risk_score}/10 ({delta_direction} of {abs(risk_delta)} vs. device average)."
    )

    if shadows:
        names = ", ".join(
            s.get("conflicting_rule_name", "unknown") for s in shadows[:3]
        )
        parts.append(f"Shadowed by existing rule(s): {names}.")

    if conflicts:
        names = ", ".join(
            c.get("conflicting_rule_name", c.get("rule_name", "unknown"))
            for c in conflicts[:3]
        )
        parts.append(f"Conflicts/overlaps with: {names}.")

    verdict_label = {
        "safe": "SAFE — rule can be added with low risk.",
        "warning": "WARNING — review recommended before deployment.",
        "dangerous": "DANGEROUS — rule introduces significant risk; do not deploy without mitigation.",
    }
    parts.append(f"Verdict: {verdict_label.get(verdict, verdict)}")

    return " ".join(parts)
