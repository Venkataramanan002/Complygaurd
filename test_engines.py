"""Golden tests for the analysis core: parsers + risk engine.

Runs against the checked-in sample configs with frozen expected values, so a
regression in parsing or scoring fails loudly. No DB or server needed:
    .venv/Scripts/python.exe -m pytest test_engines.py -q
"""

from pathlib import Path

import pytest

from database.models import FirewallRule
from parsers.config_parsers import PaloAltoXMLParser
from parsers.router_parser import CiscoRouterParser
from parsers.switch_parser import CiscoSwitchParser
from utils.risk_engine import calculate_rule_risk

SAMPLES = Path(__file__).parent / "sample_data"

VULN_PORTS = {
    23:   {"service": "Telnet", "risk": "critical", "reason": "Unencrypted remote access"},
    445:  {"service": "SMB",    "risk": "high",     "reason": "Ransomware vector"},
    3389: {"service": "RDP",    "risk": "high",     "reason": "Brute-force target"},
}


@pytest.fixture(scope="module")
def pa_content() -> str:
    return (SAMPLES / "fortress_enterprise_fw.xml").read_text(encoding="utf-8")


def test_paloalto_parser_golden(pa_content):
    parser = PaloAltoXMLParser()
    rules = parser.parse_rules(pa_content)
    zones = parser.parse_topology(pa_content)

    assert len(rules) == 83
    assert len(zones) == 15
    assert sum(1 for z in zones if z["is_entry_point"]) == 2
    for r in rules:
        assert r["rule_name"], "every rule needs a name"
        assert r["action"] in ("allow", "deny", "drop", "reject")


def test_risk_engine_golden(pa_content):
    rules = PaloAltoXMLParser().parse_rules(pa_content)
    frs = [FirewallRule(**{**r, "device_name": "test-fw"}) for r in rules]
    results = [calculate_rule_risk(fr, frs, VULN_PORTS) for fr in frs]

    scores = [r["risk_score"] for r in results]
    assert all(0 <= s <= 10 for s in scores)
    assert min(scores) == 1.0
    assert max(scores) == 6.5
    assert sum(1 for s in scores if s >= 6) == 1
    assert {r["risk_level"] for r in results} == {"low", "medium", "high"}
    for r in results:
        assert r["reason"], "every scored rule needs an explanation"


def test_risk_engine_monotonic():
    """An any→any allow rule must always outscore a tightly-scoped one."""
    wide = FirewallRule(
        device_name="t", rule_name="wide", rule_position=1,
        source_ip="any", dest_ip="any", dest_port="any",
        protocol="any", action="allow", is_enabled=True,
    )
    tight = FirewallRule(
        device_name="t", rule_name="tight", rule_position=2,
        source_ip="10.0.0.5/32", dest_ip="10.0.1.9/32", dest_port="443",
        protocol="tcp", action="allow", is_enabled=True,
    )
    all_rules = [wide, tight]
    wide_score = calculate_rule_risk(wide, all_rules, VULN_PORTS)["risk_score"]
    tight_score = calculate_rule_risk(tight, all_rules, VULN_PORTS)["risk_score"]
    assert wide_score > tight_score


def test_switch_parser_golden():
    content = (SAMPLES / "switch_core_01.conf").read_text(encoding="utf-8")
    result = CiscoSwitchParser().parse(content)
    assert result["device_name"]
    assert len(result["vlans"]) > 0
    assert len(result["interfaces"]) > 0


def test_router_parser_golden():
    content = (SAMPLES / "router_core_01.conf").read_text(encoding="utf-8")
    result = CiscoRouterParser().parse(content)
    assert result["device_name"]
    assert len(result["interfaces"]) > 0
    assert result["routing_protocol"]
