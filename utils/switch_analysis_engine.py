"""
Switch Security Analysis Engine

Evaluates Cisco IOS/IOS-XE switch configurations for security weaknesses.
Each check returns a finding dict with severity, description, and recommendation
so the frontend can display actionable results.
"""

from typing import List, Dict, Any


def analyze_switch(topo_node: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run all switch security checks against a topology node.
    Returns a full analysis report with score, grade, and findings.
    """
    findings: List[Dict[str, Any]] = []

    vlans = topo_node.get("vlans") or []
    trunk_ports = topo_node.get("trunk_ports") or []
    access_ports = topo_node.get("access_ports") or []
    port_security = topo_node.get("port_security") or []
    stp_mode = topo_node.get("stp_mode") or ""
    stp_root_for = topo_node.get("stp_root_for") or []
    acls = topo_node.get("acls") or []
    interfaces = topo_node.get("interfaces") or []

    # ── 1. VLAN Segmentation ────────────────────────────────────────────
    if len(vlans) < 3:
        findings.append({
            "check": "VLAN Segmentation",
            "severity": "high",
            "status": "fail",
            "description": f"Only {len(vlans)} VLANs configured. Flat networks allow unrestricted lateral movement.",
            "recommendation": "Segment the network into separate VLANs for servers, users, management, and guests at minimum.",
            "category": "segmentation",
        })
    else:
        findings.append({
            "check": "VLAN Segmentation",
            "severity": "info",
            "status": "pass",
            "description": f"{len(vlans)} VLANs configured providing network segmentation.",
            "recommendation": "Verify each VLAN serves a distinct security zone.",
            "category": "segmentation",
        })

    # Check for VLAN 1 usage (default VLAN is a security risk)
    vlan1_used = any(v.get("id") == 1 for v in vlans)
    access_on_vlan1 = any(p.get("vlan_id") == 1 for p in access_ports)
    if access_on_vlan1:
        findings.append({
            "check": "Default VLAN 1 Usage",
            "severity": "medium",
            "status": "fail",
            "description": "Access ports are assigned to VLAN 1 (default). Attackers target VLAN 1 for VLAN hopping attacks.",
            "recommendation": "Move all user-facing ports off VLAN 1. Use a dedicated VLAN for each user group.",
            "category": "segmentation",
        })

    # ── 2. Native VLAN Security ─────────────────────────────────────────
    trunks_with_native_1 = [t for t in trunk_ports if t.get("native_vlan") in (None, 1)]
    if trunks_with_native_1:
        findings.append({
            "check": "Native VLAN on Trunks",
            "severity": "high",
            "status": "fail",
            "description": f"{len(trunks_with_native_1)} trunk port(s) use VLAN 1 as native VLAN. "
                           "This enables double-tagging VLAN hopping attacks (IEEE 802.1Q).",
            "recommendation": "Set a dedicated unused VLAN (e.g., VLAN 999) as the native VLAN on all trunks: "
                              "`switchport trunk native vlan 999`.",
            "category": "trunk_security",
            "affected_ports": [t.get("port", "?") for t in trunks_with_native_1],
        })
    else:
        findings.append({
            "check": "Native VLAN on Trunks",
            "severity": "info",
            "status": "pass",
            "description": "All trunks use a non-default native VLAN. VLAN hopping via double-tagging is mitigated.",
            "recommendation": "Ensure the native VLAN is unused (no devices assigned to it).",
            "category": "trunk_security",
        })

    # Trunk allowed VLANs — check if any trunk allows ALL VLANs
    trunks_all_vlans = [t for t in trunk_ports if not t.get("allowed_vlans")]
    if trunks_all_vlans:
        findings.append({
            "check": "Trunk VLAN Pruning",
            "severity": "medium",
            "status": "fail",
            "description": f"{len(trunks_all_vlans)} trunk(s) allow all VLANs. Unpruned trunks expand the broadcast domain unnecessarily.",
            "recommendation": "Restrict trunks to only carry required VLANs: `switchport trunk allowed vlan <list>`.",
            "category": "trunk_security",
        })

    # ── 3. STP Security ─────────────────────────────────────────────────
    if not stp_mode:
        findings.append({
            "check": "Spanning Tree Protocol",
            "severity": "high",
            "status": "fail",
            "description": "No STP mode configured. Without STP, network loops can cause broadcast storms and outages.",
            "recommendation": "Enable Rapid PVST+ or MST: `spanning-tree mode rapid-pvst`.",
            "category": "stp_security",
        })
    elif stp_mode.lower() in ("rapid-pvst", "mst", "rstp"):
        findings.append({
            "check": "Spanning Tree Protocol",
            "severity": "info",
            "status": "pass",
            "description": f"STP mode '{stp_mode}' provides fast convergence and loop prevention.",
            "recommendation": "Ensure BPDU Guard and Root Guard are enabled on access ports.",
            "category": "stp_security",
        })
    else:
        findings.append({
            "check": "Spanning Tree Protocol",
            "severity": "low",
            "status": "warn",
            "description": f"STP mode '{stp_mode}' is legacy. Convergence is slow (30-50 seconds).",
            "recommendation": "Upgrade to Rapid PVST+ for sub-second convergence.",
            "category": "stp_security",
        })

    if not stp_root_for:
        findings.append({
            "check": "STP Root Bridge Control",
            "severity": "medium",
            "status": "fail",
            "description": "This switch is not configured as root bridge for any VLAN. "
                           "An attacker could inject a rogue switch with lower priority and become root.",
            "recommendation": "Set root bridge priority on core switches: `spanning-tree vlan <id> root primary`.",
            "category": "stp_security",
        })
    else:
        findings.append({
            "check": "STP Root Bridge Control",
            "severity": "info",
            "status": "pass",
            "description": f"Root bridge for VLANs: {', '.join(str(v) for v in stp_root_for[:10])}{'...' if len(stp_root_for) > 10 else ''}.",
            "recommendation": "Verify root bridge is on the most capable switch in the topology.",
            "category": "stp_security",
        })

    # ── 4. Port Security ────────────────────────────────────────────────
    total_access = len(access_ports)
    secured_ports = len(port_security)
    unsecured = total_access - secured_ports

    if total_access > 0 and unsecured > 0:
        pct = round(secured_ports / total_access * 100) if total_access else 0
        sev = "high" if pct < 50 else "medium" if pct < 80 else "low"
        findings.append({
            "check": "Port Security Coverage",
            "severity": sev,
            "status": "fail",
            "description": f"Only {secured_ports}/{total_access} access ports ({pct}%) have port-security enabled. "
                           f"{unsecured} ports allow unlimited MAC addresses — rogue devices can connect freely.",
            "recommendation": "Enable port-security on all access ports: `switchport port-security`, "
                              "`switchport port-security maximum 2`, `switchport port-security violation restrict`.",
            "category": "port_security",
        })
    elif total_access > 0:
        findings.append({
            "check": "Port Security Coverage",
            "severity": "info",
            "status": "pass",
            "description": f"All {total_access} access ports have port-security enabled.",
            "recommendation": "Review max MAC addresses per port — 1-2 is ideal for end-user ports.",
            "category": "port_security",
        })

    # Check for shutdown violation mode (best practice)
    non_shutdown = [ps for ps in port_security if ps.get("violation_mode") != "shutdown"]
    if non_shutdown:
        findings.append({
            "check": "Port Security Violation Mode",
            "severity": "low",
            "status": "warn",
            "description": f"{len(non_shutdown)} port(s) use '{non_shutdown[0].get('violation_mode', 'restrict')}' "
                           "instead of 'shutdown'. Restrict/protect modes log but don't disable the port.",
            "recommendation": "Use `switchport port-security violation shutdown` on critical ports to auto-disable on violation.",
            "category": "port_security",
        })

    # Sticky MAC
    sticky_ports = [ps for ps in port_security if ps.get("sticky")]
    if port_security and not sticky_ports:
        findings.append({
            "check": "Sticky MAC Learning",
            "severity": "low",
            "status": "warn",
            "description": "No ports use sticky MAC address learning. MAC addresses must be manually configured or are lost on reboot.",
            "recommendation": "Enable `switchport port-security mac-address sticky` for automatic MAC learning that persists.",
            "category": "port_security",
        })

    # ── 5. ACL Coverage ─────────────────────────────────────────────────
    if not acls:
        findings.append({
            "check": "Switch ACL Coverage",
            "severity": "medium",
            "status": "fail",
            "description": "No ACLs configured on this switch. Inter-VLAN traffic is unfiltered.",
            "recommendation": "Apply ACLs to restrict traffic between sensitive VLANs (e.g., block user VLAN from database VLAN).",
            "category": "access_control",
        })
    else:
        total_rules = sum(len(a.get("rules", [])) for a in acls)
        deny_any = sum(1 for a in acls for r in a.get("rules", []) if "deny" in r.get("action", "") and "any" in r.get("condition", ""))
        findings.append({
            "check": "Switch ACL Coverage",
            "severity": "info",
            "status": "pass",
            "description": f"{len(acls)} ACL(s) with {total_rules} rules. {deny_any} explicit deny-all rules present.",
            "recommendation": "Verify each ACL ends with an explicit deny-all to prevent unintended traffic.",
            "category": "access_control",
        })

    # ── 6. Management Security ──────────────────────────────────────────
    mgmt_svi = any(i.get("name", "").lower().startswith("vlan") and i.get("ip") for i in interfaces)
    if mgmt_svi:
        findings.append({
            "check": "Management Interface",
            "severity": "info",
            "status": "pass",
            "description": "Management SVI configured with IP address for remote administration.",
            "recommendation": "Ensure management SVI is on a dedicated management VLAN with ACL restrictions.",
            "category": "management",
        })

    # ── Score calculation ───────────────────────────────────────────────
    severity_weights = {"high": 15, "medium": 8, "low": 3, "info": 0}
    deductions = sum(severity_weights.get(f["severity"], 0) for f in findings if f["status"] != "pass")
    score = max(0, 100 - deductions)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    return {
        "device_name": topo_node.get("device_name", "unknown"),
        "device_type": "switch",
        "score": score,
        "grade": grade,
        "total_checks": len(findings),
        "passed": sum(1 for f in findings if f["status"] == "pass"),
        "failed": sum(1 for f in findings if f["status"] == "fail"),
        "warnings": sum(1 for f in findings if f["status"] == "warn"),
        "findings": findings,
        "summary": {
            "vlans": len(vlans),
            "trunk_ports": len(trunk_ports),
            "access_ports": total_access,
            "port_security_coverage": f"{round(secured_ports / total_access * 100)}%" if total_access else "N/A",
            "stp_mode": stp_mode or "none",
            "acl_count": len(acls),
        },
    }
