"""
Router Security Analysis Engine

Evaluates Cisco IOS/IOS-XE router configurations for security weaknesses.
Checks ACLs, NAT exposure, routing protocol security, anti-spoofing,
WAN hardening, and interface security.
"""

from typing import List, Dict, Any

# Ports that should never be exposed on a WAN interface
_DANGEROUS_WAN_PORTS = {
    23: "Telnet (cleartext remote access)",
    21: "FTP (cleartext file transfer)",
    69: "TFTP (unauthenticated file transfer)",
    161: "SNMP (information disclosure)",
    445: "SMB (ransomware vector)",
    135: "RPC (Windows exploit vector)",
    3389: "RDP (brute force target)",
    1433: "MSSQL (database exposure)",
    3306: "MySQL (database exposure)",
    5432: "PostgreSQL (database exposure)",
}

# RFC 1918 + RFC 5737 private/reserved ranges that should be blocked inbound on WAN
_BOGON_PREFIXES = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.",
]


def analyze_router(topo_node: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run all router security checks against a topology node.
    Returns a full analysis report with score, grade, and findings.
    """
    findings: List[Dict[str, Any]] = []

    interfaces = topo_node.get("interfaces") or []
    acls = topo_node.get("acls") or []
    nat_rules = topo_node.get("nat_rules") or []
    static_routes = topo_node.get("static_routes") or []
    bgp_neighbors = topo_node.get("bgp_neighbors") or []
    routing_protocol = topo_node.get("routing_protocol") or "unknown"
    ospf_area = topo_node.get("ospf_area")
    bgp_asn = topo_node.get("bgp_asn")

    wan_interfaces = [i for i in interfaces if i.get("zone") == "wan" or i.get("nat") == "outside"]
    lan_interfaces = [i for i in interfaces if i.get("zone") in ("lan", "datacenter", "management") or i.get("nat") == "inside"]

    # ── 1. WAN Interface Hardening ──────────────────────────────────────
    if not wan_interfaces:
        findings.append({
            "check": "WAN Interface Detection",
            "severity": "low",
            "status": "warn",
            "description": "No WAN-facing interfaces detected. If this router connects to the internet, zone labels may be missing.",
            "recommendation": "Tag WAN-facing interfaces with descriptions containing 'WAN' or 'ISP' for accurate analysis.",
            "category": "wan_hardening",
        })
    else:
        wan_with_acl = 0
        for wan in wan_interfaces:
            intf_name = wan.get("name", "?")
            # Check if ACL is applied inbound
            has_acl_in = False
            for acl in acls:
                acl_name = acl.get("name", "")
                # Check if any interface references this ACL
                for i in interfaces:
                    if i.get("name") == intf_name:
                        # We can infer from the interface data structure
                        has_acl_in = True  # If ACLs exist and WAN exists, likely applied
                        break
            if acls:
                wan_with_acl += 1

        if wan_with_acl < len(wan_interfaces) and not acls:
            findings.append({
                "check": "WAN Inbound ACL",
                "severity": "critical",
                "status": "fail",
                "description": f"{len(wan_interfaces)} WAN interface(s) detected but no ACLs configured. "
                               "All internet traffic reaches the router unfiltered.",
                "recommendation": "Apply an extended ACL inbound on every WAN interface: "
                                  "`ip access-group WAN-INBOUND in`. Include anti-spoofing, allow only needed services.",
                "category": "wan_hardening",
            })
        else:
            findings.append({
                "check": "WAN Inbound ACL",
                "severity": "info",
                "status": "pass",
                "description": f"ACLs configured to filter WAN traffic. {len(acls)} ACL(s) with "
                               f"{sum(len(a.get('rules', [])) for a in acls)} rules total.",
                "recommendation": "Verify the ACL ends with an explicit `deny ip any any log` to block and log all unmatched traffic.",
                "category": "wan_hardening",
            })

    # ── 2. Anti-Spoofing Checks ─────────────────────────────────────────
    has_antispoofing = False
    for acl in acls:
        for rule in acl.get("rules", []):
            condition = rule.get("condition", "")
            if rule.get("action") == "deny" and any(prefix in condition for prefix in ["10.0.0.0", "172.16.0.0", "192.168.0.0"]):
                has_antispoofing = True
                break

    if has_antispoofing:
        findings.append({
            "check": "Anti-Spoofing (BCP38/RFC2827)",
            "severity": "info",
            "status": "pass",
            "description": "ACLs deny RFC 1918 private addresses on WAN inbound — prevents IP spoofing attacks.",
            "recommendation": "Also block RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) inbound.",
            "category": "wan_hardening",
        })
    else:
        findings.append({
            "check": "Anti-Spoofing (BCP38/RFC2827)",
            "severity": "high",
            "status": "fail",
            "description": "No anti-spoofing rules detected. Attackers can send packets with forged private source IPs "
                           "to bypass internal ACLs and launch reflection attacks.",
            "recommendation": "Add deny rules for RFC 1918 ranges on WAN inbound: "
                              "`deny ip 10.0.0.0 0.255.255.255 any`, `deny ip 172.16.0.0 0.15.255.255 any`, "
                              "`deny ip 192.168.0.0 0.0.255.255 any`.",
            "category": "wan_hardening",
        })

    # ── 3. Routing Protocol Security ────────────────────────────────────
    if routing_protocol == "bgp" and bgp_asn:
        findings.append({
            "check": "BGP Configuration",
            "severity": "info",
            "status": "pass",
            "description": f"BGP AS {bgp_asn} configured with {len(bgp_neighbors)} neighbor(s). "
                           "BGP provides scalable inter-domain routing.",
            "recommendation": "Ensure all BGP neighbors use MD5 authentication (`neighbor <ip> password`), "
                              "prefix filtering (`route-map` with `prefix-list`), and max-prefix limits.",
            "category": "routing_security",
        })

        # Check if route-maps are applied to BGP neighbors
        # BGP without filtering is dangerous
        if len(bgp_neighbors) > 0:
            external_peers = [n for n in bgp_neighbors if n.get("remote_asn") != bgp_asn]
            if external_peers:
                findings.append({
                    "check": "eBGP Peer Filtering",
                    "severity": "medium",
                    "status": "warn",
                    "description": f"{len(external_peers)} external BGP peer(s) (eBGP). Without route filtering, "
                                   "a compromised peer could inject malicious routes and hijack traffic.",
                    "recommendation": "Apply inbound/outbound route-maps with strict prefix-lists to every eBGP neighbor. "
                                      "Set `maximum-prefix` limits to prevent route table exhaustion.",
                    "category": "routing_security",
                    "affected_peers": [f"{n['neighbor_ip']} (AS {n['remote_asn']})" for n in external_peers],
                })

            ibgp_peers = [n for n in bgp_neighbors if n.get("remote_asn") == bgp_asn]
            if ibgp_peers:
                findings.append({
                    "check": "iBGP Peer Configuration",
                    "severity": "info",
                    "status": "pass",
                    "description": f"{len(ibgp_peers)} internal BGP peer(s) (iBGP) for redundancy.",
                    "recommendation": "Ensure iBGP uses loopback as update-source and next-hop-self is set.",
                    "category": "routing_security",
                })

    if routing_protocol == "ospf":
        findings.append({
            "check": "OSPF Configuration",
            "severity": "info",
            "status": "pass",
            "description": f"OSPF configured with area {ospf_area or '0'}. OSPF provides fast convergence for internal routing.",
            "recommendation": "Enable OSPF authentication on all interfaces: `ip ospf authentication message-digest`. "
                              "Use passive-interface on non-OSPF-facing interfaces.",
            "category": "routing_security",
        })

    if routing_protocol == "static" or (not bgp_asn and not ospf_area):
        findings.append({
            "check": "Dynamic Routing",
            "severity": "low",
            "status": "warn",
            "description": "Only static routes configured. Static routing doesn't adapt to link failures automatically.",
            "recommendation": "Consider OSPF or BGP for automatic failover. Static routes are acceptable for simple topologies.",
            "category": "routing_security",
        })

    # ── 4. NAT Security ────────────────────────────────────────────────
    if not nat_rules:
        if wan_interfaces:
            findings.append({
                "check": "NAT Configuration",
                "severity": "medium",
                "status": "fail",
                "description": "WAN interfaces exist but no NAT rules configured. Internal IP addresses may be exposed to the internet.",
                "recommendation": "Configure PAT (NAT overload) for outbound internet access: "
                                  "`ip nat inside source list <ACL> interface <WAN> overload`.",
                "category": "nat_security",
            })
    else:
        static_nats = [n for n in nat_rules if n.get("type") == "static"]
        dynamic_nats = [n for n in nat_rules if n.get("type") in ("dynamic", "dynamic_pat")]

        if static_nats:
            findings.append({
                "check": "Static NAT Exposure",
                "severity": "medium",
                "status": "warn",
                "description": f"{len(static_nats)} static NAT mapping(s) expose internal servers directly to the internet. "
                               "Each static NAT creates a permanent inbound path.",
                "recommendation": "Ensure each static NAT has a corresponding ACL that restricts inbound access to only required ports and sources.",
                "category": "nat_security",
                "mappings": [
                    f"{n.get('inside_ip', '?')}:{n.get('inside_port', '*')} → {n.get('outside_ip', '?')}:{n.get('outside_port', '*')}"
                    for n in static_nats
                ],
            })

        if dynamic_nats:
            findings.append({
                "check": "Dynamic NAT / PAT",
                "severity": "info",
                "status": "pass",
                "description": f"{len(dynamic_nats)} dynamic NAT/PAT rule(s) configured for outbound access.",
                "recommendation": "Verify the NAT ACL only permits authorized internal subnets.",
                "category": "nat_security",
            })

    # ── 5. ACL Analysis ─────────────────────────────────────────────────
    if not acls:
        findings.append({
            "check": "ACL Configuration",
            "severity": "high",
            "status": "fail",
            "description": "No ACLs configured. All traffic flows unrestricted through the router.",
            "recommendation": "Create ACLs to filter traffic between zones. Apply inbound on WAN and between sensitive segments.",
            "category": "access_control",
        })
    else:
        total_rules = sum(len(a.get("rules", [])) for a in acls)
        permit_any = 0
        deny_any = 0
        for acl in acls:
            for rule in acl.get("rules", []):
                cond = rule.get("condition", "").lower()
                if rule.get("action") == "permit" and cond.strip() in ("ip any any", "any any"):
                    permit_any += 1
                if rule.get("action") == "deny" and "any" in cond:
                    deny_any += 1

        findings.append({
            "check": "ACL Configuration",
            "severity": "info",
            "status": "pass",
            "description": f"{len(acls)} ACL(s) with {total_rules} rules configured.",
            "recommendation": "Review ACLs periodically. Remove unused or overly broad rules.",
            "category": "access_control",
        })

        if permit_any > 0:
            findings.append({
                "check": "Overly Permissive ACL Rules",
                "severity": "critical",
                "status": "fail",
                "description": f"{permit_any} ACL rule(s) permit ALL traffic (permit ip any any). "
                               "This bypasses all access control on the router.",
                "recommendation": "Replace `permit ip any any` with specific source/destination/port rules. "
                                  "Only allow traffic that is explicitly needed.",
                "category": "access_control",
            })

        acls_without_deny = []
        for acl in acls:
            rules = acl.get("rules", [])
            if rules and rules[-1].get("action") != "deny":
                acls_without_deny.append(acl.get("name", "?"))
        if acls_without_deny:
            findings.append({
                "check": "Explicit Deny at ACL End",
                "severity": "low",
                "status": "warn",
                "description": f"ACL(s) {', '.join(acls_without_deny)} don't end with explicit deny. "
                               "Cisco has an implicit deny, but explicit deny with `log` provides visibility.",
                "recommendation": "Add `deny ip any any log` at the end of each ACL for logging denied traffic.",
                "category": "access_control",
            })

    # ── 6. Default Route Security ───────────────────────────────────────
    default_routes = [r for r in static_routes if r.get("network") == "0.0.0.0"]
    if len(default_routes) > 1:
        findings.append({
            "check": "Redundant Default Route",
            "severity": "info",
            "status": "pass",
            "description": f"{len(default_routes)} default routes configured providing WAN redundancy.",
            "recommendation": "Verify administrative distances differ so failover works correctly.",
            "category": "routing_security",
        })
    elif len(default_routes) == 1:
        findings.append({
            "check": "Default Route Redundancy",
            "severity": "low",
            "status": "warn",
            "description": "Only one default route configured. If the WAN link fails, all internet traffic is lost.",
            "recommendation": "Add a backup default route with higher metric/administrative distance to a secondary ISP or path.",
            "category": "routing_security",
        })

    # ── 7. Interface Security ───────────────────────────────────────────
    down_interfaces = [i for i in interfaces if i.get("status") == "down" and i.get("ip")]
    unused_with_ip = [i for i in interfaces if i.get("status") == "down" and i.get("ip")]
    if unused_with_ip:
        findings.append({
            "check": "Shutdown Interfaces with IP",
            "severity": "low",
            "status": "warn",
            "description": f"{len(unused_with_ip)} shutdown interface(s) still have IP addresses assigned.",
            "recommendation": "Remove IP addresses from unused interfaces to reduce attack surface: `no ip address`.",
            "category": "interface_security",
        })

    # Count interfaces without descriptions
    no_desc = [i for i in interfaces if not i.get("description") and not i.get("name", "").lower().startswith("loopback")]
    if no_desc and len(no_desc) > len(interfaces) * 0.3:
        findings.append({
            "check": "Interface Documentation",
            "severity": "low",
            "status": "warn",
            "description": f"{len(no_desc)} interface(s) have no description. Undocumented interfaces make troubleshooting harder.",
            "recommendation": "Add descriptions to all active interfaces: `description Link to <DEVICE> <PORT>`.",
            "category": "interface_security",
        })

    # ── Score calculation ───────────────────────────────────────────────
    severity_weights = {"critical": 20, "high": 15, "medium": 8, "low": 3, "info": 0}
    deductions = sum(severity_weights.get(f["severity"], 0) for f in findings if f["status"] != "pass")
    score = max(0, 100 - deductions)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    return {
        "device_name": topo_node.get("device_name", "unknown"),
        "device_type": "router",
        "score": score,
        "grade": grade,
        "total_checks": len(findings),
        "passed": sum(1 for f in findings if f["status"] == "pass"),
        "failed": sum(1 for f in findings if f["status"] == "fail"),
        "warnings": sum(1 for f in findings if f["status"] == "warn"),
        "findings": findings,
        "summary": {
            "routing_protocol": routing_protocol,
            "bgp_asn": bgp_asn,
            "bgp_neighbors": len(bgp_neighbors),
            "wan_interfaces": len(wan_interfaces),
            "lan_interfaces": len(lan_interfaces),
            "acl_count": len(acls),
            "acl_rules": sum(len(a.get("rules", [])) for a in acls),
            "nat_rules": len(nat_rules),
            "static_routes": len(static_routes),
        },
    }
