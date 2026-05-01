"""
Cisco IOS / IOS-XE router configuration parser.

Extracts interfaces, routing protocols (OSPF, BGP, EIGRP, static),
ACLs, NAT rules, and inter-device connectivity from a standard Cisco
IOS running-config.
"""

import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class CiscoRouterParser:
    """Parse Cisco IOS router configs into structured topology data."""

    def parse(self, content: str) -> Dict[str, Any]:
        hostname = self._parse_hostname(content)
        interfaces = self._parse_interfaces(content)
        ospf = self._parse_ospf(content)
        bgp = self._parse_bgp(content)
        eigrp = self._parse_eigrp(content)
        static_routes = self._parse_static_routes(content)
        acls = self._parse_acls(content)
        nat_rules = self._parse_nat(content)
        route_maps = self._parse_route_maps(content)

        # Determine primary routing protocol
        routing_protocol = "static"
        if bgp["enabled"]:
            routing_protocol = "bgp"
        elif ospf["enabled"]:
            routing_protocol = "ospf"
        elif eigrp["enabled"]:
            routing_protocol = "eigrp"

        return {
            "device_name": hostname,
            "interfaces": interfaces,
            "routing_protocol": routing_protocol,
            "ospf": ospf,
            "bgp": bgp,
            "eigrp": eigrp,
            "static_routes": static_routes,
            "acls": acls,
            "nat_rules": nat_rules,
            "route_maps": route_maps,
        }

    # ── Hostname ────────────────────────────────────────────────────────

    def _parse_hostname(self, content: str) -> str:
        m = re.search(r'^hostname\s+(\S+)', content, re.MULTILINE)
        return m.group(1) if m else "router-unknown"

    # ── Interfaces ──────────────────────────────────────────────────────

    def _parse_interfaces(self, content: str) -> List[Dict[str, Any]]:
        interfaces = []
        intf_blocks = re.findall(
            r'^(interface\s+\S+)\s*\n((?:\s+.+\n)*)',
            content, re.MULTILINE
        )
        for intf_line, block in intf_blocks:
            name = intf_line.replace("interface ", "").strip()
            intf = self._parse_single_interface(name, block)
            interfaces.append(intf)
        return interfaces

    def _parse_single_interface(self, name: str, block: str) -> Dict[str, Any]:
        intf: Dict[str, Any] = {
            "name": name,
            "ip_address": None,
            "subnet_mask": None,
            "status": "up",
            "description": "",
            "speed": None,
            "duplex": None,
            "mtu": None,
            "nat_direction": None,   # inside / outside
            "ospf_area": None,
            "acl_in": None,
            "acl_out": None,
            "vrf": None,
            "encapsulation": None,
            "bandwidth": None,
            "neighbor": None,
            "zone": None,
        }

        if re.search(r'^\s+shutdown', block, re.MULTILINE):
            intf["status"] = "down"

        m = re.search(r'description\s+(.+)', block)
        if m:
            intf["description"] = m.group(1).strip()

        m = re.search(r'ip\s+address\s+([\d.]+)\s+([\d.]+)', block)
        if m:
            intf["ip_address"] = m.group(1)
            intf["subnet_mask"] = m.group(2)

        m = re.search(r'speed\s+(\S+)', block)
        if m:
            intf["speed"] = m.group(1)

        m = re.search(r'duplex\s+(\S+)', block)
        if m:
            intf["duplex"] = m.group(1)

        m = re.search(r'mtu\s+(\d+)', block)
        if m:
            intf["mtu"] = int(m.group(1))

        m = re.search(r'bandwidth\s+(\d+)', block)
        if m:
            intf["bandwidth"] = int(m.group(1))

        # NAT direction
        if re.search(r'ip\s+nat\s+inside', block):
            intf["nat_direction"] = "inside"
        elif re.search(r'ip\s+nat\s+outside', block):
            intf["nat_direction"] = "outside"

        # OSPF
        m = re.search(r'ip\s+ospf\s+\d+\s+area\s+(\S+)', block)
        if m:
            intf["ospf_area"] = m.group(1)

        # ACLs applied to interface
        m = re.search(r'ip\s+access-group\s+(\S+)\s+in', block)
        if m:
            intf["acl_in"] = m.group(1)
        m = re.search(r'ip\s+access-group\s+(\S+)\s+out', block)
        if m:
            intf["acl_out"] = m.group(1)

        # VRF
        m = re.search(r'(?:ip\s+)?vrf\s+forwarding\s+(\S+)', block)
        if m:
            intf["vrf"] = m.group(1)

        # Encapsulation (subinterfaces)
        m = re.search(r'encapsulation\s+dot1Q\s+(\d+)', block)
        if m:
            intf["encapsulation"] = f"dot1Q {m.group(1)}"

        # Neighbor from description
        desc = intf["description"]
        if desc:
            m = re.search(r'(?:to|from|link|uplink|peer)\s+(\S+)', desc, re.IGNORECASE)
            if m:
                intf["neighbor"] = m.group(1)

        # Zone inference from description or name
        desc_lower = desc.lower() + " " + name.lower()
        if any(w in desc_lower for w in ["wan", "internet", "isp", "outside"]):
            intf["zone"] = "wan"
        elif any(w in desc_lower for w in ["dmz", "perimeter"]):
            intf["zone"] = "dmz"
        elif any(w in desc_lower for w in ["lan", "inside", "internal", "trust"]):
            intf["zone"] = "lan"
        elif any(w in desc_lower for w in ["server", "datacenter", "dc"]):
            intf["zone"] = "datacenter"
        elif any(w in desc_lower for w in ["mgmt", "management", "oob"]):
            intf["zone"] = "management"

        return intf

    # ── OSPF ────────────────────────────────────────────────────────────

    def _parse_ospf(self, content: str) -> Dict[str, Any]:
        ospf: Dict[str, Any] = {"enabled": False, "process_id": None, "router_id": None, "areas": [], "networks": [], "neighbors": []}

        m = re.search(r'^router\s+ospf\s+(\d+)\s*\n((?:\s+.+\n)*)', content, re.MULTILINE)
        if not m:
            return ospf

        ospf["enabled"] = True
        ospf["process_id"] = int(m.group(1))
        block = m.group(2)

        # Router ID
        rid = re.search(r'router-id\s+([\d.]+)', block)
        if rid:
            ospf["router_id"] = rid.group(1)

        # Networks
        for nm in re.finditer(r'network\s+([\d.]+)\s+([\d.]+)\s+area\s+(\S+)', block):
            ospf["networks"].append({
                "network": nm.group(1),
                "wildcard": nm.group(2),
                "area": nm.group(3),
            })
            if nm.group(3) not in ospf["areas"]:
                ospf["areas"].append(nm.group(3))

        # Passive interfaces
        ospf["passive_interfaces"] = []
        for pm in re.finditer(r'passive-interface\s+(\S+)', block):
            ospf["passive_interfaces"].append(pm.group(1))

        return ospf

    # ── BGP ─────────────────────────────────────────────────────────────

    def _parse_bgp(self, content: str) -> Dict[str, Any]:
        bgp: Dict[str, Any] = {"enabled": False, "asn": None, "router_id": None, "neighbors": [], "networks": []}

        m = re.search(r'^router\s+bgp\s+(\d+)\s*\n((?:\s+.+\n)*)', content, re.MULTILINE)
        if not m:
            return bgp

        bgp["enabled"] = True
        bgp["asn"] = int(m.group(1))
        block = m.group(2)

        rid = re.search(r'bgp\s+router-id\s+([\d.]+)', block)
        if rid:
            bgp["router_id"] = rid.group(1)

        for nm in re.finditer(r'neighbor\s+([\d.]+)\s+remote-as\s+(\d+)', block):
            neighbor = {"neighbor_ip": nm.group(1), "remote_asn": int(nm.group(2)), "state": "active"}
            # Description
            dm = re.search(rf'neighbor\s+{re.escape(nm.group(1))}\s+description\s+(.+)', block)
            if dm:
                neighbor["description"] = dm.group(1).strip()
            bgp["neighbors"].append(neighbor)

        for nm in re.finditer(r'network\s+([\d.]+)\s+mask\s+([\d.]+)', block):
            bgp["networks"].append({"network": nm.group(1), "mask": nm.group(2)})

        return bgp

    # ── EIGRP ───────────────────────────────────────────────────────────

    def _parse_eigrp(self, content: str) -> Dict[str, Any]:
        eigrp: Dict[str, Any] = {"enabled": False, "asn": None, "networks": []}

        m = re.search(r'^router\s+eigrp\s+(\d+)\s*\n((?:\s+.+\n)*)', content, re.MULTILINE)
        if not m:
            return eigrp

        eigrp["enabled"] = True
        eigrp["asn"] = int(m.group(1))
        block = m.group(2)

        for nm in re.finditer(r'network\s+([\d.]+)(?:\s+([\d.]+))?', block):
            eigrp["networks"].append({
                "network": nm.group(1),
                "wildcard": nm.group(2) if nm.group(2) else "0.0.0.0",
            })

        return eigrp

    # ── Static routes ───────────────────────────────────────────────────

    def _parse_static_routes(self, content: str) -> List[Dict[str, Any]]:
        routes = []
        for m in re.finditer(
            r'^ip\s+route(?:\s+vrf\s+\S+)?\s+([\d.]+)\s+([\d.]+)\s+([\d.\S]+)(?:\s+(\d+))?',
            content, re.MULTILINE
        ):
            routes.append({
                "network": m.group(1),
                "mask": m.group(2),
                "next_hop": m.group(3),
                "metric": int(m.group(4)) if m.group(4) else None,
            })
        return routes

    # ── ACLs ────────────────────────────────────────────────────────────

    def _parse_acls(self, content: str) -> List[Dict[str, Any]]:
        acls: Dict[str, List[Dict]] = {}

        # Named ACLs
        acl_blocks = re.findall(
            r'^ip\s+access-list\s+(\S+)\s+(\S+)\s*\n((?:\s+.+\n)*)',
            content, re.MULTILINE
        )
        for acl_type, acl_name, block in acl_blocks:
            rules = []
            for line in block.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("!") or line.startswith("remark"):
                    continue
                m = re.match(r'(\d+\s+)?(permit|deny)\s+(.+)', line)
                if m:
                    rules.append({
                        "action": m.group(2),
                        "protocol": self._extract_protocol(m.group(3)),
                        "condition": m.group(3).strip(),
                    })
            acls[acl_name] = rules

        # Numbered ACLs
        for m in re.finditer(r'^access-list\s+(\d+)\s+(permit|deny)\s+(.+)', content, re.MULTILINE):
            acl_num = m.group(1)
            acls.setdefault(acl_num, [])
            acls[acl_num].append({
                "action": m.group(2),
                "protocol": self._extract_protocol(m.group(3)),
                "condition": m.group(3).strip(),
            })

        return [{"name": name, "type": "extended" if any("tcp" in r.get("protocol", "") or "udp" in r.get("protocol", "") for r in rules) else "standard", "rules": rules} for name, rules in acls.items()]

    def _extract_protocol(self, condition: str) -> str:
        parts = condition.split()
        if parts and parts[0] in ("ip", "tcp", "udp", "icmp", "gre", "esp", "ahp", "eigrp", "ospf"):
            return parts[0]
        return "ip"

    # ── NAT ─────────────────────────────────────────────────────────────

    def _parse_nat(self, content: str) -> List[Dict[str, Any]]:
        nat_rules = []

        # Static NAT
        for m in re.finditer(
            r'^ip\s+nat\s+inside\s+source\s+static\s+(?:tcp\s+|udp\s+)?([\d.]+)\s+(?:(\d+)\s+)?([\d.]+)(?:\s+(\d+))?',
            content, re.MULTILINE
        ):
            nat_rules.append({
                "type": "static",
                "inside_ip": m.group(1),
                "inside_port": int(m.group(2)) if m.group(2) else None,
                "outside_ip": m.group(3),
                "outside_port": int(m.group(4)) if m.group(4) else None,
            })

        # Dynamic NAT with overload (PAT)
        for m in re.finditer(
            r'^ip\s+nat\s+inside\s+source\s+list\s+(\S+)\s+(?:interface\s+(\S+)|pool\s+(\S+))(?:\s+overload)?',
            content, re.MULTILINE
        ):
            nat_rules.append({
                "type": "dynamic_pat" if "overload" in m.group(0) else "dynamic",
                "acl": m.group(1),
                "interface": m.group(2),
                "pool": m.group(3),
            })

        return nat_rules

    # ── Route-maps ──────────────────────────────────────────────────────

    def _parse_route_maps(self, content: str) -> List[Dict[str, Any]]:
        route_maps = []
        for m in re.finditer(
            r'^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)\s*\n((?:\s+.+\n)*)',
            content, re.MULTILINE
        ):
            route_maps.append({
                "name": m.group(1),
                "action": m.group(2),
                "sequence": int(m.group(3)),
                "statements": [l.strip() for l in m.group(4).strip().splitlines() if l.strip() and not l.strip().startswith("!")],
            })
        return route_maps

    # ── Convert to topology nodes ───────────────────────────────────────

    def to_topology_nodes(self, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert parsed router config into NetworkTopology-compatible dicts.
        One node per interface with an IP, plus the router device node itself.
        """
        hostname = parsed["device_name"]
        nodes = []

        # Collect connected devices
        connected_devices = []
        for intf in parsed["interfaces"]:
            if intf.get("neighbor"):
                connected_devices.append(intf["neighbor"])

        # Find management / primary IP
        primary_ip = None
        for intf in parsed["interfaces"]:
            if intf.get("ip_address") and intf["status"] == "up":
                primary_ip = intf["ip_address"]
                break

        # BGP neighbor IPs as connected devices
        if parsed["bgp"]["enabled"]:
            for n in parsed["bgp"]["neighbors"]:
                desc = n.get("description", "")
                if desc:
                    connected_devices.append(desc.split()[0])

        # OSPF neighbors from network statements → infer connected devices
        # (actual neighbor discovery would need show commands, but we can track the areas)

        # Main router node
        nodes.append({
            "device_name": hostname,
            "device_type": "router",
            "zone": "core",
            "ip_address": primary_ip or "0.0.0.0",
            "ports_open": [22, 23, 161, 179] if parsed["bgp"]["enabled"] else [22, 23, 161],
            "connected_to": list(set(connected_devices)),
            "is_entry_point": any(
                intf.get("zone") == "wan" or intf.get("nat_direction") == "outside"
                for intf in parsed["interfaces"]
            ),
            "routing_protocol": parsed["routing_protocol"],
            "ospf_area": parsed["ospf"]["areas"][0] if parsed["ospf"]["areas"] else None,
            "bgp_asn": parsed["bgp"]["asn"],
            "bgp_neighbors": parsed["bgp"]["neighbors"],
            "static_routes": parsed["static_routes"],
            "nat_rules": parsed["nat_rules"],
            "acls": parsed["acls"],
            "interfaces": [
                {
                    "name": intf["name"],
                    "ip": intf.get("ip_address"),
                    "subnet": intf.get("subnet_mask"),
                    "status": intf.get("status", "up"),
                    "speed": intf.get("speed"),
                    "description": intf.get("description", ""),
                    "zone": intf.get("zone"),
                    "nat": intf.get("nat_direction"),
                }
                for intf in parsed["interfaces"]
            ],
        })

        # Per-interface zone nodes (each routed interface represents a network segment)
        for intf in parsed["interfaces"]:
            if not intf.get("ip_address") or intf["status"] == "down":
                continue
            # Skip loopback
            if intf["name"].lower().startswith("loopback"):
                continue

            zone = intf.get("zone") or self._infer_zone(intf)
            is_wan = zone == "wan" or intf.get("nat_direction") == "outside"

            nodes.append({
                "device_name": hostname,
                "device_type": "router",
                "zone": zone,
                "ip_address": intf["ip_address"],
                "ports_open": [],
                "connected_to": [intf["neighbor"]] if intf.get("neighbor") else [hostname],
                "is_entry_point": is_wan,
                "subnet": intf["ip_address"].rsplit(".", 1)[0] + ".0/24",
                "link_type": "wan" if is_wan else "routed",
                "neighbor_device": intf.get("neighbor"),
                "neighbor_port": None,
            })

        return nodes

    def _infer_zone(self, intf: Dict) -> str:
        """Infer a zone name from interface naming conventions."""
        name = intf["name"].lower()
        if "serial" in name or "tunnel" in name:
            return "wan"
        if "gig" in name or "fast" in name or "ten" in name:
            return "lan"
        return "other"

    # ── Generate ACL-based firewall rules ───────────────────────────────

    def to_firewall_rules(self, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert router ACLs into FirewallRule-compatible dicts so they
        participate in risk scoring and attack path analysis.
        """
        hostname = parsed["device_name"]
        rules = []
        pos = 1

        # Build ACL→interface mapping
        acl_intf_map: Dict[str, Dict] = {}
        for intf in parsed["interfaces"]:
            if intf.get("acl_in"):
                acl_intf_map.setdefault(intf["acl_in"], {})["in_intf"] = intf
            if intf.get("acl_out"):
                acl_intf_map.setdefault(intf["acl_out"], {})["out_intf"] = intf

        for acl in parsed["acls"]:
            acl_name = acl["name"]
            intf_info = acl_intf_map.get(acl_name, {})
            in_intf = intf_info.get("in_intf", {})
            out_intf = intf_info.get("out_intf", {})

            src_zone = in_intf.get("zone", "any") if in_intf else "any"
            dst_zone = out_intf.get("zone", "any") if out_intf else "any"

            for ace in acl["rules"]:
                # Parse source/dest from condition
                src, dst, port = self._parse_ace_condition(ace.get("condition", ""))
                rules.append({
                    "device_name": hostname,
                    "rule_name": f"{acl_name}-{pos}",
                    "rule_position": pos,
                    "source_ip": src or src_zone,
                    "source_port": "any",
                    "dest_ip": dst or dst_zone,
                    "dest_port": port or "any",
                    "protocol": ace.get("protocol", "ip"),
                    "action": "allow" if ace["action"] == "permit" else "deny",
                    "service_name": None,
                    "is_enabled": True,
                })
                pos += 1

        return rules

    def _parse_ace_condition(self, condition: str):
        """Extract src, dst, port from an ACE condition string."""
        parts = condition.split()
        src = dst = port = None

        # Simple pattern: protocol src dst [eq port]
        if len(parts) >= 3:
            # parts[0] = protocol
            src_raw = parts[1] if len(parts) > 1 else "any"
            dst_raw = parts[2] if len(parts) > 2 else "any"

            # Handle 'host x.x.x.x' pattern
            idx = 1
            if idx < len(parts) and parts[idx] == "host" and idx + 1 < len(parts):
                src = parts[idx + 1]
                idx += 2
            elif idx < len(parts) and parts[idx] == "any":
                src = "any"
                idx += 1
            elif idx < len(parts):
                src = parts[idx]
                idx += 1
                if idx < len(parts) and re.match(r'[\d.]+', parts[idx]):
                    idx += 1  # skip wildcard mask

            if idx < len(parts) and parts[idx] == "host" and idx + 1 < len(parts):
                dst = parts[idx + 1]
                idx += 2
            elif idx < len(parts) and parts[idx] == "any":
                dst = "any"
                idx += 1
            elif idx < len(parts):
                dst = parts[idx]
                idx += 1
                if idx < len(parts) and re.match(r'[\d.]+', parts[idx]):
                    idx += 1

            if idx < len(parts) and parts[idx] == "eq" and idx + 1 < len(parts):
                port = parts[idx + 1]

        return src, dst, port
