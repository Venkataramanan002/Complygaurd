"""
Cisco IOS / IOS-XE switch configuration parser.

Extracts VLANs, trunk/access ports, STP configuration, port-security,
ACLs, and inter-device link information from a standard Cisco IOS
running-config or startup-config.
"""

import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class CiscoSwitchParser:
    """Parse Cisco IOS switch configs into structured topology data."""

    def parse(self, content: str) -> Dict[str, Any]:
        """
        Main entry point.  Returns a dict with:
          - device_name: hostname of the switch
          - vlans: list of VLAN dicts
          - interfaces: list of interface dicts (trunk / access / routed)
          - stp: STP configuration dict
          - port_security: list of port-security entries
          - acls: list of ACL dicts
          - static_routes: list of static route dicts
          - management_ip: management IP if found
        """
        hostname = self._parse_hostname(content)
        vlans = self._parse_vlans(content)
        interfaces = self._parse_interfaces(content)
        stp = self._parse_stp(content)
        port_security = self._extract_port_security(interfaces)
        acls = self._parse_acls(content)
        static_routes = self._parse_static_routes(content)
        mgmt_ip = self._find_management_ip(interfaces)

        return {
            "device_name": hostname,
            "vlans": vlans,
            "interfaces": interfaces,
            "stp": stp,
            "port_security": port_security,
            "acls": acls,
            "static_routes": static_routes,
            "management_ip": mgmt_ip,
        }

    # ── Hostname ────────────────────────────────────────────────────────

    def _parse_hostname(self, content: str) -> str:
        m = re.search(r'^hostname\s+(\S+)', content, re.MULTILINE)
        return m.group(1) if m else "switch-unknown"

    # ── VLANs ───────────────────────────────────────────────────────────

    def _parse_vlans(self, content: str) -> List[Dict[str, Any]]:
        vlans = []
        # Match "vlan <id>" blocks
        blocks = re.findall(
            r'^vlan\s+(\d+)\s*\n((?:\s+.+\n)*)',
            content, re.MULTILINE
        )
        for vlan_id_str, block in blocks:
            vlan_id = int(vlan_id_str)
            name_m = re.search(r'name\s+(\S+)', block)
            name = name_m.group(1) if name_m else f"VLAN{vlan_id}"
            state_m = re.search(r'state\s+(\S+)', block)
            state = state_m.group(1) if state_m else "active"
            vlans.append({
                "id": vlan_id,
                "name": name,
                "state": state,
            })

        # Also catch single-line "vlan <id>" with no block (just id)
        seen_ids = {v["id"] for v in vlans}
        for m in re.finditer(r'^vlan\s+(\d[\d,\-]*)\s*$', content, re.MULTILINE):
            for vid in self._expand_vlan_range(m.group(1)):
                if vid not in seen_ids:
                    vlans.append({"id": vid, "name": f"VLAN{vid}", "state": "active"})
                    seen_ids.add(vid)

        return sorted(vlans, key=lambda v: v["id"])

    def _expand_vlan_range(self, spec: str) -> List[int]:
        """Expand '10,20,30-35' into [10, 20, 30, 31, 32, 33, 34, 35]."""
        result = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                try:
                    result.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    pass
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    pass
        return result

    # ── Interfaces ──────────────────────────────────────────────────────

    def _parse_interfaces(self, content: str) -> List[Dict[str, Any]]:
        interfaces = []
        # Split config into interface blocks
        intf_blocks = re.findall(
            r'^(interface\s+\S+)\s*\n((?:\s+.+\n)*)',
            content, re.MULTILINE
        )
        for intf_line, block in intf_blocks:
            intf_name = intf_line.replace("interface ", "").strip()
            intf = self._parse_single_interface(intf_name, block)
            interfaces.append(intf)

        return interfaces

    def _parse_single_interface(self, name: str, block: str) -> Dict[str, Any]:
        intf: Dict[str, Any] = {
            "name": name,
            "status": "up",
            "description": "",
            "mode": "unknown",       # trunk / access / routed / svi
            "vlan_id": None,
            "allowed_vlans": [],
            "native_vlan": None,
            "ip_address": None,
            "subnet_mask": None,
            "speed": None,
            "duplex": None,
            "port_security": None,
            "channel_group": None,
            "neighbor": None,
        }

        # Shutdown?
        if re.search(r'^\s+shutdown', block, re.MULTILINE):
            intf["status"] = "down"

        # Description
        m = re.search(r'description\s+(.+)', block)
        if m:
            intf["description"] = m.group(1).strip()

        # Switchport mode
        if re.search(r'switchport\s+mode\s+trunk', block):
            intf["mode"] = "trunk"
        elif re.search(r'switchport\s+mode\s+access', block):
            intf["mode"] = "access"
        elif name.lower().startswith("vlan"):
            intf["mode"] = "svi"
        elif re.search(r'no\s+switchport', block) or re.search(r'ip\s+address', block):
            intf["mode"] = "routed"

        # Access VLAN
        m = re.search(r'switchport\s+access\s+vlan\s+(\d+)', block)
        if m:
            intf["vlan_id"] = int(m.group(1))

        # Trunk allowed VLANs
        m = re.search(r'switchport\s+trunk\s+allowed\s+vlan\s+([\d,\-]+)', block)
        if m:
            intf["allowed_vlans"] = self._expand_vlan_range(m.group(1))

        # Native VLAN
        m = re.search(r'switchport\s+trunk\s+native\s+vlan\s+(\d+)', block)
        if m:
            intf["native_vlan"] = int(m.group(1))

        # IP address (routed port or SVI)
        m = re.search(r'ip\s+address\s+([\d.]+)\s+([\d.]+)', block)
        if m:
            intf["ip_address"] = m.group(1)
            intf["subnet_mask"] = m.group(2)

        # Speed / duplex
        m = re.search(r'speed\s+(\S+)', block)
        if m:
            intf["speed"] = m.group(1)
        m = re.search(r'duplex\s+(\S+)', block)
        if m:
            intf["duplex"] = m.group(1)

        # Port-channel / EtherChannel
        m = re.search(r'channel-group\s+(\d+)\s+mode\s+(\S+)', block)
        if m:
            intf["channel_group"] = {"id": int(m.group(1)), "mode": m.group(2)}

        # Port-security
        if re.search(r'switchport\s+port-security', block):
            ps: Dict[str, Any] = {"enabled": True}
            m = re.search(r'port-security\s+maximum\s+(\d+)', block)
            ps["max_mac"] = int(m.group(1)) if m else 1
            m = re.search(r'port-security\s+violation\s+(\S+)', block)
            ps["violation_mode"] = m.group(1) if m else "shutdown"
            ps["sticky"] = bool(re.search(r'port-security\s+mac-address\s+sticky', block))
            intf["port_security"] = ps

        # Neighbor hint from description (common pattern: "Uplink to CORE-RTR-01 Gi0/1")
        desc = intf["description"]
        if desc:
            m = re.search(r'(?:to|from|link|uplink|downlink)\s+(\S+)', desc, re.IGNORECASE)
            if m:
                intf["neighbor"] = m.group(1)

        return intf

    # ── Port-security summary ───────────────────────────────────────────

    def _extract_port_security(self, interfaces: List[Dict]) -> List[Dict]:
        result = []
        for intf in interfaces:
            ps = intf.get("port_security")
            if ps and ps.get("enabled"):
                result.append({
                    "port": intf["name"],
                    "max_mac": ps.get("max_mac", 1),
                    "violation_mode": ps.get("violation_mode", "shutdown"),
                    "sticky": ps.get("sticky", False),
                })
        return result

    # ── STP ─────────────────────────────────────────────────────────────

    def _parse_stp(self, content: str) -> Dict[str, Any]:
        stp: Dict[str, Any] = {"mode": "pvst", "root_for": []}

        m = re.search(r'spanning-tree\s+mode\s+(\S+)', content)
        if m:
            stp["mode"] = m.group(1)

        # Root bridge priority settings
        for m in re.finditer(r'spanning-tree\s+vlan\s+([\d,\-]+)\s+priority\s+(\d+)', content):
            priority = int(m.group(2))
            if priority <= 4096:  # likely root bridge
                stp["root_for"].extend(self._expand_vlan_range(m.group(1)))

        # Root primary shortcut
        for m in re.finditer(r'spanning-tree\s+vlan\s+([\d,\-]+)\s+root\s+primary', content):
            stp["root_for"].extend(self._expand_vlan_range(m.group(1)))

        stp["root_for"] = sorted(set(stp["root_for"]))
        return stp

    # ── ACLs ────────────────────────────────────────────────────────────

    def _parse_acls(self, content: str) -> List[Dict[str, Any]]:
        acls: Dict[str, List[Dict]] = {}

        # Standard / extended named ACLs
        acl_blocks = re.findall(
            r'^ip\s+access-list\s+(\S+)\s+(\S+)\s*\n((?:\s+.+\n)*)',
            content, re.MULTILINE
        )
        for acl_type, acl_name, block in acl_blocks:
            rules = []
            for line in block.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("!"):
                    continue
                rule = self._parse_acl_line(line)
                if rule:
                    rules.append(rule)
            acls[acl_name] = rules

        # Numbered ACLs
        for m in re.finditer(
            r'^access-list\s+(\d+)\s+(permit|deny)\s+(.+)',
            content, re.MULTILINE
        ):
            acl_num = m.group(1)
            acls.setdefault(acl_num, [])
            acls[acl_num].append({
                "action": m.group(2),
                "condition": m.group(3).strip(),
            })

        return [{"name": name, "rules": rules} for name, rules in acls.items()]

    def _parse_acl_line(self, line: str) -> Optional[Dict]:
        m = re.match(r'(permit|deny)\s+(.+)', line)
        if m:
            return {"action": m.group(1), "condition": m.group(2).strip()}
        return None

    # ── Static routes ───────────────────────────────────────────────────

    def _parse_static_routes(self, content: str) -> List[Dict[str, Any]]:
        routes = []
        for m in re.finditer(
            r'^ip\s+route\s+([\d.]+)\s+([\d.]+)\s+([\d.\S]+)(?:\s+(\d+))?',
            content, re.MULTILINE
        ):
            routes.append({
                "network": m.group(1),
                "mask": m.group(2),
                "next_hop": m.group(3),
                "metric": int(m.group(4)) if m.group(4) else None,
            })
        return routes

    # ── Management IP ───────────────────────────────────────────────────

    def _find_management_ip(self, interfaces: List[Dict]) -> Optional[str]:
        # Prefer Vlan1 or any SVI, then any routed port with an IP
        for intf in interfaces:
            if intf["name"].lower() == "vlan1" and intf.get("ip_address"):
                return intf["ip_address"]
        for intf in interfaces:
            if intf["mode"] == "svi" and intf.get("ip_address"):
                return intf["ip_address"]
        for intf in interfaces:
            if intf.get("ip_address"):
                return intf["ip_address"]
        return None

    # ── Convert to topology nodes ───────────────────────────────────────

    def to_topology_nodes(self, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert parsed switch config into a list of NetworkTopology-compatible
        dicts — one node per VLAN/zone the switch participates in, plus the
        switch device node itself.
        """
        hostname = parsed["device_name"]
        mgmt_ip = parsed.get("management_ip", "10.0.0.1")
        nodes = []

        # Build VLAN→interfaces mapping
        vlan_intfs: Dict[int, List[str]] = {}
        for intf in parsed["interfaces"]:
            if intf["mode"] == "access" and intf.get("vlan_id"):
                vlan_intfs.setdefault(intf["vlan_id"], []).append(intf["name"])
            elif intf["mode"] == "trunk":
                for vid in intf.get("allowed_vlans", []):
                    vlan_intfs.setdefault(vid, []).append(intf["name"])

        # Collect connected devices from interface descriptions
        connected_devices = []
        for intf in parsed["interfaces"]:
            if intf.get("neighbor"):
                connected_devices.append(intf["neighbor"])

        # Main switch node
        nodes.append({
            "device_name": hostname,
            "device_type": "switch",
            "zone": "management",
            "ip_address": mgmt_ip,
            "ports_open": [22, 23, 161],  # SSH, Telnet, SNMP typical
            "connected_to": list(set(connected_devices)),
            "is_entry_point": False,
            "vlans": parsed["vlans"],
            "trunk_ports": [
                {
                    "port": intf["name"],
                    "allowed_vlans": intf.get("allowed_vlans", []),
                    "native_vlan": intf.get("native_vlan"),
                    "neighbor": intf.get("neighbor"),
                }
                for intf in parsed["interfaces"] if intf["mode"] == "trunk"
            ],
            "access_ports": [
                {
                    "port": intf["name"],
                    "vlan_id": intf.get("vlan_id"),
                    "port_security": intf.get("port_security"),
                    "status": intf.get("status", "up"),
                }
                for intf in parsed["interfaces"] if intf["mode"] == "access"
            ],
            "stp_mode": parsed["stp"]["mode"],
            "stp_root_for": parsed["stp"]["root_for"],
            "port_security": parsed["port_security"],
            "acls": parsed["acls"],
            "static_routes": parsed["static_routes"],
            "interfaces": [
                {
                    "name": intf["name"],
                    "ip": intf.get("ip_address"),
                    "subnet": intf.get("subnet_mask"),
                    "status": intf.get("status", "up"),
                    "speed": intf.get("speed"),
                    "description": intf.get("description", ""),
                    "mode": intf["mode"],
                }
                for intf in parsed["interfaces"]
            ],
        })

        # Per-VLAN SVI nodes (these represent L3 presence in each VLAN segment)
        for vlan_info in parsed["vlans"]:
            vid = vlan_info["id"]
            vname = vlan_info["name"]
            # Find matching SVI
            svi_ip = None
            for intf in parsed["interfaces"]:
                if intf["name"].lower() == f"vlan{vid}" and intf.get("ip_address"):
                    svi_ip = intf["ip_address"]
                    break
            if svi_ip:
                nodes.append({
                    "device_name": hostname,
                    "device_type": "switch",
                    "zone": vname.lower().replace(" ", "_"),
                    "ip_address": svi_ip,
                    "ports_open": [],
                    "connected_to": [hostname],
                    "is_entry_point": False,
                    "vlan_id": vid,
                    "subnet": svi_ip.rsplit(".", 1)[0] + ".0/24",
                    "link_type": "svi",
                })

        return nodes
