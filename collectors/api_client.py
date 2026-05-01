"""
Multi-vendor REST/XML API collector.

Supports:
  - Palo Alto PAN-OS XML API (API key auth)
  - Fortinet FortiOS REST API (Bearer token)
  - Cisco ASA/FDM REST API (Bearer token)
"""

import asyncio
import logging
import os
import time
import defusedxml.ElementTree as ET  # SECURITY: prevents XXE
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
import yaml
from dotenv import load_dotenv

from database.connection import AsyncSessionLocal
from database.operations import insert_system_health

load_dotenv()
logger = logging.getLogger(__name__)

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "devices.yaml")


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class DeviceConfig:
    name: str
    host: str
    vendor: str  # paloalto | fortinet | cisco
    auth_type: str  # apikey | token | basic
    credentials_env_var: str
    poll_interval_minutes: int = 15
    enabled: bool = True
    verify_ssl: bool = False


@dataclass
class CollectionResult:
    device_name: str
    vendor: str
    success: bool
    rules_collected: int = 0
    health_collected: bool = False
    error: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


# ── Config loader ────────────────────────────────────────────────────────────

def load_devices() -> List[DeviceConfig]:
    """Load device configs from YAML. Returns empty list if file missing."""
    try:
        with open(_CONFIG_PATH, "r") as f:
            data = yaml.safe_load(f) or {}
        return [DeviceConfig(**d) for d in data.get("devices", [])]
    except FileNotFoundError:
        logger.warning("config/devices.yaml not found")
        return []
    except Exception as e:
        logger.error(f"Error loading devices config: {e}")
        return []


def save_devices(devices: List[DeviceConfig]):
    """Persist device list back to YAML (for Add Device feature)."""
    data = {"devices": [
        {
            "name": d.name,
            "host": d.host,
            "vendor": d.vendor,
            "auth_type": d.auth_type,
            "credentials_env_var": d.credentials_env_var,
            "poll_interval_minutes": d.poll_interval_minutes,
            "enabled": d.enabled,
            "verify_ssl": d.verify_ssl,
        }
        for d in devices
    ]}
    with open(_CONFIG_PATH, "w") as f:
        yaml.dump(data, f, default_flow_style=False)


def _get_credential(device: DeviceConfig) -> str:
    """Read credential from environment variable. Never log or return it."""
    return os.getenv(device.credentials_env_var, "")


# ── Vendor-specific collectors ───────────────────────────────────────────────

async def _poll_paloalto(device: DeviceConfig) -> CollectionResult:
    """Palo Alto PAN-OS XML API — fetch security rules & system health."""
    api_key = _get_credential(device)
    result = CollectionResult(device_name=device.name, vendor="paloalto", success=False)
    rules_count = 0

    ssl_ctx = False if not device.verify_ssl else None

    async with aiohttp.ClientSession() as session:
        # 1. Fetch security rules
        rules_url = (
            f"https://{device.host}/api/?type=config&action=show"
            f"&xpath=/config/devices/entry/vsys/entry/rulebase/security/rules"
            f"&key={api_key}"
        )
        try:
            async with session.get(rules_url, ssl=ssl_ctx, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    xml_text = await resp.text()
                    rules_count = await _parse_pa_rules_xml(xml_text, device.name)
                    result.rules_collected = rules_count
                else:
                    result.error = f"Rules API returned {resp.status}"
                    logger.error(f"[{device.name}] Rules API: {resp.status}")
        except Exception as e:
            result.error = str(e)
            logger.error(f"[{device.name}] Rules fetch error: {e}")

        # 2. Fetch system health
        health_url = (
            f"https://{device.host}/api/?type=op"
            f"&cmd=<show><system><info></info></system></show>"
            f"&key={api_key}"
        )
        try:
            async with session.get(health_url, ssl=ssl_ctx, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    xml_text = await resp.text()
                    await _parse_pa_health_xml(xml_text, device.name)
                    result.health_collected = True
        except Exception as e:
            logger.error(f"[{device.name}] Health fetch error: {e}")

    result.success = rules_count > 0 or result.health_collected
    return result


async def _parse_pa_rules_xml(xml_text: str, device_name: str) -> int:
    """Parse Palo Alto XML security rules and insert into firewall_rules table."""
    from database.models import FirewallRule
    count = 0
    try:
        root = ET.fromstring(xml_text)
        entries = root.findall(".//entry")

        async with AsyncSessionLocal() as session:
            for i, entry in enumerate(entries):
                rule_name = entry.get("name", f"rule-{i}")
                source = _xml_text(entry, "source/member", "any")
                dest = _xml_text(entry, "destination/member", "any")
                service = _xml_text(entry, "service/member", "any")
                action = _xml_text(entry, "action", "allow")
                protocol = _xml_text(entry, "protocol/member", "any")
                disabled = _xml_text(entry, "disabled", "no")

                rule = FirewallRule(
                    device_name=device_name,
                    rule_name=rule_name,
                    rule_position=i + 1,
                    source_ip=source,
                    dest_ip=dest,
                    dest_port=service,
                    protocol=protocol,
                    action=action,
                    service_name=service,
                    is_enabled=disabled != "yes",
                )
                session.add(rule)
                count += 1
            await session.commit()
    except ET.ParseError as e:
        logger.error(f"PA XML parse error: {e}")
    except Exception as e:
        logger.error(f"PA rules DB insert error: {e}")
    return count


async def _parse_pa_health_xml(xml_text: str, device_name: str):
    """Extract system health from PAN-OS op-cmd response."""
    try:
        root = ET.fromstring(xml_text)
        sys_info = root.find(".//system")
        if sys_info is None:
            return

        health_data = {
            "device_name": device_name,
            "cpu_usage_percent": float(_xml_text(sys_info, "cpu", "0")),
            "memory_usage_percent": float(_xml_text(sys_info, "memory", "0")),
            "active_sessions": int(_xml_text(sys_info, "session-count", "0")),
        }
        async with AsyncSessionLocal() as session:
            await insert_system_health(session, health_data)
    except Exception as e:
        logger.error(f"PA health parse error: {e}")


def _xml_text(parent, path: str, default: str = "") -> str:
    """Safely get text of first matching XML element."""
    el = parent.find(path)
    return el.text.strip() if el is not None and el.text else default


async def _poll_fortinet(device: DeviceConfig) -> CollectionResult:
    """Fortinet FortiOS REST API — fetch firewall policies."""
    token = _get_credential(device)
    result = CollectionResult(device_name=device.name, vendor="fortinet", success=False)
    ssl_ctx = False if not device.verify_ssl else None

    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://{device.host}/api/v2/cmdb/firewall/policy"

    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            async with session.get(url, ssl=ssl_ctx, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    policies = data.get("results", [])
                    count = await _insert_fortinet_rules(policies, device.name)
                    result.rules_collected = count
                    result.success = count > 0
                else:
                    result.error = f"API returned {resp.status}"
                    logger.error(f"[{device.name}] Fortinet API: {resp.status}")
        except Exception as e:
            result.error = str(e)
            logger.error(f"[{device.name}] Fortinet fetch error: {e}")

    return result


async def _insert_fortinet_rules(policies: list, device_name: str) -> int:
    """Map FortiOS policy JSON to FirewallRule records."""
    from database.models import FirewallRule
    count = 0
    async with AsyncSessionLocal() as session:
        for i, p in enumerate(policies):
            try:
                src_intf = _forti_list(p.get("srcintf", []))
                dst_intf = _forti_list(p.get("dstintf", []))
                src_addr = _forti_list(p.get("srcaddr", []))
                dst_addr = _forti_list(p.get("dstaddr", []))
                service = _forti_list(p.get("service", []))
                action = "allow" if p.get("action") == "accept" else "deny"

                rule = FirewallRule(
                    device_name=device_name,
                    rule_name=f"policy-{p.get('policyid', i)}",
                    rule_position=i + 1,
                    source_ip=src_addr,
                    dest_ip=dst_addr,
                    protocol="any",
                    action=action,
                    service_name=service,
                    is_enabled=p.get("status") == "enable",
                )
                session.add(rule)
                count += 1
            except Exception as e:
                logger.error(f"Fortinet rule insert error: {e}")
        await session.commit()
    return count


def _forti_list(items) -> str:
    """Extract names from FortiOS list-of-dicts [{name: ...}] or return string."""
    if isinstance(items, list):
        names = [i.get("name", str(i)) if isinstance(i, dict) else str(i) for i in items]
        return ", ".join(names) if names else "any"
    return str(items)


async def _poll_cisco(device: DeviceConfig) -> CollectionResult:
    """Cisco ASA/FDM REST API — fetch access rules."""
    token = _get_credential(device)
    result = CollectionResult(device_name=device.name, vendor="cisco", success=False)
    ssl_ctx = False if not device.verify_ssl else None

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # FDM first needs the default access policy ID
    policy_url = f"https://{device.host}/api/fdm/latest/policy/accesspolicies"

    async with aiohttp.ClientSession(headers=headers) as session:
        try:
            # Get policy ID
            async with session.get(policy_url, ssl=ssl_ctx, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    result.error = f"Policy list returned {resp.status}"
                    return result
                policies = await resp.json()
                items = policies.get("items", [])
                if not items:
                    result.error = "No access policies found"
                    return result
                policy_id = items[0].get("id", "default")

            # Fetch rules from that policy
            rules_url = f"https://{device.host}/api/fdm/latest/policy/accesspolicies/{policy_id}/accessrules"
            async with session.get(rules_url, ssl=ssl_ctx, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    rules = data.get("items", [])
                    count = await _insert_cisco_rules(rules, device.name)
                    result.rules_collected = count
                    result.success = count > 0
                else:
                    result.error = f"Rules API returned {resp.status}"
        except Exception as e:
            result.error = str(e)
            logger.error(f"[{device.name}] Cisco fetch error: {e}")

    return result


async def _insert_cisco_rules(rules: list, device_name: str) -> int:
    """Map Cisco FDM access rules to FirewallRule records."""
    from database.models import FirewallRule
    count = 0
    async with AsyncSessionLocal() as session:
        for i, r in enumerate(rules):
            try:
                src_nets = _cisco_network_text(r.get("sourceNetworks", {}))
                dst_nets = _cisco_network_text(r.get("destinationNetworks", {}))
                src_ports = _cisco_port_text(r.get("sourcePorts", {}))
                dst_ports = _cisco_port_text(r.get("destinationPorts", {}))
                action = r.get("ruleAction", "PERMIT").lower()
                action = "allow" if action == "permit" else "deny"

                rule = FirewallRule(
                    device_name=device_name,
                    rule_name=r.get("name", f"rule-{i}"),
                    rule_position=i + 1,
                    source_ip=src_nets,
                    source_port=src_ports,
                    dest_ip=dst_nets,
                    dest_port=dst_ports,
                    protocol="any",
                    action=action,
                    is_enabled=r.get("enabled", True),
                )
                session.add(rule)
                count += 1
            except Exception as e:
                logger.error(f"Cisco rule insert error: {e}")
        await session.commit()
    return count


def _cisco_network_text(nets: dict) -> str:
    """Extract network names from Cisco FDM network objects."""
    objects = nets.get("objects", [])
    if objects:
        return ", ".join(o.get("name", o.get("value", "any")) for o in objects)
    return "any"


def _cisco_port_text(ports: dict) -> str:
    """Extract port info from Cisco FDM port objects."""
    objects = ports.get("objects", [])
    if objects:
        return ", ".join(o.get("name", o.get("port", "any")) for o in objects)
    return "any"


# ── Unified DeviceCollector ──────────────────────────────────────────────────

_VENDOR_POLLERS = {
    "paloalto": _poll_paloalto,
    "fortinet": _poll_fortinet,
    "cisco": _poll_cisco,
}


class DeviceCollector:
    """Unified device collector with poll routing, status tracking, and scheduling."""

    _instance: Optional["DeviceCollector"] = None

    def __init__(self):
        self._devices: List[DeviceConfig] = load_devices()
        self._last_results: Dict[str, CollectionResult] = {}
        self._schedule_tasks: Dict[str, asyncio.Task] = {}
        self._scheduling_active = False

    def reload_devices(self):
        self._devices = load_devices()

    def get_devices(self) -> List[DeviceConfig]:
        return self._devices

    def add_device(self, cfg: DeviceConfig):
        """Add a device and persist to YAML."""
        self._devices.append(cfg)
        save_devices(self._devices)

    async def poll(self, device_name: str) -> CollectionResult:
        """Poll a single device by name."""
        device = next((d for d in self._devices if d.name == device_name), None)
        if not device:
            return CollectionResult(
                device_name=device_name, vendor="unknown",
                success=False, error="Device not found in config"
            )

        if not device.enabled:
            return CollectionResult(
                device_name=device_name, vendor=device.vendor,
                success=False, error="Device is disabled"
            )

        poller = _VENDOR_POLLERS.get(device.vendor)
        if not poller:
            return CollectionResult(
                device_name=device_name, vendor=device.vendor,
                success=False, error=f"Unsupported vendor: {device.vendor}"
            )

        result = await poller(device)
        self._last_results[device_name] = result
        return result

    def status(self) -> dict:
        """Return status of all devices and their last poll results."""
        devices_status = []
        for d in self._devices:
            last = self._last_results.get(d.name)
            devices_status.append({
                "name": d.name,
                "host": d.host,
                "vendor": d.vendor,
                "enabled": d.enabled,
                "poll_interval_minutes": d.poll_interval_minutes,
                "last_poll": last.timestamp if last else None,
                "last_poll_success": last.success if last else None,
                "rules_collected": last.rules_collected if last else 0,
                "health_collected": last.health_collected if last else False,
                "last_error": last.error if last else None,
            })
        return {
            "scheduling_active": self._scheduling_active,
            "devices": devices_status,
        }

    async def start_scheduled_polling(self):
        """Start background polling tasks for all enabled devices."""
        if self._scheduling_active:
            return
        self._scheduling_active = True
        for device in self._devices:
            if device.enabled:
                self._schedule_tasks[device.name] = asyncio.create_task(
                    self._poll_loop(device)
                )
        logger.info("Scheduled polling started for all enabled devices")

    async def stop_scheduled_polling(self):
        """Cancel all scheduled polling tasks."""
        self._scheduling_active = False
        for name, task in self._schedule_tasks.items():
            task.cancel()
        self._schedule_tasks.clear()
        logger.info("Scheduled polling stopped")

    async def _poll_loop(self, device: DeviceConfig):
        """Background loop that polls a device at its configured interval."""
        while self._scheduling_active:
            try:
                result = await self.poll(device.name)
                logger.info(
                    f"[{device.name}] Poll complete: {result.rules_collected} rules, "
                    f"success={result.success}"
                )
            except Exception as e:
                logger.error(f"[{device.name}] Poll loop error: {e}")
            await asyncio.sleep(device.poll_interval_minutes * 60)


def get_device_collector() -> DeviceCollector:
    """Return the module-level DeviceCollector singleton."""
    if DeviceCollector._instance is None:
        DeviceCollector._instance = DeviceCollector()
    return DeviceCollector._instance
