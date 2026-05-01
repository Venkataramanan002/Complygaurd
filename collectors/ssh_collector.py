"""
SSH/CLI config backup collector using Netmiko.

Connects to network devices via SSH, retrieves running configs,
stores versioned backups, detects changes, and feeds through parser pipeline.
"""

import asyncio
import hashlib
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from database.connection import AsyncSessionLocal
from database.operations import insert_admin_audit

logger = logging.getLogger(__name__)

BACKUPS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "backups")

# Vendor → Netmiko device_type mapping
_DEVICE_TYPE_MAP = {
    "cisco": "cisco_asa",
    "paloalto": "paloalto_panos",
    "fortinet": "fortinet",
}

# Vendor → CLI commands to get running config
_CONFIG_COMMANDS = {
    "cisco": ["show running-config"],
    "fortinet": ["show full-configuration"],
    "paloalto": ["set cli config-output-format set", "show"],
}


@dataclass
class ConfigBackupResult:
    device_name: str
    success: bool
    version_number: int = 0
    file_path: str = ""
    file_hash: str = ""
    file_size: int = 0
    change_detected: bool = False
    change_summary: str = ""
    error: Optional[str] = None


class SSHConfigCollector:
    """Collects running configs from network devices via SSH/CLI."""

    def __init__(self):
        Path(BACKUPS_DIR).mkdir(parents=True, exist_ok=True)

    async def backup_config(self, device: dict) -> ConfigBackupResult:
        """
        Connect to device via SSH, retrieve config, store versioned backup.

        Args:
            device: dict with keys: name, host, vendor, credentials_env_var
        """
        device_name = device["name"]
        vendor = device["vendor"]
        host = device["host"]
        cred_var = device.get("credentials_env_var", "")

        result = ConfigBackupResult(device_name=device_name, success=False)

        # Read SSH credentials from environment
        cred_value = os.getenv(cred_var, "")
        if not cred_value:
            result.error = f"No credentials found in env var '{cred_var}'"
            return result

        # Parse credentials (format: "username:password")
        if ":" in cred_value:
            username, password = cred_value.split(":", 1)
        else:
            username = "admin"
            password = cred_value

        device_type = _DEVICE_TYPE_MAP.get(vendor)
        if not device_type:
            result.error = f"Unsupported vendor for SSH: {vendor}"
            return result

        # Use asyncio.to_thread for blocking Netmiko calls
        try:
            config_text = await asyncio.to_thread(
                self._ssh_get_config, host, username, password, device_type, vendor
            )
        except Exception as e:
            result.error = f"SSH connection failed: {e}"
            logger.error(f"[{device_name}] SSH error: {e}")
            return result

        if not config_text:
            result.error = "Empty config returned"
            return result

        # Compute hash and store backup
        file_hash = hashlib.sha256(config_text.encode()).hexdigest()
        file_size = len(config_text.encode())

        # Determine version number
        device_backup_dir = os.path.join(BACKUPS_DIR, device_name)
        Path(device_backup_dir).mkdir(parents=True, exist_ok=True)

        version = self._get_next_version(device_name)
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp_str}.conf"
        file_path = os.path.join(device_backup_dir, filename)

        # Write config to file
        with open(file_path, "w") as f:
            f.write(config_text)

        # Check for changes against previous backup
        change_detected = False
        change_summary = ""
        prev_hash = self._get_previous_hash(device_name)
        if prev_hash and prev_hash != file_hash:
            change_detected = True
            change_summary = f"Config changed (hash {prev_hash[:12]}... → {file_hash[:12]}...)"
            # Record change in admin_audit
            async with AsyncSessionLocal() as session:
                await insert_admin_audit(session, {
                    "device_name": device_name,
                    "admin_username": "ssh_collector",
                    "action_type": "config_changed",
                    "change_before": prev_hash,
                    "change_after": file_hash,
                })
        elif not prev_hash:
            change_summary = "Initial backup"

        # Store backup record in database
        from database.models import ConfigBackup
        async with AsyncSessionLocal() as session:
            backup = ConfigBackup(
                id=str(uuid.uuid4()),
                device_name=device_name,
                timestamp=datetime.utcnow(),
                file_path=file_path,
                file_hash=file_hash,
                file_size=file_size,
                version_number=version,
                change_detected=change_detected,
                change_summary=change_summary,
            )
            session.add(backup)
            await session.commit()

        result.success = True
        result.version_number = version
        result.file_path = file_path
        result.file_hash = file_hash
        result.file_size = file_size
        result.change_detected = change_detected
        result.change_summary = change_summary

        logger.info(
            f"[{device_name}] Backup v{version} saved: {file_size} bytes, "
            f"change={'YES' if change_detected else 'NO'}"
        )
        return result

    def _ssh_get_config(
        self, host: str, username: str, password: str,
        device_type: str, vendor: str,
    ) -> str:
        """Blocking SSH call — runs in a thread via asyncio.to_thread()."""
        from netmiko import ConnectHandler

        device_params = {
            "device_type": device_type,
            "host": host,
            "username": username,
            "password": password,
            "timeout": 30,
        }
        commands = _CONFIG_COMMANDS.get(vendor, ["show running-config"])

        conn = ConnectHandler(**device_params)
        try:
            output_parts = []
            for cmd in commands:
                output_parts.append(conn.send_command(cmd, read_timeout=60))
            return "\n".join(output_parts)
        finally:
            conn.disconnect()

    def _get_next_version(self, device_name: str) -> int:
        """Determine next version number from existing backup files."""
        device_dir = os.path.join(BACKUPS_DIR, device_name)
        if not os.path.exists(device_dir):
            return 1
        existing = [f for f in os.listdir(device_dir) if f.endswith(".conf")]
        return len(existing) + 1

    def _get_previous_hash(self, device_name: str) -> Optional[str]:
        """Get the hash of the most recent backup file for comparison."""
        device_dir = os.path.join(BACKUPS_DIR, device_name)
        if not os.path.exists(device_dir):
            return None
        files = sorted(
            [f for f in os.listdir(device_dir) if f.endswith(".conf")],
            reverse=True,
        )
        if len(files) < 2:
            # No previous backup to compare against (current backup is the first or only one)
            return None
        # The second newest file is the "previous" (newest was just written)
        prev_path = os.path.join(device_dir, files[1])
        try:
            with open(prev_path, "r") as f:
                content = f.read()
            return hashlib.sha256(content.encode()).hexdigest()
        except Exception:
            return None


def get_ssh_collector() -> SSHConfigCollector:
    """Return a singleton SSH collector instance."""
    if not hasattr(get_ssh_collector, "_instance"):
        get_ssh_collector._instance = SSHConfigCollector()
    return get_ssh_collector._instance
