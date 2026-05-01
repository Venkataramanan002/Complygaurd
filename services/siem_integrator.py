"""
SIEM Integrator — forward security events to external SIEM platforms.

Supports:
  * Webhook (generic JSON POST)
  * Syslog (UDP RFC 5424)
  * Splunk HEC (HTTP Event Collector)

Target configuration lives in config/siem.yaml.
"""

import datetime
import json
import logging
import os
import socket
from typing import Any, Dict, List, Optional

import aiohttp
import yaml

logger = logging.getLogger(__name__)

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "siem.yaml")


# ── Configuration loader ────────────────────────────────────────────────────

def _load_config() -> dict:
    """Load SIEM targets from config/siem.yaml."""
    try:
        with open(_CONFIG_PATH, "r") as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        logger.warning("SIEM config not found at %s — no targets loaded", _CONFIG_PATH)
        return {}


# ── CEF formatter ───────────────────────────────────────────────────────────

def _escape_cef(value: str) -> str:
    """Escape characters that are special in CEF extensions."""
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")


# ── SIEM Integrator class ──────────────────────────────────────────────────

class SIEMIntegrator:
    """Routes security events to configured SIEM targets."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = _load_config() if config_path is None else self._load(config_path)
        self.targets: List[dict] = self.config.get("targets", [])

    # -- public API -----------------------------------------------------------

    def format_cef(
        self,
        event_type: str,
        severity: int,
        device: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Format an event as a CEF (Common Event Format) string.

        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions

        Parameters
        ----------
        event_type : str   Signature ID / event class (e.g. "drift_detected").
        severity   : int   0-10 scale per CEF spec.
        device     : str   Device hostname or identifier.
        message    : str   Human-readable event name.
        details    : dict  Optional key=value extension pairs.

        Returns
        -------
        str  The CEF-formatted line.
        """
        severity = max(0, min(severity, 10))
        extensions = ""
        if details:
            pairs = [
                f"{_escape_cef(str(k))}={_escape_cef(str(v))}"
                for k, v in details.items()
            ]
            extensions = " ".join(pairs)

        cef = (
            f"CEF:0|FortressLens|FirewallReviewer|1.0|{event_type}|{message}|{severity}|"
            f"dvchost={_escape_cef(device)} {extensions}"
        ).rstrip()
        return cef

    async def forward_webhook(
        self,
        url: str,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Send a JSON POST request to an arbitrary webhook URL.

        Returns
        -------
        dict  {"status": int, "body": str}
        """
        send_headers = {"Content-Type": "application/json"}
        if headers:
            send_headers.update(headers)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=send_headers,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    body = await resp.text()
                    logger.info("Webhook POST %s → %d", url, resp.status)
                    return {"status": resp.status, "body": body}
        except Exception as exc:
            logger.error("Webhook POST %s failed: %s", url, exc)
            return {"status": 0, "body": str(exc)}

    async def forward_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Route a security event to all enabled targets defined in config/siem.yaml.

        Parameters
        ----------
        event : dict
            Must contain at least:
              event_type (str), severity (int), device (str), message (str).
            May also contain a "details" dict for additional context.

        Returns
        -------
        list[dict]  One result dict per target attempted.
        """
        results: List[Dict[str, Any]] = []

        for target in self.targets:
            if not target.get("enabled", False):
                continue

            target_type = (target.get("type") or "").lower()
            target_name = target.get("name", "unnamed")

            try:
                if target_type == "webhook":
                    result = await self._send_webhook(target, event)
                elif target_type == "syslog":
                    result = self._send_syslog(target, event)
                elif target_type == "splunk":
                    result = await self._send_splunk(target, event)
                else:
                    result = {"target": target_name, "status": "skipped", "reason": f"unknown type '{target_type}'"}

                results.append(result)
            except Exception as exc:
                logger.error("SIEM target '%s' error: %s", target_name, exc)
                results.append({"target": target_name, "status": "error", "reason": str(exc)})

        if not results:
            logger.debug("No enabled SIEM targets — event not forwarded")

        return results

    # -- target-specific senders ─────────────────────────────────────────────

    async def _send_webhook(self, target: dict, event: Dict[str, Any]) -> dict:
        """POST event JSON to a generic webhook endpoint."""
        endpoint = target.get("endpoint", "")
        if not endpoint:
            return {"target": target.get("name"), "status": "error", "reason": "no endpoint configured"}

        headers: Dict[str, str] = {}
        auth_env = target.get("auth_env_var")
        if auth_env:
            token = os.getenv(auth_env, "")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        payload = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            **event,
        }
        result = await self.forward_webhook(endpoint, payload, headers)
        return {"target": target.get("name"), **result}

    def _send_syslog(self, target: dict, event: Dict[str, Any]) -> dict:
        """Send CEF-formatted message via UDP syslog."""
        endpoint = target.get("endpoint", "")
        if not endpoint:
            return {"target": target.get("name"), "status": "error", "reason": "no endpoint configured"}

        # Parse host:port
        parts = endpoint.rsplit(":", 1)
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 514

        cef_line = self.format_cef(
            event_type=event.get("event_type", "generic"),
            severity=event.get("severity", 5),
            device=event.get("device", "fortress-lens"),
            message=event.get("message", ""),
            details=event.get("details"),
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(cef_line.encode("utf-8"), (host, port))
            sock.close()
            logger.info("Syslog UDP sent to %s:%d (%d bytes)", host, port, len(cef_line))
            return {"target": target.get("name"), "status": 200, "body": "sent"}
        except OSError as exc:
            logger.error("Syslog send to %s:%d failed: %s", host, port, exc)
            return {"target": target.get("name"), "status": 0, "body": str(exc)}

    async def _send_splunk(self, target: dict, event: Dict[str, Any]) -> dict:
        """POST event to Splunk HTTP Event Collector."""
        endpoint = target.get("endpoint", "")
        if not endpoint:
            return {"target": target.get("name"), "status": "error", "reason": "no endpoint configured"}

        auth_env = target.get("auth_env_var")
        token = os.getenv(auth_env, "") if auth_env else ""

        headers = {
            "Content-Type": "application/json",
        }
        if token:
            headers["Authorization"] = f"Splunk {token}"

        payload = {
            "event": {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                **event,
            },
            "sourcetype": "fortress_lens",
            "source": "firewall_reviewer",
        }
        result = await self.forward_webhook(endpoint, payload, headers)
        return {"target": target.get("name"), **result}

    # -- utility ─────────────────────────────────────────────────────────────

    @staticmethod
    def _load(path: str) -> dict:
        try:
            with open(path, "r") as fh:
                return yaml.safe_load(fh) or {}
        except FileNotFoundError:
            return {}


# ── Singleton accessor ──────────────────────────────────────────────────────

def get_siem_integrator() -> SIEMIntegrator:
    """Return a lazily-initialised singleton SIEMIntegrator."""
    if not hasattr(get_siem_integrator, "_instance"):
        get_siem_integrator._instance = SIEMIntegrator()
    return get_siem_integrator._instance
