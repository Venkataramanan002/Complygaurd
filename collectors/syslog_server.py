"""
Production-grade async UDP+TCP syslog receiver.

Listens on configurable ports, buffers incoming messages in an asyncio.Queue,
and drains them in batches — auto-detecting vendor (Palo Alto / Cisco / Fortinet)
before routing each line to the correct parser and inserting into the database.
"""

import asyncio
import ipaddress
import logging
import time
import os
from typing import Dict, Any, List, Optional

import yaml

from parsers.paloalto import PaloAltoParser
from parsers.fortinet import FortinetParser
from parsers.cisco import CiscoParser
from database.connection import AsyncSessionLocal
from database.operations import insert_connection, insert_threat, insert_admin_audit

logger = logging.getLogger(__name__)

# ── Config loader ────────────────────────────────────────────────────────────

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "syslog.yaml")


def _load_config() -> dict:
    """Load syslog.yaml; fall back to sensible defaults."""
    try:
        with open(_CONFIG_PATH, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("config/syslog.yaml not found — using defaults")
        return {}


def _parse_allowed_networks(sources: list) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Convert CIDR strings to network objects for fast membership checks."""
    nets = []
    for s in sources or []:
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            logger.warning(f"Invalid allowed_source entry ignored: {s}")
    return nets


# ── Syslog Server ────────────────────────────────────────────────────────────

class SyslogServer:
    """Async syslog receiver with queue-buffered batch processing."""

    _instance: Optional["SyslogServer"] = None  # module-level singleton

    def __init__(self):
        cfg = _load_config()

        # Ports & networking
        self.host = "0.0.0.0"
        self.udp_port: int = cfg.get("udp_port", 514)
        self.tcp_port: int = cfg.get("tcp_port", 1514)
        self.allowed_networks = _parse_allowed_networks(cfg.get("allowed_sources"))

        # Queue & batching
        self.buffer_size: int = cfg.get("buffer_size", 50_000)
        self.batch_size: int = cfg.get("batch_size", 500)
        self.flush_interval: float = cfg.get("flush_interval_seconds", 2)

        # Parsers
        self.pa_parser = PaloAltoParser()
        self.forti_parser = FortinetParser()
        self.cisco_parser = CiscoParser()

        # Async primitives (created lazily in start())
        self._queue: Optional[asyncio.Queue] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._udp_transport = None
        self._tcp_server = None

        # Runtime stats
        self._running = False
        self._start_time: Optional[float] = None
        self._messages_received = 0
        self._messages_parsed = 0
        self._messages_failed = 0
        self._connections_inserted = 0
        self._threats_inserted = 0

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def start(self):
        """Begin listening on UDP + TCP and start the batch consumer."""
        if self._running:
            logger.warning("Syslog server already running")
            return

        self._queue = asyncio.Queue(maxsize=self.buffer_size)
        self._start_time = time.time()
        self._running = True

        loop = asyncio.get_running_loop()

        # UDP listener
        try:
            self._udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: _SyslogUDPProtocol(self),
                local_addr=(self.host, self.udp_port),
            )
            logger.info(f"Syslog UDP listening on {self.host}:{self.udp_port}")
        except OSError as e:
            logger.error(f"Cannot bind UDP {self.udp_port}: {e}")
            self._udp_transport = None

        # TCP listener
        try:
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp_client, self.host, self.tcp_port,
            )
            logger.info(f"Syslog TCP listening on {self.host}:{self.tcp_port}")
        except OSError as e:
            logger.error(f"Cannot bind TCP {self.tcp_port}: {e}")
            self._tcp_server = None

        # Batch consumer
        self._consumer_task = asyncio.create_task(self._batch_consumer())
        logger.info("Syslog batch consumer started")

    async def stop(self):
        """Gracefully shut down listeners and drain remaining messages."""
        if not self._running:
            return

        self._running = False

        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None

        # Let consumer finish current batch
        if self._consumer_task and not self._consumer_task.done():
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass
            self._consumer_task = None

        # Drain any remaining queued messages
        if self._queue and not self._queue.empty():
            remaining: List[tuple] = []
            while not self._queue.empty():
                remaining.append(self._queue.get_nowait())
            if remaining:
                await self._process_batch(remaining)

        logger.info("Syslog server stopped")

    def status(self) -> dict:
        """Return current server statistics."""
        uptime = round(time.time() - self._start_time, 1) if self._start_time and self._running else 0
        elapsed = max(uptime, 1)
        return {
            "running": self._running,
            "udp_port": self.udp_port,
            "tcp_port": self.tcp_port,
            "messages_received": self._messages_received,
            "messages_parsed": self._messages_parsed,
            "messages_failed": self._messages_failed,
            "connections_inserted": self._connections_inserted,
            "threats_inserted": self._threats_inserted,
            "queue_depth": self._queue.qsize() if self._queue else 0,
            "messages_per_second": round(self._messages_received / elapsed, 2),
            "uptime_seconds": uptime,
        }

    # ── source filtering ─────────────────────────────────────────────────────

    def _is_allowed(self, source_ip: str) -> bool:
        if not self.allowed_networks:
            return True  # no whitelist = accept all
        try:
            addr = ipaddress.ip_address(source_ip)
            return any(addr in net for net in self.allowed_networks)
        except ValueError:
            return False

    # ── TCP handler ──────────────────────────────────────────────────────────

    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"

        if not self._is_allowed(source_ip):
            writer.close()
            return

        try:
            while self._running:
                data = await reader.read(8192)
                if not data:
                    break
                for line in data.decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line:
                        await self._enqueue(line, source_ip)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    # ── queue ingestion ──────────────────────────────────────────────────────

    async def _enqueue(self, message: str, source_ip: str):
        """Put a raw syslog line into the processing queue."""
        self._messages_received += 1
        try:
            self._queue.put_nowait((message, source_ip))
        except asyncio.QueueFull:
            self._messages_failed += 1
            logger.warning("Syslog queue full — dropping message")

    # ── batch consumer ───────────────────────────────────────────────────────

    async def _batch_consumer(self):
        """Drain the queue in batches of `batch_size` every `flush_interval` seconds."""
        while self._running:
            batch: List[tuple] = []
            deadline = time.time() + self.flush_interval

            while len(batch) < self.batch_size:
                remaining = max(deadline - time.time(), 0)
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                    batch.append(item)
                except asyncio.TimeoutError:
                    break

            if batch:
                await self._process_batch(batch)

    async def _process_batch(self, batch: List[tuple]):
        """Parse a batch of raw messages and insert into the database."""
        conn_records: List[dict] = []
        threat_records: List[dict] = []
        audit_records: List[dict] = []

        for message, source_ip in batch:
            parsed = self._detect_and_parse(message)
            if not parsed:
                self._messages_failed += 1
                continue

            self._messages_parsed += 1
            record_type = parsed.pop("type", None)

            if record_type == "connection":
                parsed["source"] = "syslog"
                conn_records.append(parsed)
            elif record_type == "threat":
                parsed["source"] = "syslog"
                threat_records.append(parsed)
            elif record_type == "admin_audit":
                audit_records.append(parsed)
            else:
                self._messages_failed += 1

        # Bulk insert (one session per batch for efficiency)
        if conn_records:
            async with AsyncSessionLocal() as session:
                for rec in conn_records:
                    try:
                        await insert_connection(session, rec)
                        self._connections_inserted += 1
                    except Exception as e:
                        logger.error(f"Insert connection error: {e}")
                        self._messages_failed += 1

        if threat_records:
            async with AsyncSessionLocal() as session:
                for rec in threat_records:
                    try:
                        await insert_threat(session, rec)
                        self._threats_inserted += 1
                    except Exception as e:
                        logger.error(f"Insert threat error: {e}")
                        self._messages_failed += 1

        if audit_records:
            async with AsyncSessionLocal() as session:
                for rec in audit_records:
                    try:
                        await insert_admin_audit(session, rec)
                    except Exception as e:
                        logger.error(f"Insert audit error: {e}")
                        self._messages_failed += 1

    # ── vendor detection & parsing ───────────────────────────────────────────

    def _detect_and_parse(self, message: str) -> Dict[str, Any]:
        """Auto-detect vendor by message patterns and route to the right parser."""
        try:
            # Cisco ASA — distinctive %ASA- prefix
            if "%ASA-" in message:
                return self.cisco_parser.parse(message)

            # Fortinet — key=value with specific keys
            if "devname=" in message or "logid=" in message or "type=traffic" in message:
                return self.forti_parser.parse(message)

            # Palo Alto — CSV with comma-separated fields
            # Check for PA CSV header patterns (future_use fields, TRAFFIC/THREAT log types)
            if "," in message:
                parts = message.split(",")
                if len(parts) > 5:
                    return self.pa_parser.parse(message)

            return {}
        except Exception as e:
            logger.error(f"Parse error: {e}")
            return {}


# ── UDP Protocol ─────────────────────────────────────────────────────────────

class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Async datagram handler that feeds into the server's queue."""

    def __init__(self, server: SyslogServer):
        self.server = server

    def datagram_received(self, data: bytes, addr: tuple):
        source_ip = addr[0]
        if not self.server._is_allowed(source_ip):
            return
        message = data.decode("utf-8", errors="ignore").strip()
        if message:
            # Schedule enqueue on the event loop
            asyncio.ensure_future(self.server._enqueue(message, source_ip))


# ── Module-level singleton accessor ──────────────────────────────────────────

def get_syslog_server() -> SyslogServer:
    """Return the module-level SyslogServer singleton."""
    if SyslogServer._instance is None:
        SyslogServer._instance = SyslogServer()
    return SyslogServer._instance
