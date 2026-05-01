"""
Threat Intelligence Service — multi-source IP reputation checking with caching.

Sources: AbuseIPDB, AlienVault OTX, VirusTotal.
Results cached in threat_intel_cache table with configurable TTL.
"""

import datetime
import logging
import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

import aiohttp
import yaml

from database.connection import AsyncSessionLocal
from database.models import ThreatIntelCache
from sqlalchemy import select, and_

logger = logging.getLogger(__name__)

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "threat_intel.yaml")


def _load_config() -> dict:
    try:
        with open(_CONFIG_PATH, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


@dataclass
class ThreatIntelResult:
    ip: str
    source: str
    risk_score: float  # 0-100
    is_malicious: bool
    categories: List[str]
    country: str
    isp: str
    last_reported: str
    reports_count: int
    raw_data: Dict[str, Any]


class ThreatIntelService:
    """Multi-source threat intelligence lookup with caching."""

    def __init__(self):
        self.config = _load_config()
        self.cache_ttl = self.config.get("cache_ttl_hours", 24)

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check an IP across all enabled feeds. Returns aggregated result."""
        results = []
        sources = self.config.get("sources", {})

        for source_name, source_cfg in sources.items():
            if not source_cfg.get("enabled", False):
                continue

            # Check cache first
            cached = await self._get_cached(ip, source_name)
            if cached:
                results.append(cached)
                continue

            # Query the feed
            result = await self._query_source(ip, source_name, source_cfg)
            if result:
                results.append(result)
                await self._cache_result(ip, source_name, result)

        if not results:
            return {
                "ip": ip,
                "combined_score": 0,
                "is_malicious": False,
                "sources": [],
                "status": "no_data",
            }

        # Aggregate scores with weights
        total_weight = 0
        weighted_score = 0
        for r in results:
            weight = sources.get(r.source, {}).get("weight", 0.33)
            weighted_score += r.risk_score * weight
            total_weight += weight

        combined = round(weighted_score / max(total_weight, 0.01), 1)

        return {
            "ip": ip,
            "combined_score": combined,
            "is_malicious": combined > 50,
            "sources": [asdict(r) for r in results],
            "status": "checked",
        }

    async def bulk_check(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Check multiple IPs."""
        results = []
        for ip in ips[:50]:  # limit to 50 to avoid rate limits
            result = await self.check_ip(ip)
            results.append(result)
        return results

    async def get_ioc_summary(self) -> List[Dict[str, Any]]:
        """Return cached threat intel results sorted by risk score."""
        async with AsyncSessionLocal() as session:
            stmt = select(ThreatIntelCache).order_by(ThreatIntelCache.queried_at.desc()).limit(100)
            result = await session.execute(stmt)
            cached = result.scalars().all()

        # Aggregate by IP
        by_ip: Dict[str, Dict] = {}
        for c in cached:
            data = c.result_json or {}
            ip = c.ip
            if ip not in by_ip:
                by_ip[ip] = {"ip": ip, "max_score": 0, "sources": [], "country": "", "is_malicious": False}
            score = data.get("risk_score", 0)
            if score > by_ip[ip]["max_score"]:
                by_ip[ip]["max_score"] = score
                by_ip[ip]["country"] = data.get("country", "")
                by_ip[ip]["is_malicious"] = score > 50
            by_ip[ip]["sources"].append(c.source)

        # Sort by score descending
        return sorted(by_ip.values(), key=lambda x: x["max_score"], reverse=True)[:20]

    # ── Source query implementations ─────────────────────────────────────────

    async def _query_source(self, ip: str, source: str, cfg: dict) -> Optional[ThreatIntelResult]:
        api_key = os.getenv(cfg.get("api_key_env", ""), "")

        try:
            if source == "abuseipdb":
                return await self._query_abuseipdb(ip, api_key)
            elif source == "otx":
                return await self._query_otx(ip, api_key)
            elif source == "virustotal":
                return await self._query_virustotal(ip, api_key)
        except Exception as e:
            logger.error(f"[{source}] Query failed for {ip}: {e}")
        return None

    async def _query_abuseipdb(self, ip: str, api_key: str) -> Optional[ThreatIntelResult]:
        if not api_key:
            return self._unavailable_result(ip, "abuseipdb")
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": api_key, "Accept": "application/json"}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return self._unavailable_result(ip, "abuseipdb")
                data = await resp.json()
                d = data.get("data", {})
                return ThreatIntelResult(
                    ip=ip, source="abuseipdb",
                    risk_score=d.get("abuseConfidenceScore", 0),
                    is_malicious=d.get("abuseConfidenceScore", 0) > 50,
                    categories=[str(c) for c in d.get("categories", [])],
                    country=d.get("countryCode", ""),
                    isp=d.get("isp", ""),
                    last_reported=d.get("lastReportedAt", ""),
                    reports_count=d.get("totalReports", 0),
                    raw_data=d,
                )

    async def _query_otx(self, ip: str, api_key: str) -> Optional[ThreatIntelResult]:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": api_key} if api_key else {}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return self._unavailable_result(ip, "otx")
                data = await resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                reputation = data.get("reputation", 0)
                return ThreatIntelResult(
                    ip=ip, source="otx",
                    risk_score=min(pulse_count * 10 + abs(reputation) * 20, 100),
                    is_malicious=pulse_count > 0,
                    categories=[p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
                    country=data.get("country_code", ""),
                    isp=data.get("asn", ""),
                    last_reported="",
                    reports_count=pulse_count,
                    raw_data={"pulse_count": pulse_count, "reputation": reputation},
                )

    async def _query_virustotal(self, ip: str, api_key: str) -> Optional[ThreatIntelResult]:
        if not api_key:
            return self._unavailable_result(ip, "virustotal")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return self._unavailable_result(ip, "virustotal")
                data = await resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                score = round((malicious / total) * 100, 1)
                return ThreatIntelResult(
                    ip=ip, source="virustotal",
                    risk_score=score,
                    is_malicious=malicious > 0,
                    categories=[],
                    country=attrs.get("country", ""),
                    isp=attrs.get("as_owner", ""),
                    last_reported="",
                    reports_count=malicious,
                    raw_data=stats,
                )

    def _unavailable_result(self, ip: str, source: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            ip=ip, source=source, risk_score=0, is_malicious=False,
            categories=[], country="", isp="", last_reported="",
            reports_count=0, raw_data={"status": "unavailable_no_api_key"},
        )

    # ── Cache ────────────────────────────────────────────────────────────────

    async def _get_cached(self, ip: str, source: str) -> Optional[ThreatIntelResult]:
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=self.cache_ttl)
        async with AsyncSessionLocal() as session:
            stmt = select(ThreatIntelCache).where(
                and_(
                    ThreatIntelCache.ip == ip,
                    ThreatIntelCache.source == source,
                    ThreatIntelCache.queried_at >= cutoff,
                )
            ).order_by(ThreatIntelCache.queried_at.desc()).limit(1)
            result = await session.execute(stmt)
            cached = result.scalar_one_or_none()
            if cached and cached.result_json:
                data = cached.result_json
                return ThreatIntelResult(
                    ip=ip, source=source,
                    risk_score=data.get("risk_score", 0),
                    is_malicious=data.get("is_malicious", False),
                    categories=data.get("categories", []),
                    country=data.get("country", ""),
                    isp=data.get("isp", ""),
                    last_reported=data.get("last_reported", ""),
                    reports_count=data.get("reports_count", 0),
                    raw_data=data.get("raw_data", {}),
                )
        return None

    async def _cache_result(self, ip: str, source: str, result: ThreatIntelResult):
        async with AsyncSessionLocal() as session:
            cache_entry = ThreatIntelCache(
                ip=ip,
                source=source,
                result_json=asdict(result),
                queried_at=datetime.datetime.utcnow(),
                ttl_hours=self.cache_ttl,
            )
            session.add(cache_entry)
            await session.commit()


def get_threat_intel_service() -> ThreatIntelService:
    if not hasattr(get_threat_intel_service, "_instance"):
        get_threat_intel_service._instance = ThreatIntelService()
    return get_threat_intel_service._instance
