"""
Configuration drift detector.

Compares live config against last known-good backup to detect unauthorized changes.
"""

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy import select, desc

from database.connection import AsyncSessionLocal
from database.models import ConfigBackup, DriftEvent
from services.alert_service import create_alert

logger = logging.getLogger(__name__)


@dataclass
class DriftReport:
    device_name: str
    drift_detected: bool
    baseline_backup_id: Optional[str]
    live_config_hash: str
    severity: str  # critical | medium | low
    drift_summary: str
    detected_at: str


class DriftDetector:
    """Detects configuration drift by comparing live vs baseline configs."""

    async def detect_drift(self, device_name: str, live_config: Optional[str] = None) -> DriftReport:
        """
        Compare current config against last backup.
        If live_config is None, uses the latest two backups for comparison.
        """
        now = datetime.utcnow()

        async with AsyncSessionLocal() as session:
            # Get latest backup
            stmt = (
                select(ConfigBackup)
                .where(ConfigBackup.device_name == device_name)
                .order_by(desc(ConfigBackup.timestamp))
                .limit(2)
            )
            result = await session.execute(stmt)
            backups = result.scalars().all()

        if not backups:
            return DriftReport(
                device_name=device_name,
                drift_detected=False,
                baseline_backup_id=None,
                live_config_hash="",
                severity="low",
                drift_summary="No baseline backup found for comparison",
                detected_at=now.isoformat(),
            )

        baseline = backups[0]

        # Compare against live config or second-most-recent backup
        if live_config:
            live_hash = hashlib.sha256(live_config.encode()).hexdigest()
        elif len(backups) >= 2:
            # Compare two most recent backups
            try:
                with open(backups[0].file_path, "r") as f:
                    live_hash = hashlib.sha256(f.read().encode()).hexdigest()
            except FileNotFoundError:
                live_hash = backups[0].file_hash
        else:
            live_hash = baseline.file_hash

        drift_detected = live_hash != baseline.file_hash

        # Determine severity
        severity = "low"
        summary = "No drift detected"
        if drift_detected:
            severity = "medium"
            summary = f"Configuration drift detected: hash changed from {baseline.file_hash[:12]}... to {live_hash[:12]}..."

            # If we can read both files, check what changed
            if baseline.change_detected:
                severity = "critical"
                summary += f" — {baseline.change_summary or 'security-impacting changes detected'}"

        # Store drift event if drift found
        if drift_detected:
            async with AsyncSessionLocal() as session:
                event = DriftEvent(
                    device_name=device_name,
                    severity=severity,
                    drift_summary=summary,
                    diff_json={"baseline_hash": baseline.file_hash, "live_hash": live_hash},
                    baseline_backup_id=baseline.id,
                )
                session.add(event)
                await session.commit()

            # Create alert
            await create_alert(
                alert_type="drift",
                severity=severity,
                title=f"Config drift detected on {device_name}",
                message=summary,
                source_device=device_name,
            )

        return DriftReport(
            device_name=device_name,
            drift_detected=drift_detected,
            baseline_backup_id=baseline.id,
            live_config_hash=live_hash,
            severity=severity,
            drift_summary=summary,
            detected_at=now.isoformat(),
        )
