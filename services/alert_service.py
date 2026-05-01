"""
Alert Service — stores and retrieves alerts from the database.
"""

import logging
from database.connection import AsyncSessionLocal
from database.models import Alert

logger = logging.getLogger(__name__)


async def create_alert(alert_type: str, severity: str, title: str, message: str, source_device: str = ""):
    """Create a new alert in the database."""
    async with AsyncSessionLocal() as session:
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            source_device=source_device,
        )
        session.add(alert)
        await session.commit()
        logger.info(f"Alert created: [{severity}] {title}")
