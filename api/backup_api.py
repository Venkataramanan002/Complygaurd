"""
Config Backup API — trigger backups, view history, download, and diff endpoints.

SECURITY: All endpoints require authentication. Trigger backup requires admin.
"""

import difflib
import os
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from collectors.ssh_collector import get_ssh_collector
from collectors.api_client import load_devices
from database.connection import get_db
from database.models import ConfigBackup
from app.dependencies import require_auth, require_role

router = APIRouter(prefix="/api/backups", tags=["Config Backups"])


@router.post("/trigger/{device_name}")
async def trigger_backup(device_name: str, user: dict = Depends(require_role("admin"))):
    """Trigger an SSH config backup for a specific device."""
    devices = load_devices()
    device = next((d for d in devices if d.name == device_name), None)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{device_name}' not found")

    collector = get_ssh_collector()
    result = await collector.backup_config({
        "name": device.name,
        "host": device.host,
        "vendor": device.vendor,
        "credentials_env_var": device.credentials_env_var,
    })
    return {
        "device_name": result.device_name,
        "success": result.success,
        "version_number": result.version_number,
        "file_hash": result.file_hash,
        "file_size": result.file_size,
        "change_detected": result.change_detected,
        "change_summary": result.change_summary,
        "error": result.error,
    }


@router.get("/history/{device_name}")
async def backup_history(
    device_name: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_auth),
):
    """Get paginated backup history for a device."""
    stmt = (
        select(ConfigBackup)
        .where(ConfigBackup.device_name == device_name)
        .order_by(desc(ConfigBackup.timestamp))
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(stmt)
    backups = result.scalars().all()
    return {
        "device_name": device_name,
        "backups": [
            {
                "id": b.id,
                "timestamp": b.timestamp.isoformat() if b.timestamp else None,
                "file_hash": b.file_hash,
                "file_size": b.file_size,
                "version_number": b.version_number,
                "change_detected": b.change_detected,
                "change_summary": b.change_summary,
            }
            for b in backups
        ],
    }


@router.get("/diff/{backup_id_a}/{backup_id_b}")
async def backup_diff(
    backup_id_a: str,
    backup_id_b: str,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_auth),
):
    """Return unified diff between two backup files."""
    backup_a = await _get_backup(db, backup_id_a)
    backup_b = await _get_backup(db, backup_id_b)

    content_a = _read_backup_file(backup_a.file_path)
    content_b = _read_backup_file(backup_b.file_path)

    diff_lines = list(difflib.unified_diff(
        content_a.splitlines(keepends=True),
        content_b.splitlines(keepends=True),
        fromfile=f"v{backup_a.version_number} ({backup_a.file_hash[:12]})",
        tofile=f"v{backup_b.version_number} ({backup_b.file_hash[:12]})",
    ))

    return {
        "backup_a": {
            "id": backup_a.id,
            "version": backup_a.version_number,
            "hash": backup_a.file_hash,
            "timestamp": backup_a.timestamp.isoformat(),
        },
        "backup_b": {
            "id": backup_b.id,
            "version": backup_b.version_number,
            "hash": backup_b.file_hash,
            "timestamp": backup_b.timestamp.isoformat(),
        },
        "diff": "".join(diff_lines),
        "additions": sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++")),
        "deletions": sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---")),
    }


@router.get("/download/{backup_id}")
async def download_backup(backup_id: str, db: AsyncSession = Depends(get_db), user: dict = Depends(require_auth)):
    """Download a backup file."""
    backup = await _get_backup(db, backup_id)

    # Path traversal protection: ensure file_path is under BACKUPS_DIR
    from collectors.ssh_collector import BACKUPS_DIR
    real_path = os.path.realpath(backup.file_path)
    base_path = os.path.realpath(BACKUPS_DIR)
    if not real_path.startswith(base_path):
        raise HTTPException(status_code=403, detail="Access denied")

    if not os.path.exists(real_path):
        raise HTTPException(status_code=404, detail="Backup file not found on disk")

    return FileResponse(
        real_path,
        media_type="text/plain",
        filename=f"{backup.device_name}_v{backup.version_number}.conf",
    )


async def _get_backup(db: AsyncSession, backup_id: str) -> ConfigBackup:
    """Fetch a ConfigBackup by ID or raise 404."""
    result = await db.execute(
        select(ConfigBackup).where(ConfigBackup.id == backup_id)
    )
    backup = result.scalar_one_or_none()
    if not backup:
        raise HTTPException(status_code=404, detail=f"Backup '{backup_id}' not found")
    return backup


def _read_backup_file(file_path: str) -> str:
    """Read backup file contents with path safety check."""
    from collectors.ssh_collector import BACKUPS_DIR
    real_path = os.path.realpath(file_path)
    base_path = os.path.realpath(BACKUPS_DIR)
    if not real_path.startswith(base_path):
        raise HTTPException(status_code=403, detail="Access denied")
    try:
        with open(real_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Backup file not found on disk")
