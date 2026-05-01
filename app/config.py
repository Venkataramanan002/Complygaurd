"""
Centralised configuration via pydantic-settings.

Every secret and tuneable is an environment variable with a *safe* default
(or no default at all for secrets — the app crashes on startup if they're
missing, which is the correct behaviour for a security product).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./firewall.db"

    # ── Authentication ────────────────────────────────────────────────────
    # NO default — forces operators to set a real secret.
    jwt_secret: str = Field(..., description="JWT signing key (REQUIRED)")
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 480

    # First-run admin account
    default_admin_password: str = Field(
        ..., description="Initial admin password (REQUIRED)"
    )

    # ── Server ────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    debug: bool = False

    # ── CORS ──────────────────────────────────────────────────────────────
    cors_origins: str = ""  # comma-separated or "*"

    @property
    def cors_origin_list(self) -> List[str]:
        raw = self.cors_origins.strip()
        if raw == "*":
            return ["*"]
        if raw:
            return [o.strip() for o in raw.split(",")]
        return [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:5174",
            "http://localhost:8080",
            "http://localhost:8081",
        ]

    # ── Upload limits ─────────────────────────────────────────────────────
    max_upload_bytes: int = 50 * 1024 * 1024  # 50 MB

    # ── Rate limiting ─────────────────────────────────────────────────────
    login_rate_limit: str = "5/minute"
    register_rate_limit: str = "3/minute"
    default_rate_limit: str = "60/minute"

    # ── External integrations (all optional) ──────────────────────────────
    pa_api_key: Optional[str] = None
    forti_api_token: Optional[str] = None
    cisco_fdm_token: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    vt_api_key: Optional[str] = None
    redis_url: Optional[str] = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
