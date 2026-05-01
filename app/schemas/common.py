"""Pydantic schemas shared across routers."""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional, Any


class ReachabilityRequest(BaseModel):
    source_zone: str


class UploadResponse(BaseModel):
    upload_id: str
    vendor: str
    message: str = ""
    processed_rows: int = 0
    errors_count: int = 0
