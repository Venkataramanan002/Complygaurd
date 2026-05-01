"""
Upload size enforcement middleware.

Rejects request bodies that exceed the configured maximum *before* they are
fully buffered into memory.  Applied to upload-related routes.
"""

from __future__ import annotations

import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from app.config import get_settings

logger = logging.getLogger(__name__)
_settings = get_settings()

_UPLOAD_PATHS = frozenset({"/api/upload-config", "/api/upload-data", "/api/validate-upload"})


class UploadSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized uploads before reading the entire body."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.method in ("POST", "PUT") and request.url.path.rstrip("/") in _UPLOAD_PATHS:
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    size = int(content_length)
                    max_bytes = _settings.max_upload_bytes
                    if size > max_bytes:
                        mb = max_bytes / (1024 * 1024)
                        logger.warning(
                            "Upload rejected: %d bytes exceeds %d MB limit",
                            size, mb,
                        )
                        return JSONResponse(
                            status_code=413,
                            content={
                                "detail": f"File too large. Maximum upload size is {mb:.0f} MB."
                            },
                        )
                except ValueError:
                    pass

        return await call_next(request)
