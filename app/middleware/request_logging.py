"""
Request logging middleware — audit trail for all API calls.

Logs: timestamp, client IP, method, path, status code, duration.
Critical for a security product to track who accessed what.
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

logger = logging.getLogger("fortress.access")


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every API request with timing info."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = uuid.uuid4().hex[:12]
        request.state.request_id = request_id
        ip = _client_ip(request)

        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000

        # Only log API requests (skip static files)
        path = request.url.path
        if path.startswith("/api"):
            logger.info(
                "%s | %s | %s %s | %d | %.1fms",
                request_id,
                ip,
                request.method,
                path,
                response.status_code,
                duration_ms,
            )

        response.headers["X-Request-ID"] = request_id
        return response
