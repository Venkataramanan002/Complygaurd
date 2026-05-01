"""
In-memory rate limiter middleware.

Uses a sliding-window counter per IP address.  For production deployments
with multiple workers/replicas, swap the store for Redis.
"""

from __future__ import annotations

import time
import logging
from collections import defaultdict
from typing import Dict, Tuple

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response, JSONResponse

logger = logging.getLogger(__name__)


class _SlidingWindowCounter:
    """Per-IP sliding-window hit counter."""

    def __init__(self, window_seconds: int, max_hits: int):
        self.window = window_seconds
        self.max_hits = max_hits
        self._hits: Dict[str, list] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        # Prune expired hits
        cutoff = now - self.window
        self._hits[key] = hits = [t for t in hits if t > cutoff]
        if len(hits) >= self.max_hits:
            return False
        hits.append(now)
        return True


# Pre-built limiters for specific route patterns
_login_limiter = _SlidingWindowCounter(window_seconds=60, max_hits=5)
_register_limiter = _SlidingWindowCounter(window_seconds=60, max_hits=3)
_upload_limiter = _SlidingWindowCounter(window_seconds=60, max_hits=10)
_default_limiter = _SlidingWindowCounter(window_seconds=60, max_hits=120)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply route-specific rate limits."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ip = _client_ip(request)
        path = request.url.path.rstrip("/")

        # Route-specific limits
        if path == "/api/auth/login" and request.method == "POST":
            limiter = _login_limiter
        elif path == "/api/auth/register" and request.method == "POST":
            limiter = _register_limiter
        elif path in ("/api/upload-config", "/api/upload-data") and request.method == "POST":
            limiter = _upload_limiter
        else:
            limiter = _default_limiter

        if not limiter.is_allowed(ip):
            logger.warning("Rate limit exceeded: %s on %s %s", ip, request.method, path)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Please try again later."},
            )

        return await call_next(request)
