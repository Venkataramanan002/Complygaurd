"""
JWT auth guard middleware.

Every /api/* route requires a valid Bearer token except the public allowlist.
Role enforcement (RBAC): viewer/auditor are read-only (GET only); analyst and
admin may mutate. /api/auth/register is additionally admin-gated in its
endpoint. Enforced centrally here so no individual router can forget to opt in.

Role comes from the JWT claim, so a role change takes effect on next login
(tokens live 8h). Acceptable for this deployment size.
"""

from __future__ import annotations

import logging

from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import get_settings

logger = logging.getLogger(__name__)

_PUBLIC_PATHS = frozenset({
    "/api/health",
    "/api/auth/login",
})


class AuthGuardMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated /api requests with 401."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path.rstrip("/")
        # OPTIONS passes through so CORS preflight (which carries no auth) works
        if (
            not path.startswith("/api")
            or path in _PUBLIC_PATHS
            or request.method == "OPTIONS"
        ):
            return await call_next(request)

        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        if token:
            settings = get_settings()
            try:
                payload = jwt.decode(
                    token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
                )
                # RBAC: mutations require analyst or admin; GET is open to all roles
                role = payload.get("role", "viewer")
                if request.method != "GET" and role not in ("admin", "analyst"):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": f"Role '{role}' is read-only"},
                    )
                return await call_next(request)
            except JWTError:
                logger.warning("Rejected invalid JWT on %s %s", request.method, path)
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
