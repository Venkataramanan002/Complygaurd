"""
Shared FastAPI dependencies — authentication, authorisation, DB sessions.

Usage in any router:

    from app.dependencies import require_auth, require_role

    @router.get("/secure")
    async def secure(user=Depends(require_auth)):
        ...

    @router.post("/admin-only")
    async def admin(user=Depends(require_role("admin"))):
        ...
"""

from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database.session import get_db
from database.models import User

_settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/login",
    auto_error=False,
)


# ── Core user resolver ────────────────────────────────────────────────────

async def _resolve_user(
    token: Optional[str],
    db: AsyncSession,
) -> Optional[dict]:
    """Decode JWT and look up the user.  Returns None when token is absent."""
    if not token:
        return None
    try:
        payload = jwt.decode(
            token,
            _settings.jwt_secret,
            algorithms=[_settings.jwt_algorithm],
        )
        username: Optional[str] = payload.get("sub")
        if not username:
            return None
        result = await db.execute(
            select(User).where(User.username == username.lower())
        )
        user = result.scalar_one_or_none()
        if not user:
            return None
        return {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at.isoformat() if user.created_at else "",
        }
    except JWTError:
        return None


# ── Optional auth (for public routes that optionally read the user) ───────

async def optional_auth(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[dict]:
    return await _resolve_user(token, db)


# ── Required auth (rejects unauthenticated callers) ──────────────────────

async def require_auth(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = await _resolve_user(token, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ── Role-based auth ──────────────────────────────────────────────────────

def require_role(*allowed_roles: str):
    """Return a dependency that enforces the caller has one of *allowed_roles*."""

    async def _dep(user: dict = Depends(require_auth)) -> dict:
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user['role']}' is not authorised for this action",
            )
        return user

    return _dep
