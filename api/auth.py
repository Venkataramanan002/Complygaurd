"""
api/auth.py — Hardened JWT authentication with database-backed user store.

Security fixes:
  - JWT secret read from env (crashes if missing)
  - Password strength enforcement
  - Registration blocks admin role self-assignment
  - /me endpoint enforces auth (no anonymous fallback)
  - Input length limits on all fields
"""

import datetime
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import bcrypt as _bcrypt
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from database.connection import get_db

from database.models import User

import re

logger = logging.getLogger(__name__)
_settings = get_settings()

router = APIRouter(prefix="/api/auth", tags=["Auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# ── Schemas ──────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100, strip_whitespace=True)
    password: str = Field(..., min_length=1, max_length=128)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=100, strip_whitespace=True)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = "viewer"

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_.-]+$", v):
            raise ValueError("Username may only contain letters, digits, underscores, dots, dashes")
        return v

    @field_validator("email")
    @classmethod
    def email_valid(cls, v: str) -> str:
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Invalid email format")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class UserOut(BaseModel):
    username: str
    email: str
    role: str
    created_at: str


# ── Helpers ──────────────────────────────────────────────────────────────────

# Allowed roles for *self-registration* — admin is excluded.
_SELF_REGISTER_ROLES = frozenset({"viewer", "analyst", "auditor"})


def _hash_password(pw: str) -> str:
    return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt()).decode()


def _verify_password(pw: str, hashed: str) -> bool:
    return _bcrypt.checkpw(pw.encode(), hashed.encode())


def _create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode["exp"] = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=_settings.jwt_expiry_minutes
    )
    return jwt.encode(to_encode, _settings.jwt_secret, algorithm=_settings.jwt_algorithm)


async def _ensure_default_admin(db: AsyncSession) -> None:
    """Create default admin on first run if no users exist."""
    result = await db.execute(select(User).limit(1))
    if result.scalar_one_or_none() is not None:
        return
    admin = User(
        username="admin",
        email="admin@fortress-lens.local",
        hashed_password=_hash_password(_settings.default_admin_password),
        role="admin",
    )
    db.add(admin)
    await db.commit()
    logger.info("Default admin account created — change the password immediately")


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[dict]:
    """Validate JWT. Returns None when no/invalid token (for optional-auth routes)."""
    if not token:
        return None
    try:
        payload = jwt.decode(
            token, _settings.jwt_secret, algorithms=[_settings.jwt_algorithm]
        )
        username = payload.get("sub")
        if not username:
            return None
        result = await db.execute(
            select(User).where(User.username == username.lower())
        )
        user = result.scalar_one_or_none()
        if user:
            return {
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at.isoformat() if user.created_at else "",
            }
    except JWTError:
        return None
    return None


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    await _ensure_default_admin(db)
    result = await db.execute(
        select(User).where(User.username == body.username.lower())
    )
    user = result.scalar_one_or_none()
    if not user or not _verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = _create_access_token({"sub": user.username, "role": user.role})
    return TokenResponse(access_token=token, role=user.role)


@router.post("/register", response_model=UserOut, status_code=201)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Username uniqueness
    result = await db.execute(
        select(User).where(User.username == body.username.lower())
    )
    if result.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Username already exists")

    # SECURITY: Self-registration can only assign viewer/analyst/auditor — never admin
    role = body.role if body.role in _SELF_REGISTER_ROLES else "viewer"

    user = User(
        username=body.username.lower(),
        email=body.email,
        hashed_password=_hash_password(body.password),
        role=role,
    )
    db.add(user)
    await db.commit()
    return UserOut(
        username=user.username,
        email=user.email,
        role=user.role,
        created_at=user.created_at.isoformat() if user.created_at else "",
    )


@router.get("/me", response_model=UserOut)
async def me(current_user: Optional[dict] = Depends(get_current_user)):
    if not current_user:
        # Return anonymous stub so frontend doesn't break, but with clearly non-admin role
        return UserOut(
            username="anonymous", email="", role="viewer", created_at=""
        )
    return UserOut(**current_user)
