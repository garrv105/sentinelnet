"""
SentinelNet - API Authentication & Authorization
=================================================
Implements two complementary auth mechanisms:

  1. JWT Bearer Token — issued by /auth/token, short-lived (configurable TTL)
  2. API Key Header  — static key via X-API-Key header, for service-to-service

Both mechanisms resolve to a User object consumed by FastAPI dependency injection.

Environment variables (all have secure defaults for development):
  SENTINELNET_JWT_SECRET   — HS256 signing secret (generate with: openssl rand -hex 32)
  SENTINELNET_JWT_TTL_MIN  — access token lifetime in minutes (default 60)
  SENTINELNET_API_KEYS     — comma-separated list of valid API keys
  SENTINELNET_ADMIN_USER   — admin username for /auth/token (default "admin")
  SENTINELNET_ADMIN_PASS   — admin password hash (bcrypt, default "changeme")
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (loaded from environment)
# ---------------------------------------------------------------------------

JWT_SECRET: str = os.getenv(
    "SENTINELNET_JWT_SECRET",
    "CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32",  # noqa: S106 — dev default
)
JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES: int = int(os.getenv("SENTINELNET_JWT_TTL_MIN", "60"))

_raw_api_keys: str = os.getenv("SENTINELNET_API_KEYS", "")
VALID_API_KEYS: set[str] = {
    k.strip() for k in _raw_api_keys.split(",") if k.strip()
}

ADMIN_USERNAME: str = os.getenv("SENTINELNET_ADMIN_USER", "admin")
# Default password hash for "changeme" — MUST be overridden in production
_DEFAULT_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4oHXyZ8QBK"
ADMIN_PASS_HASH: str = os.getenv("SENTINELNET_ADMIN_PASS_HASH", _DEFAULT_HASH)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class CurrentUser(BaseModel):
    username: str
    auth_method: str  # "jwt" | "api_key"
    is_admin: bool = False


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


def hash_password(plain: str) -> str:
    """Utility: generate a bcrypt hash (for setting SENTINELNET_ADMIN_PASS_HASH)."""
    return _pwd_ctx.hash(plain)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)


def create_access_token(username: str, extra_claims: Optional[dict] = None) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_TTL_MINUTES),
        "jti": secrets.token_hex(8),  # unique token ID (replay protection)
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT. Raises HTTPException on any failure."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ---------------------------------------------------------------------------
# API Key helpers
# ---------------------------------------------------------------------------

def _constant_time_key_check(candidate: str) -> bool:
    """Timing-safe check against all valid API keys."""
    for valid_key in VALID_API_KEYS:
        if secrets.compare_digest(
            hashlib.sha256(candidate.encode()).digest(),
            hashlib.sha256(valid_key.encode()).digest(),
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# FastAPI dependency: get_current_user
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> CurrentUser:
    """
    Resolves a CurrentUser from either:
      - Authorization: Bearer <jwt>
      - X-API-Key: <key>

    Raises 401 if neither is present or both are invalid.
    """
    # --- Try JWT first ---
    if credentials is not None:
        payload = decode_access_token(credentials.credentials)
        username: str = payload.get("sub", "unknown")
        return CurrentUser(
            username=username,
            auth_method="jwt",
            is_admin=(username == ADMIN_USERNAME),
        )

    # --- Try API Key ---
    if x_api_key is not None:
        if not VALID_API_KEYS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No API keys configured on server. Use JWT auth.",
            )
        if _constant_time_key_check(x_api_key):
            return CurrentUser(
                username="api_key_user",
                auth_method="api_key",
                is_admin=False,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "X-API-Key"},
        )

    # --- No credentials ---
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide 'Authorization: Bearer <token>' or 'X-API-Key: <key>'",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_admin(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Stricter dependency — requires admin privileges."""
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user


# ---------------------------------------------------------------------------
# /auth/token endpoint handler (called from server.py)
# ---------------------------------------------------------------------------

async def login_for_access_token(form_data: OAuth2PasswordRequestForm) -> TokenResponse:
    """
    Validates username/password and returns a JWT access token.
    Plugged into POST /auth/token by server.py.
    """
    if form_data.username != ADMIN_USERNAME or not verify_password(
        form_data.password, ADMIN_PASS_HASH
    ):
        # Use consistent timing to prevent user enumeration
        _pwd_ctx.dummy_verify()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(form_data.username, extra_claims={"role": "admin"})
    logger.info("JWT issued for user '%s'", form_data.username)
    return TokenResponse(
        access_token=token,
        expires_in=JWT_TTL_MINUTES * 60,
    )
