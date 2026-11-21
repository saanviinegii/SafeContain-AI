"""SafeContain AI JWT Authentication & Role Authorization Engine.

Provides cryptographic token generation, validation, expiration enforcement,
and role-based access control dependencies for FastAPI endpoints.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Callable, Dict, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt

from backend.app.core.config import settings
from backend.app.security.roles import AppRole, has_sufficient_privilege, normalize_app_role
from backend.app.security.user_store import UserRecord, user_store

logger = logging.getLogger(__name__)

# OAuth2 password bearer scheme; auto_error=False allows structured custom error responses
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_PREFIX}/auth/login",
    auto_error=False
)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed, expiring JWT access token with standard claims."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": now,
        "iss": "safecontain-ai",
    })

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and cryptographically verifies a JWT access token.

    Raises:
        HTTPException(401): If token is expired, tampered with, or malformed.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "sub"]}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"The token has expired\""},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
        )


async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> UserRecord:
    """FastAPI dependency to extract and validate the authenticated user from the Bearer token."""
    if not settings.AUTH_ENABLED:
        # Development / test override only if explicitly configured
        admin = user_store.get_user_by_username("admin")
        if admin:
            return admin

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided. Include 'Authorization: Bearer <token>' header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    username: Optional[str] = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token: missing subject (sub) claim.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = user_store.get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account associated with this token was not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated. Contact an administrator.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(min_role: AppRole) -> Callable:
    """Dependency factory that validates the authenticated user satisfies the required role tier."""
    async def role_checker(current_user: UserRecord = Depends(get_current_user)) -> UserRecord:
        if not has_sufficient_privilege(current_user.role, min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Forbidden: Insufficient privileges. Required role: '{min_role.value}' or higher. "
                    f"Your active verified role is '{current_user.role.value}'."
                )
            )
        return current_user

    return role_checker


# Reusable FastAPI dependency shorthands
require_admin = require_role(AppRole.ADMIN)
require_analyst = require_role(AppRole.ANALYST)
require_viewer = require_role(AppRole.VIEWER)
