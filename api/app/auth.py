"""Supabase JWT verification.

Supabase signs access tokens HS256 with the project's JWT secret, so this is
the real verification path, not a stand-in: point SUPABASE_JWT_SECRET at the
project secret and the same code verifies production tokens.

The role claim is never trusted from the token -- it is read from the
profiles table, so a user cannot mint themselves an admin session.
"""

import os
import uuid

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import Profile, get_session

JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET", "dev-only-secret-change-in-env")
JWT_AUDIENCE = "authenticated"

# auto_error=False so guests reach the endpoint instead of getting a 403.
_optional = HTTPBearer(auto_error=False)
_required = HTTPBearer(auto_error=True)


def _user_id(creds: HTTPAuthorizationCredentials) -> uuid.UUID:
    try:
        claims = jwt.decode(
            creds.credentials,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=JWT_AUDIENCE,
        )
        return uuid.UUID(claims["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError) as exc:
        raise HTTPException(401, "Invalid or expired session.") from exc


def current_user(
    creds: HTTPAuthorizationCredentials = Depends(_required),
    session: Session = Depends(get_session),
) -> Profile:
    """Signed-in user, creating the profile row on first sight."""
    user_id = _user_id(creds)
    profile = session.get(Profile, user_id)
    if profile is None:
        profile = Profile(id=user_id)
        session.add(profile)
        session.commit()
    return profile


def optional_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_optional),
    session: Session = Depends(get_session),
) -> Profile | None:
    """None for guests. The scan endpoints stay open to everyone."""
    if creds is None:
        return None
    return current_user(creds, session)


def require_admin(user: Profile = Depends(current_user)) -> Profile:
    if user.role != "admin":
        raise HTTPException(403, "Administrator access required.")
    return user
