"""Supabase JWT verification via JWKS.

The project signs access tokens with ES256, so verification uses the public
key published at the project's JWKS endpoint. No shared secret exists and
none is needed -- nothing here is confidential, and SUPABASE_URL is the same
value the browser already sends on every request.

The role claim is never trusted from the token. It is read from the profiles
table, so a user cannot mint themselves an admin session.
"""

import os
import uuid

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from sqlalchemy.orm import Session

from app.db import Profile, get_session

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
JWT_AUDIENCE = "authenticated"
JWT_ALGORITHMS = ["ES256", "RS256"]

# Keys are cached and only refetched when a token arrives with an unknown
# kid, so rotation is handled without a restart and without a fetch per
# request.
_jwk_client = (
    PyJWKClient(f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json", cache_keys=True)
    if SUPABASE_URL
    else None
)

# auto_error=False so guests reach the endpoint instead of getting a 403.
_optional = HTTPBearer(auto_error=False)
_required = HTTPBearer(auto_error=True)


def _signing_key(token: str):
    """Public key for this token. Patched in tests; never mocked in prod."""
    if _jwk_client is None:
        raise HTTPException(503, "Authentication is not configured.")
    try:
        return _jwk_client.get_signing_key_from_jwt(token).key
    except jwt.PyJWKClientError as exc:
        # Could not reach or parse the key set. That is our problem, not a
        # bad token, so do not tell the user their session is invalid.
        raise HTTPException(503, "Cannot verify sessions right now.") from exc


def _user_id(creds: HTTPAuthorizationCredentials) -> uuid.UUID:
    try:
        claims = jwt.decode(
            creds.credentials,
            _signing_key(creds.credentials),
            algorithms=JWT_ALGORITHMS,
            audience=JWT_AUDIENCE,
            issuer=f"{SUPABASE_URL}/auth/v1",
            # PyJWT only checks `exp` when it is present, so a token minted
            # without one would never expire and there is no revocation path.
            options={"require": ["exp", "sub", "aud", "iss"]},
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
