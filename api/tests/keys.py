"""Test signing keys.

Tests mint ES256 tokens with a locally generated keypair and patch the
public-key lookup. That keeps production on a single verification path --
there is no test-only HS256 branch that could be reached in a real
deployment.
"""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from app import auth

_private = ec.generate_private_key(ec.SECP256R1())
_public = _private.public_key()


def install(monkeypatch) -> None:
    """Point auth at the test keypair for the duration of a test."""
    monkeypatch.setattr(auth, "_signing_key", lambda token: _public)
    monkeypatch.setattr(auth, "SUPABASE_URL", "https://test.supabase.co")


def token(
    user_id: uuid.UUID,
    *,
    expires_in: timedelta = timedelta(hours=1),
    key=None,
    issuer: str = "https://test.supabase.co/auth/v1",
    audience: str = "authenticated",
) -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "aud": audience,
            "iss": issuer,
            "exp": datetime.now(UTC) + expires_in,
        },
        key or _private,
        algorithm="ES256",
    )


def other_key():
    """A different keypair, for forged-token tests."""
    return ec.generate_private_key(ec.SECP256R1())
