"""Guest/account split, ownership isolation and deletion.

Needs the database, so these skip on a host with no DATABASE_URL reachable.
Run them with `docker compose run --rm api python -m pytest`.
"""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError

from app.auth import JWT_AUDIENCE, JWT_SECRET
from app.db import Scan, SessionLocal, engine
from app.main import app

client = TestClient(app)

SCAM = "Your KYC is expired. Share your OTP now or your account will be blocked."


def _migrated_db_available() -> bool:
    try:
        return inspect(engine).has_table("scans")
    except SQLAlchemyError:
        return False


pytestmark = pytest.mark.skipif(
    not _migrated_db_available(), reason="migrated database not reachable"
)


def token(user_id: uuid.UUID) -> str:
    return jwt.encode(
        {
            "sub": str(user_id),
            "aud": JWT_AUDIENCE,
            "exp": datetime.now(UTC) + timedelta(hours=1),
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def auth(user_id: uuid.UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(user_id)}"}


def scan_count() -> int:
    with SessionLocal() as s:
        return s.scalar(select(func.count()).select_from(Scan))


@pytest.fixture
def user():
    return uuid.uuid4()


# --- R3: guests are never persisted ---


def test_guest_scan_writes_nothing():
    before = scan_count()
    r = client.post("/api/v1/scan/text", json={"text": SCAM})
    assert r.status_code == 200
    assert scan_count() == before, "a guest scan reached the database"


def test_guest_asking_to_save_is_refused_not_silently_dropped():
    before = scan_count()
    r = client.post("/api/v1/scan/text", json={"text": SCAM, "save": True})
    assert r.status_code == 401
    assert scan_count() == before


def test_signed_in_scan_without_save_flag_writes_nothing(user):
    before = scan_count()
    client.post("/api/v1/scan/text", json={"text": SCAM}, headers=auth(user))
    assert scan_count() == before, "saving must be opt-in per scan"


# --- saving and reading back ---


def test_save_then_appears_in_history(user):
    client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user))
    items = client.get("/api/v1/history", headers=auth(user)).json()
    assert len(items) == 1
    assert items[0]["band"] in ("high", "caution")
    assert items[0]["indicator_codes"]


def test_stored_excerpt_is_masked(user):
    text = "Emergency! Send Rs 50,000 to 9876543210 or mail anadi.sharma@example.com now"
    client.post("/api/v1/scan/text", json={"text": text, "save": True}, headers=auth(user))
    excerpt = client.get("/api/v1/history", headers=auth(user)).json()[0]["sanitized_excerpt"]
    assert "9876543210" not in excerpt
    assert "anadi.sharma@example.com" not in excerpt


# --- ownership isolation ---


def test_history_is_private_to_its_owner(user):
    other = uuid.uuid4()
    client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user))
    assert client.get("/api/v1/history", headers=auth(other)).json() == []


def test_cannot_read_another_users_scan_by_id(user):
    other = uuid.uuid4()
    client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user))
    scan_id = client.get("/api/v1/history", headers=auth(user)).json()[0]["id"]
    # 404, not 403 -- never confirm that someone else's scan exists.
    assert client.get(f"/api/v1/history/{scan_id}", headers=auth(other)).status_code == 404


def test_cannot_delete_another_users_scan(user):
    other = uuid.uuid4()
    client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user))
    scan_id = client.get("/api/v1/history", headers=auth(user)).json()[0]["id"]
    assert client.delete(f"/api/v1/history/{scan_id}", headers=auth(other)).status_code == 404
    assert len(client.get("/api/v1/history", headers=auth(user)).json()) == 1


# --- auth boundary ---


def test_history_requires_authentication():
    assert client.get("/api/v1/history").status_code == 403


def test_forged_token_is_rejected(user):
    bad = jwt.encode({"sub": str(user), "aud": JWT_AUDIENCE}, "wrong-secret", algorithm="HS256")
    r = client.get("/api/v1/history", headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401


def test_expired_token_is_rejected(user):
    stale = jwt.encode(
        {
            "sub": str(user),
            "aud": JWT_AUDIENCE,
            "exp": datetime.now(UTC) - timedelta(hours=1),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    r = client.get("/api/v1/history", headers={"Authorization": f"Bearer {stale}"})
    assert r.status_code == 401


# --- deletion ---


def test_delete_single_scan(user):
    client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user))
    scan_id = client.get("/api/v1/history", headers=auth(user)).json()[0]["id"]
    assert client.delete(f"/api/v1/history/{scan_id}", headers=auth(user)).status_code == 204
    assert client.get("/api/v1/history", headers=auth(user)).json() == []


def test_bulk_erase(user):
    for _ in range(3):
        client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user))
    assert client.delete("/api/v1/history", headers=auth(user)).json() == {"deleted": 3}
    assert client.get("/api/v1/history", headers=auth(user)).json() == []
