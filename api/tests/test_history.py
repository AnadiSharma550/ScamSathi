"""Guest/account split, ownership isolation and deletion.

Needs the database, so these skip on a host with no DATABASE_URL reachable.
Run them with `docker compose run --rm api python -m pytest`.
"""

import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError

from app.db import Feedback, Scan, SessionLocal, engine
from app.main import app
from tests import keys

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


def auth(user_id: uuid.UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {keys.token(user_id)}"}


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


def test_token_signed_by_another_key_is_rejected(user):
    forged = keys.token(user, key=keys.other_key())
    r = client.get("/api/v1/history", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_expired_token_is_rejected(user):
    stale = keys.token(user, expires_in=timedelta(hours=-1))
    r = client.get("/api/v1/history", headers={"Authorization": f"Bearer {stale}"})
    assert r.status_code == 401


def test_token_from_another_project_is_rejected(user):
    """A valid Supabase token from a different project must not work here."""
    wrong_issuer = keys.token(user, issuer="https://someone-else.supabase.co/auth/v1")
    r = client.get("/api/v1/history", headers={"Authorization": f"Bearer {wrong_issuer}"})
    assert r.status_code == 401


def test_token_for_another_audience_is_rejected(user):
    wrong_aud = keys.token(user, audience="anon")
    r = client.get("/api/v1/history", headers={"Authorization": f"Bearer {wrong_aud}"})
    assert r.status_code == 401


# --- deletion ---


def test_delete_single_scan(user):
    client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user))
    scan_id = client.get("/api/v1/history", headers=auth(user)).json()[0]["id"]
    assert client.delete(f"/api/v1/history/{scan_id}", headers=auth(user)).status_code == 204
    assert client.get("/api/v1/history", headers=auth(user)).json() == []


# --- feedback (F9) ---


def saved_scan_id(user) -> str:
    client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user))
    return client.get("/api/v1/history", headers=auth(user)).json()[0]["id"]


def test_feedback_accepted_on_own_scan(user):
    scan_id = saved_scan_id(user)
    r = client.post(
        "/api/v1/feedback",
        json={"scan_id": scan_id, "verdict": "too_low", "comment": "missed a UPI scam"},
        headers=auth(user),
    )
    assert r.status_code == 201
    assert r.json()["status"] == "open"


def test_cannot_leave_feedback_on_another_users_scan(user):
    scan_id = saved_scan_id(user)
    other = uuid.uuid4()
    r = client.post(
        "/api/v1/feedback",
        json={"scan_id": scan_id, "verdict": "too_high"},
        headers=auth(other),
    )
    assert r.status_code == 404


def test_feedback_requires_a_known_verdict(user):
    scan_id = saved_scan_id(user)
    r = client.post(
        "/api/v1/feedback",
        json={"scan_id": scan_id, "verdict": "whatever"},
        headers=auth(user),
    )
    assert r.status_code == 422


def test_feedback_comment_is_length_capped(user):
    scan_id = saved_scan_id(user)
    r = client.post(
        "/api/v1/feedback",
        json={"scan_id": scan_id, "verdict": "unclear", "comment": "x" * 501},
        headers=auth(user),
    )
    assert r.status_code == 422


def test_deleting_a_scan_removes_its_feedback(user):
    scan_id = saved_scan_id(user)
    client.post(
        "/api/v1/feedback",
        json={"scan_id": scan_id, "verdict": "correct"},
        headers=auth(user),
    )
    client.delete(f"/api/v1/history/{scan_id}", headers=auth(user))
    with SessionLocal() as s:
        remaining = s.scalar(
            select(func.count()).select_from(Feedback).where(Feedback.scan_id == scan_id)
        )
    assert remaining == 0, "feedback outlived the scan it points at"


def test_bulk_erase(user):
    for _ in range(3):
        client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user))
    assert client.delete("/api/v1/history", headers=auth(user)).json() == {"deleted": 3}
    assert client.get("/api/v1/history", headers=auth(user)).json() == []
