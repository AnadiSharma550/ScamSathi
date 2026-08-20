"""Administration (F10): role gate, feedback review, audit, metrics."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError

from app.db import AuditEvent, Profile, SessionLocal, engine
from app.main import app
from tests import keys

client = TestClient(app)

SCAM = "Your KYC is expired. Share your OTP now or your account will be blocked."


def _db_ready() -> bool:
    try:
        return inspect(engine).has_table("audit_events")
    except SQLAlchemyError:
        return False


pytestmark = pytest.mark.skipif(not _db_ready(), reason="migrated database not reachable")


def auth(user_id: uuid.UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {keys.token(user_id)}"}


@pytest.fixture
def user():
    return uuid.uuid4()


@pytest.fixture
def admin():
    """A profile whose role is admin in the database, not in the token."""
    admin_id = uuid.uuid4()
    # First call creates the profile row.
    client.get("/api/v1/history", headers=auth(admin_id))
    with SessionLocal() as session:
        profile = session.get(Profile, admin_id)
        profile.role = "admin"
        session.commit()
    return admin_id


def make_feedback(user_id: uuid.UUID, verdict: str = "too_low") -> str:
    client.post("/api/v1/scan/text", json={"text": SCAM, "save": True}, headers=auth(user_id))
    scan_id = client.get("/api/v1/history", headers=auth(user_id)).json()[0]["id"]
    r = client.post(
        "/api/v1/feedback",
        json={"scan_id": scan_id, "verdict": verdict},
        headers=auth(user_id),
    )
    return r.json()["id"]


# --- the role gate ---


@pytest.mark.parametrize(
    "path", ["/api/v1/admin/feedback", "/api/v1/admin/metrics", "/api/v1/admin/audit"]
)
def test_admin_routes_reject_ordinary_users(path, user):
    assert client.get(path, headers=auth(user)).status_code == 403


@pytest.mark.parametrize(
    "path", ["/api/v1/admin/feedback", "/api/v1/admin/metrics", "/api/v1/admin/audit"]
)
def test_admin_routes_reject_guests(path):
    assert client.get(path).status_code == 403


def test_role_cannot_be_claimed_by_the_token(user):
    """The role comes from the profiles table, never from the JWT."""
    import jwt as pyjwt

    from tests.keys import _private

    forged = pyjwt.encode(
        {
            "sub": str(user),
            "aud": "authenticated",
            "iss": "https://test.supabase.co/auth/v1",
            "exp": 9999999999,
            "role": "admin",
            "app_metadata": {"role": "admin"},
        },
        _private,
        algorithm="ES256",
    )
    r = client.get("/api/v1/admin/metrics", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 403, "a role claim in the token granted admin access"


def test_admin_can_read_the_queue(admin, user):
    make_feedback(user)
    r = client.get("/api/v1/admin/feedback", headers=auth(admin))
    assert r.status_code == 200
    assert r.json()


# --- the privacy boundary ---


def test_queue_never_exposes_scan_content(admin, user):
    """Administrators cannot freely browse private scans (synopsis 2.5)."""
    marker = "Beta main hospital mein hoon accident ho gaya bhejo"
    client.post(
        "/api/v1/scan/text", json={"text": marker, "save": True}, headers=auth(user)
    )
    scan_id = client.get("/api/v1/history", headers=auth(user)).json()[0]["id"]
    client.post(
        "/api/v1/feedback",
        json={"scan_id": scan_id, "verdict": "too_high"},
        headers=auth(user),
    )

    body = client.get("/api/v1/admin/feedback", headers=auth(admin)).text
    assert "hospital mein hoon" not in body, "scan content leaked into the admin queue"
    assert "sanitized_excerpt" not in body


def test_metrics_are_de_identified(admin, user):
    make_feedback(user)
    body = client.get("/api/v1/admin/metrics", headers=auth(admin))
    assert body.status_code == 200
    data = body.json()
    assert str(user) not in body.text, "a user id appeared in aggregate metrics"
    assert data["scans_saved"] >= 1
    assert data["by_band"] and data["model_version"]


# --- review writes an audit trail ---


def test_review_updates_status_and_audits(admin, user):
    feedback_id = make_feedback(user)
    with SessionLocal() as s:
        before = s.scalar(select(func.count()).select_from(AuditEvent))

    r = client.patch(
        f"/api/v1/admin/feedback/{feedback_id}",
        json={"status": "actioned", "note": "added a rule for this pattern"},
        headers=auth(admin),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "actioned"

    with SessionLocal() as s:
        after = s.scalar(select(func.count()).select_from(AuditEvent))
        latest = s.scalars(
            select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(1)
        ).first()
    assert after == before + 1, "a status change was not audited"
    assert latest.action == "feedback.review"
    assert latest.actor == admin
    assert "open -> actioned" in latest.meta


def test_audit_never_contains_scan_content(admin, user):
    feedback_id = make_feedback(user)
    client.patch(
        f"/api/v1/admin/feedback/{feedback_id}",
        json={"status": "dismissed"},
        headers=auth(admin),
    )
    body = client.get("/api/v1/admin/audit", headers=auth(admin)).text
    assert "KYC" not in body and "OTP" not in body


def test_review_of_missing_feedback_is_404(admin):
    r = client.patch(
        f"/api/v1/admin/feedback/{uuid.uuid4()}",
        json={"status": "actioned"},
        headers=auth(admin),
    )
    assert r.status_code == 404


def test_unknown_status_is_rejected(admin, user):
    feedback_id = make_feedback(user)
    r = client.patch(
        f"/api/v1/admin/feedback/{feedback_id}",
        json={"status": "whatever"},
        headers=auth(admin),
    )
    assert r.status_code == 422


def test_queue_filters_by_status(admin, user):
    feedback_id = make_feedback(user)
    client.patch(
        f"/api/v1/admin/feedback/{feedback_id}",
        json={"status": "dismissed"},
        headers=auth(admin),
    )
    dismissed = client.get(
        "/api/v1/admin/feedback", params={"status": "dismissed"}, headers=auth(admin)
    ).json()
    assert any(item["id"] == feedback_id for item in dismissed)
    open_items = client.get(
        "/api/v1/admin/feedback", params={"status": "open"}, headers=auth(admin)
    ).json()
    assert all(item["id"] != feedback_id for item in open_items)
