import pytest
from fastapi.testclient import TestClient

from app.contracts import MAX_TEXT_CHARS
from app.main import app

client = TestClient(app)

# R2: generated copy must never tell the user something is genuine.
BANNED = ["safe", "legitimate", "verified", "सुरक्षित है"]


def scan(text: str) -> dict:
    r = client.post("/api/v1/scan/text", json={"text": text})
    assert r.status_code == 200, r.text
    return r.json()


def test_healthz():
    assert client.get("/healthz").json() == {"status": "ok"}


# --- golden cases: the regression net for rules + URL + fusion ---

HIGH_RISK = [
    "Dear customer, your KYC is expired. Click http://sbi-verify.xyz and share your OTP to avoid account block.",
    "Congratulations! You have won Rs 25,00,000 in the lucky draw. Pay a refundable processing fee of Rs 4,999 to claim your prize.",
    "Sir please install AnyDesk so I can help you complete the refund process immediately.",
    "Work from home! Earn Rs 5000 per day. No interview needed. Complete the task on telegram and get paid commission.",
    # Hinglish: amount precedes the verb, unlike the English phrasing.
    "Beta main hospital mein hoon, accident ho gaya, turant Rs 50,000 bhejo is number par 9876543210",
]

LOW_RISK = [
    "Hi, are we still meeting for lunch at one o'clock tomorrow near the campus gate?",
    "Your Amazon order has been delivered. Track it at https://amazon.in/orders if you need the receipt.",
]


@pytest.mark.parametrize("text", HIGH_RISK)
def test_known_scams_are_high_risk(text):
    """These are unambiguous scams. Caution is not good enough (I-02)."""
    body = scan(text)
    assert body["assessment"]["band"] == "high", body["assessment"]
    assert body["assessment"]["indicators"], "flagged with no evidence"


def test_text_only_scam_not_diluted_by_absent_url():
    """A missing URL must not drag a strong rule score down a band."""
    with_url = scan(HIGH_RISK[0])["assessment"]["score"]
    text_only = scan(HIGH_RISK[1])["assessment"]["score"]
    assert text_only >= 0.65, f"text-only scam scored {text_only}"
    assert with_url >= 0.65


@pytest.mark.parametrize("text", LOW_RISK)
def test_benign_messages_are_not_high_risk(text):
    assert scan(text)["assessment"]["band"] != "high"


def test_low_risk_is_never_confident():
    """Absence of evidence must not read as an all-clear (I-02)."""
    body = scan(LOW_RISK[0])
    if body["assessment"]["band"] == "low":
        assert body["assessment"]["confidence"] <= 0.5


# --- contract + safety invariants ---


def test_limitation_notice_always_present():
    for text in HIGH_RISK + LOW_RISK + ["hi"]:
        body = scan(text)
        assert body["explanation"]["limitation_notice"]


def test_generated_copy_never_claims_safety():
    for text in HIGH_RISK + LOW_RISK:
        e = scan(text)["explanation"]
        spoken = " ".join([e["headline"], *e["why"], *e["actions"]]).lower()
        assert not any(w in spoken for w in BANNED), spoken


def test_short_input_is_unable_to_assess():
    body = scan("hello")
    assert body["assessment"]["band"] == "unable_to_assess"
    assert body["assessment"]["unable_reason"] == "text_too_short"
    assert body["assessment"]["confidence"] == 0.0


def test_entities_are_masked():
    body = scan("Call me on 9876543210 or mail anadi.sharma@example.com to confirm the transfer")
    values = [e["value_redacted"] for e in body["entities"]]
    assert "9876543210" not in " ".join(values)
    assert "anadi.sharma@example.com" not in " ".join(values)


def test_input_limits_enforced():
    assert client.post("/api/v1/scan/text", json={"text": ""}).status_code == 422
    over = {"text": "x" * (MAX_TEXT_CHARS + 1)}
    assert client.post("/api/v1/scan/text", json=over).status_code == 422


# --- URL endpoint ---


def test_url_scan_flags_brand_impersonation():
    r = client.post("/api/v1/scan/url", json={"url": "http://sbi-verify.xyz/login"})
    body = r.json()
    codes = [i["code"] for i in body["assessment"]["indicators"]]
    assert "url.brand_outside_domain" in codes
    assert body["assessment"]["band"] in ("high", "caution")


def test_url_only_scan_reaches_high_risk():
    """No prose to run rules against must not cap a bad link at Caution."""
    r = client.post("/api/v1/scan/url", json={"url": "paytm.secure-login.top/verify"})
    a = r.json()["assessment"]
    assert a["band"] == "high", a


def test_url_scan_accepts_real_bank_domain():
    r = client.post("/api/v1/scan/url", json={"url": "https://onlinesbi.com"})
    codes = [i["code"] for i in r.json()["assessment"]["indicators"]]
    assert "url.brand_outside_domain" not in codes
