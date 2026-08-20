from fastapi.testclient import TestClient

from app import ratelimit
from app.main import app

client = TestClient(app)

MSG = "Is this message a scam or not, it looks suspicious to me"


def scan():
    return client.post("/api/v1/scan/text", json={"text": MSG})


def test_scans_are_allowed_up_to_the_minute_limit():
    per_minute = ratelimit.SCAN_LIMITS[0][1]
    for n in range(per_minute):
        assert scan().status_code == 200, f"blocked at request {n + 1}"


def test_scan_over_the_limit_is_rejected():
    per_minute = ratelimit.SCAN_LIMITS[0][1]
    for _ in range(per_minute):
        scan()
    r = scan()
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) > 0


def test_rejected_requests_do_not_count_against_the_caller():
    """Hammering while blocked must not extend the block."""
    per_minute = ratelimit.SCAN_LIMITS[0][1]
    for _ in range(per_minute):
        scan()
    key = "testclient"
    window, _ = ratelimit.SCAN_LIMITS[0]
    import time

    slot = (key, window, int(time.time() // window))
    before = ratelimit.scan_limiter._counts.get(slot, 0)
    for _ in range(5):
        scan()
    assert ratelimit.scan_limiter._counts.get(slot, 0) == before


def test_image_endpoint_is_limited_too():
    """OCR is the expensive path -- it must not be the unguarded one."""
    per_minute = ratelimit.SCAN_LIMITS[0][1]
    for _ in range(per_minute):
        scan()
    r = client.post(
        "/api/v1/scan/image", files={"file": ("x.png", b"\x89PNG\r\n\x1a\n", "image/png")}
    )
    assert r.status_code == 429


def test_limiter_prunes_expired_buckets():
    limiter = ratelimit.FixedWindow([(60, 5)])
    limiter._counts = {(f"ip{n}", 60, 0): 1 for n in range(10)}
    limiter._prune(now=10_000_000)
    assert limiter._counts == {}, "stale buckets were kept"


def test_health_and_reads_are_not_rate_limited():
    per_minute = ratelimit.SCAN_LIMITS[0][1]
    for _ in range(per_minute + 2):
        scan()
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/v1/meta/versions").status_code == 200
