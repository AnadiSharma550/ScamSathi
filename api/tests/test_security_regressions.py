"""Regressions from the security review.

Each test pins a bug that shipped. Do not delete one without understanding
which failure it prevents.
"""

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import ocr, urlcheck
from app.main import app

client = TestClient(app)

APP_DIR = Path(__file__).resolve().parent.parent / "app"

# Anything that could open a socket. R4 forbids all of them in urlcheck.
NETWORK_MODULES = {
    "httpx", "requests", "aiohttp", "urllib.request", "urllib3",
    "socket", "http.client", "ftplib", "telnetlib", "asyncio.streams",
}


# --- R4: held by a test now, not a docstring ---


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


@pytest.mark.parametrize("module", ["urlcheck.py", "extract.py", "rules.py", "fusion.py"])
def test_no_network_client_in_analysis_modules(module):
    """R4: the server must never be able to fetch a submitted URL."""
    imported = _imports(APP_DIR / module)
    offenders = {
        name for name in imported if any(name == n or name.startswith(f"{n}.") for n in NETWORK_MODULES)
    }
    assert not offenders, f"{module} imports {offenders} -- R4 forbids network access here"


# --- a zero-scoring URL must not lose its flags ---


def test_bad_scheme_url_is_not_silently_cleared():
    """`file:///etc/passwd` raised a CRITICAL flag that analyse() discarded."""
    score, flags = urlcheck.analyse(["file:///etc/passwd"])
    codes = [f.code for f in flags]
    assert "url.bad_scheme" in codes
    assert score > 0, "a CRITICAL flag must not score zero"


def test_non_http_scheme_scan_is_not_low_risk():
    body = client.post("/api/v1/scan/url", json={"url": "file:///etc/passwd"}).json()
    assert body["assessment"]["band"] != "low", body["assessment"]
    assert body["assessment"]["indicators"], "flagged with no evidence"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "javascript://alert(1)", "ftp://x"])
def test_dangerous_schemes_carry_evidence(url):
    _, flags = urlcheck.analyse([url])
    assert "url.bad_scheme" in [f.code for f in flags]


# --- an elevated band must never be labelled legitimate ---


def test_elevated_band_is_never_categorised_legitimate():
    """R2: 'legitimate' contradicted the band in the same response."""
    texts = [
        "Had your mobile 11 months or more? U R entitled to Update to the latest "
        "colour mobiles with camera for Free! Call The Mobile Update Co FREE on 08002986030",
        "Your KYC is expired. Share your OTP now to avoid account block.",
        "Congratulations! You won a lucky draw prize, pay the processing fee to claim.",
    ]
    for text in texts:
        a = client.post("/api/v1/scan/text", json={"text": text}).json()["assessment"]
        if a["band"] in ("caution", "high"):
            assert a["category"] != "legitimate", f"{a['band']} labelled legitimate: {text[:40]}"


# --- decompression bomb guard must survive preprocessing ---


def test_upscale_cannot_exceed_the_pixel_guard():
    """_prepare quadrupled the pixel count after the decode-time guard."""
    from PIL import Image

    wide = Image.new("L", (Image.MAX_IMAGE_PIXELS // 999, 999), "white")
    prepared = ocr._prepare(wide)
    assert prepared.width * prepared.height <= Image.MAX_IMAGE_PIXELS


def test_small_images_are_still_upscaled():
    """The guard must not disable upscaling for ordinary screenshots."""
    from PIL import Image

    small = Image.new("L", (400, 200), "white")
    prepared = ocr._prepare(small)
    assert (prepared.width, prepared.height) == (800, 400)
