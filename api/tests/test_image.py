"""Screenshot endpoint: OCR round-trip plus the upload trust boundary.

The security cases run anywhere. The OCR cases need the tesseract binary and
skip without it, so `pytest` still passes on a host that has no Tesseract --
run them in the container.
"""

import io
import shutil

import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from app import ocr
from app.contracts import MAX_IMAGE_BYTES
from app.main import app

client = TestClient(app)

needs_tesseract = pytest.mark.skipif(
    shutil.which("tesseract") is None, reason="tesseract binary not installed"
)


def render(text: str, size=(900, 300)) -> bytes:
    """A screenshot-like PNG: black text, white background, default font."""
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    for n, line in enumerate(text.split("\n")):
        draw.text((20, 20 + n * 34), line, fill="black")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def post(data: bytes, name="shot.png", mime="image/png"):
    return client.post("/api/v1/scan/image", files={"file": (name, data, mime)})


# --- OCR ---


@needs_tesseract
def test_reads_text_from_screenshot():
    body = post(render("Your KYC is expired\nShare your OTP now")).json()
    assert "OTP" in body["extracted"]["text"].upper()
    assert body["extracted"]["ocr_quality"] > 0


@needs_tesseract
def test_screenshot_of_scam_is_flagged():
    body = post(
        render("Your KYC is expired.\nShare your OTP to avoid\naccount block.")
    ).json()
    assert body["assessment"]["band"] in ("high", "caution"), body["assessment"]
    assert body["extracted"]["ocr_quality"] is not None


@needs_tesseract
def test_unreadable_image_is_unable_to_assess():
    """A blank screenshot must not come back as Low Risk."""
    blank = render("", size=(400, 200))
    a = post(blank).json()["assessment"]
    assert a["band"] == "unable_to_assess"


# --- upload trust boundary (no tesseract needed) ---


def test_rejects_non_image_bytes():
    assert post(b"#!/bin/sh\nrm -rf /", name="evil.png").status_code == 415


def test_rejects_disallowed_format():
    buf = io.BytesIO()
    Image.new("RGB", (10, 10), "white").save(buf, format="BMP")
    assert post(buf.getvalue(), name="x.bmp", mime="image/bmp").status_code == 415


def test_rejects_spoofed_mime_type():
    """A declared image/png content-type does not make the bytes an image."""
    assert post(b"not an image at all", mime="image/png").status_code == 415


def test_rejects_oversized_upload():
    assert post(b"\x89PNG\r\n\x1a\n" + b"\x00" * MAX_IMAGE_BYTES).status_code == 413


def test_rejects_empty_upload():
    assert post(b"").status_code == 422


def test_polyglot_payload_is_stripped():
    """Data appended after a valid PNG must not survive the re-encode.

    Asserted against `_load` directly -- this is a property of the
    re-encode, not of OCR, so it holds with or without tesseract.
    """
    payload = b"<?php system($_GET[0]); ?>"
    img = ocr._load(render("hello") + payload)
    out = io.BytesIO()
    img.save(out, format="PNG")
    assert payload not in out.getvalue()


def test_exif_is_stripped():
    buf = io.BytesIO()
    src = Image.new("RGB", (60, 60), "white")
    src.save(buf, format="JPEG", exif=Image.Exif().tobytes())
    assert not ocr._load(buf.getvalue()).info.get("exif")
