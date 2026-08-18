"""Screenshot OCR.

ponytail: Pillow only, no OpenCV. Deskew and adaptive threshold solve a
photo-of-a-screen problem; screenshots are already axis-aligned and clean.
Ceiling: skewed camera photos of screens will read poorly. Add cv2 deskew
if CER on the benchmark's photo tier proves it matters.

Security note: the re-encode in `_load` is what makes an upload safe -- it
drops EXIF, trailing payloads and polyglot structure. Nothing is written to
disk at any point, so there are no temp files to leak or clean up.
"""

import io
import unicodedata

import pytesseract
from PIL import Image, ImageOps, UnidentifiedImageError

from app.contracts import ExtractedContent, InputType, Language

# Signature prefixes checked before Pillow ever sees the bytes.
MAGIC = {
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"RIFF": "WEBP",
}
ALLOWED = {"PNG", "JPEG", "WEBP"}

# Decompression-bomb guard. 40MP covers any real phone screenshot.
Image.MAX_IMAGE_PIXELS = 40_000_000

TESS_CONFIG = "--psm 6"
LANGS = "eng+hin"


class BadImage(Exception):
    """Upload rejected at the trust boundary."""


def _load(data: bytes) -> Image.Image:
    if not any(data.startswith(sig) for sig in MAGIC):
        raise BadImage("Unsupported image format.")
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise BadImage("Image could not be read.") from exc

    if img.format not in ALLOWED:
        raise BadImage("Unsupported image format.")

    # Re-encode through a fresh buffer: strips metadata and anything
    # appended after the image data.
    clean = io.BytesIO()
    img.convert("RGB").save(clean, format="PNG")
    clean.seek(0)
    return Image.open(clean)


def _prepare(img: Image.Image) -> Image.Image:
    grey = ImageOps.grayscale(img)
    if grey.height < 1000:
        grey = grey.resize((grey.width * 2, grey.height * 2), Image.LANCZOS)
    return ImageOps.autocontrast(grey)


def _normalise(text: str) -> str:
    # NFC keeps Devanagari composed; collapse runs of whitespace but keep
    # line structure, which carries meaning in messages.
    text = unicodedata.normalize("NFC", text)
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line).strip()


def read(data: bytes) -> ExtractedContent:
    """Raises BadImage on anything that is not a readable allowed image."""
    prepared = _prepare(_load(data))
    raw = pytesseract.image_to_data(
        prepared, lang=LANGS, config=TESS_CONFIG, output_type=pytesseract.Output.DICT
    )

    words = [
        (word, float(conf))
        for word, conf in zip(raw["text"], raw["conf"], strict=False)
        if word.strip() and float(conf) >= 0
    ]
    text = _normalise(" ".join(w for w, _ in words))
    mean_conf = sum(c for _, c in words) / len(words) if words else 0.0

    # Quality blends confidence with how much was actually read -- a single
    # crisp word is not a well-read screenshot.
    volume = min(len(text) / 120, 1.0)
    quality = (mean_conf / 100) * 0.7 + volume * 0.3

    return ExtractedContent(
        text=text,
        source=InputType.IMAGE,
        language_guess=Language.UNKNOWN,
        char_count=len(text),
        ocr_quality=round(min(quality, 1.0), 3),
        ocr_word_conf=round(mean_conf, 1),
    )
