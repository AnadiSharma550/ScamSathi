"""ScamSathi API. The pipeline is composed here and nowhere else."""

import time

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app import explain, extract, fusion, ocr, rules, urlcheck
from app.contracts import (
    MAX_IMAGE_BYTES,
    ExtractedContent,
    InputType,
    ScanResult,
    TextScanRequest,
    UrlScanRequest,
)

MODEL_VERSION = "none-rules-only"

app = FastAPI(title="ScamSathi AI", version="0.2.0")

# Vite dev server only. Locked to real origins before any deploy.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/meta/versions")
def versions() -> dict[str, str]:
    return {"model": MODEL_VERSION, "rules": rules.RULE_VERSION}


@app.post("/api/v1/scan/text")
def scan_text(req: TextScanRequest) -> ScanResult:
    return analyse(
        ExtractedContent(
            text=req.text,
            source=InputType.TEXT,
            language_guess=req.lang,
            char_count=len(req.text),
        )
    )


@app.post("/api/v1/scan/url")
def scan_url(req: UrlScanRequest) -> ScanResult:
    return analyse(
        ExtractedContent(
            text=req.url,
            source=InputType.URL,
            language_guess=req.lang,
            char_count=len(req.url),
        ),
        # The submitted URL may have no scheme, so don't re-extract it.
        urls=[req.url],
    )


@app.post("/api/v1/scan/image")
async def scan_image(file: UploadFile = File(...)) -> ScanResult:
    # Read with a hard ceiling: never buffer an unbounded upload.
    data = await file.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(413, "Image must be 5 MB or smaller.")
    if not data:
        raise HTTPException(422, "Empty upload.")

    try:
        extracted = ocr.read(data)
    except ocr.BadImage as exc:
        raise HTTPException(415, str(exc)) from exc

    return analyse(extracted)


def analyse(extracted: ExtractedContent, urls: list[str] | None = None) -> ScanResult:
    started = time.perf_counter()

    found = extract.entities(extracted.text)
    found_urls = urls if urls is not None else extract.raw_urls(extracted.text)
    url_score, url_flags = urlcheck.analyse(found_urls)
    rule_score, rule_flags = rules.evaluate(extracted.text)

    assessment = fusion.assess(
        extracted, rule_score, url_score, rule_flags + url_flags, has_url=bool(found_urls)
    )
    explanation = explain.build(assessment, extracted.language_guess)

    return ScanResult(
        assessment=assessment,
        explanation=explanation,
        extracted=extracted,
        entities=found,
        timing_ms=int((time.perf_counter() - started) * 1000),
        model_version=MODEL_VERSION,
        rule_version=rules.RULE_VERSION,
    )
