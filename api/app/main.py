"""ScamSathi API. The pipeline is composed here and nowhere else."""

import time
import uuid

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app import classifier, explain, extract, fusion, history, ocr, ratelimit, rules, urlcheck
from app.auth import current_user, optional_user
from app.contracts import (
    MAX_IMAGE_BYTES,
    ExtractedContent,
    FeedbackRequest,
    HistoryItem,
    InputType,
    ScanResult,
    TextScanRequest,
    UrlScanRequest,
)
from app.db import Profile, get_session

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
    return {"model": classifier.version(), "rules": rules.RULE_VERSION}


@app.post("/api/v1/scan/text", dependencies=[Depends(ratelimit.limit_scan)])
def scan_text(
    req: TextScanRequest,
    user: Profile | None = Depends(optional_user),
    session: Session = Depends(get_session),
) -> ScanResult:
    result = analyse(
        ExtractedContent(
            text=req.text,
            source=InputType.TEXT,
            language_guess=req.lang,
            char_count=len(req.text),
        )
    )
    return _maybe_save(result, req.save, user, session)


@app.post("/api/v1/scan/url", dependencies=[Depends(ratelimit.limit_scan)])
def scan_url(
    req: UrlScanRequest,
    user: Profile | None = Depends(optional_user),
    session: Session = Depends(get_session),
) -> ScanResult:
    result = analyse(
        ExtractedContent(
            text=req.url,
            source=InputType.URL,
            language_guess=req.lang,
            char_count=len(req.url),
        ),
        # The submitted URL may have no scheme, so don't re-extract it.
        urls=[req.url],
    )
    return _maybe_save(result, req.save, user, session)


def _maybe_save(
    result: ScanResult, save: bool, user: Profile | None, session: Session
) -> ScanResult:
    """The only route from a scan to the database.

    A guest never reaches `history.save`, so there is no guest write path to
    accidentally leave enabled (R3).
    """
    if not save:
        return result
    if user is None:
        raise HTTPException(401, "Sign in to save a scan.")
    history.save(session, user, result)
    return result


@app.post("/api/v1/scan/image", dependencies=[Depends(ratelimit.limit_scan)])
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


@app.get("/api/v1/history")
def list_history(
    user: Profile = Depends(current_user),
    session: Session = Depends(get_session),
) -> list[HistoryItem]:
    return history.listing(session, user)


@app.get("/api/v1/history/{scan_id}")
def get_history(
    scan_id: uuid.UUID,
    user: Profile = Depends(current_user),
    session: Session = Depends(get_session),
) -> HistoryItem:
    item = history.get(session, user, scan_id)
    if item is None:
        # 404 for someone else's scan too -- never confirm it exists.
        raise HTTPException(404, "Scan not found.")
    return item


@app.delete("/api/v1/history/{scan_id}", status_code=204)
def delete_history(
    scan_id: uuid.UUID,
    user: Profile = Depends(current_user),
    session: Session = Depends(get_session),
) -> None:
    if not history.remove(session, user, scan_id):
        raise HTTPException(404, "Scan not found.")


@app.post("/api/v1/feedback", status_code=201, dependencies=[Depends(ratelimit.limit_feedback)])
def submit_feedback(
    req: FeedbackRequest,
    user: Profile = Depends(current_user),
    session: Session = Depends(get_session),
) -> dict[str, str]:
    # Users paste the scam back into the comment box. Mask it here, at the
    # composition point, with the same masks used for scan excerpts.
    if req.comment:
        req = req.model_copy(
            update={"comment": history.sanitize(req.comment, extract.entities(req.comment))}
        )

    entry = history.add_feedback(session, user, req)
    if entry is None:
        raise HTTPException(404, "Scan not found.")
    return {"id": str(entry.id), "status": entry.status}


@app.delete("/api/v1/history")
def delete_all_history(
    user: Profile = Depends(current_user),
    session: Session = Depends(get_session),
) -> dict[str, int]:
    return {"deleted": history.remove_all(session, user)}


def analyse(extracted: ExtractedContent, urls: list[str] | None = None) -> ScanResult:
    started = time.perf_counter()

    found = extract.entities(extracted.text)
    found_urls = urls if urls is not None else extract.raw_urls(extracted.text)
    url_score, url_flags = urlcheck.analyse(found_urls)
    rule_score, rule_flags = rules.evaluate(extracted.text)
    model = classifier.predict(extracted.text) if extracted.text.strip() else None

    assessment = fusion.assess(
        extracted,
        rule_score,
        url_score,
        rule_flags + url_flags + classifier.indicator(model),
        has_url=bool(found_urls),
        model=model,
    )
    explanation = explain.build(assessment, extracted.language_guess)

    return ScanResult(
        assessment=assessment,
        explanation=explanation,
        extracted=extracted,
        entities=found,
        timing_ms=int((time.perf_counter() - started) * 1000),
        model_version=classifier.version(),
        rule_version=rules.RULE_VERSION,
    )
