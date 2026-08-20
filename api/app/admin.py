"""Administrator operations: feedback review, metrics, audit trail.

Two constraints shape this module:

1. **Administrators cannot freely browse private scans** (synopsis §2.5).
   Review works from evidence codes and bands, never from the user's
   message. `sanitized_excerpt` is not read here even though it exists and
   is already masked -- masked content is still the user's content.

2. **Every administrative change is recorded.** Status transitions go
   through `review_feedback`, which writes the audit row in the same
   transaction, so an unaudited change is not possible by forgetting.
"""

import uuid
from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import classifier, rules
from app.contracts import (
    AdminFeedbackItem,
    AdminMetrics,
    AuditItem,
    FeedbackReviewRequest,
    FeedbackStatus,
)
from app.db import AuditEvent, Feedback, Profile, Scan


def _item(feedback: Feedback, scan: Scan) -> AdminFeedbackItem:
    return AdminFeedbackItem(
        id=feedback.id,
        scan_id=feedback.scan_id,
        verdict=feedback.verdict,
        comment=feedback.comment,
        status=feedback.status,
        created_at=feedback.created_at,
        input_type=scan.input_type,
        band=scan.band,
        confidence=scan.confidence,
        category=scan.category,
        indicator_codes=[i.code for i in scan.indicators],
        model_version=scan.model_version,
        rule_version=scan.rule_version,
    )


def feedback_queue(
    session: Session,
    status: FeedbackStatus | None = None,
    limit: int = 100,
) -> list[AdminFeedbackItem]:
    """Oldest first -- a review queue is worked front to back."""
    query = (
        select(Feedback, Scan)
        .join(Scan, Scan.id == Feedback.scan_id)
        .order_by(Feedback.created_at.asc())
        .limit(limit)
    )
    if status is not None:
        query = query.where(Feedback.status == status.value)
    return [_item(feedback, scan) for feedback, scan in session.execute(query)]


def review_feedback(
    session: Session,
    admin: Profile,
    feedback_id: uuid.UUID,
    req: FeedbackReviewRequest,
) -> AdminFeedbackItem | None:
    feedback = session.get(Feedback, feedback_id)
    if feedback is None:
        return None

    previous = feedback.status
    feedback.status = req.status.value

    session.add(
        AuditEvent(
            actor=admin.id,
            action="feedback.review",
            target=str(feedback_id),
            # Status transition only. Never the comment or any scan content.
            meta=f"{previous} -> {req.status.value}"
            + (f" | {req.note}" if req.note else ""),
        )
    )
    session.commit()

    scan = session.get(Scan, feedback.scan_id)
    return _item(feedback, scan) if scan else None


def _counts(session: Session, column) -> dict[str, int]:
    rows = session.execute(select(column, func.count()).group_by(column)).all()
    return {str(value): count for value, count in rows}


def metrics(session: Session) -> AdminMetrics:
    verdicts = _counts(session, Feedback.verdict)
    return AdminMetrics(
        scans_saved=session.scalar(select(func.count()).select_from(Scan)) or 0,
        by_band=_counts(session, Scan.band),
        by_category=_counts(session, Scan.category),
        by_input_type=_counts(session, Scan.input_type),
        feedback_by_verdict=verdicts,
        feedback_by_status=_counts(session, Feedback.status),
        open_too_low=session.scalar(
            select(func.count())
            .select_from(Feedback)
            .where(Feedback.verdict == "too_low", Feedback.status == "open")
        )
        or 0,
        model_version=classifier.version(),
        rule_version=rules.RULE_VERSION,
    )


def audit_log(session: Session, limit: int = 100) -> list[AuditItem]:
    rows = session.scalars(
        select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    ).all()
    return [
        AuditItem(
            id=row.id,
            actor=row.actor,
            action=row.action,
            target=row.target,
            meta=row.meta,
            created_at=row.created_at,
        )
        for row in rows
    ]


def indicator_frequency(session: Session, limit: int = 20) -> dict[str, int]:
    """Which evidence fires most often across saved scans.

    Feeds rule-pack tuning: a rule that never fires is dead weight, and one
    that fires on everything is probably too broad.
    """
    codes = session.scalars(
        select(Scan.id).limit(2000)
    ).all()
    if not codes:
        return {}
    scans = session.scalars(select(Scan).where(Scan.id.in_(codes))).all()
    counter = Counter(i.code for s in scans for i in s.indicators)
    return dict(counter.most_common(limit))
