"""Saved-scan storage for signed-in users.

Nothing in this module runs for a guest. That is the whole of rule R3 --
there is no write path to disable, because the caller never gets here
without a Profile.
"""

import uuid

from sqlalchemy import delete as sql_delete
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.contracts import Entity, HistoryItem, ScanResult
from app.db import Profile, Scan, ScanIndicator

EXCERPT_CHARS = 300


def sanitize(text: str, entities: list[Entity]) -> str:
    """Replace every detected identifier with its masked form, then truncate.

    Reuses the masks `extract` already produced, so there is exactly one
    definition of what a masked phone number looks like.
    """
    out = text
    for entity in sorted(entities, key=lambda e: -e.span[0]):
        start, end = entity.span
        out = out[:start] + entity.value_redacted + out[end:]
    out = " ".join(out.split())
    return out[:EXCERPT_CHARS]


def save(session: Session, user: Profile, result: ScanResult) -> Scan:
    scan = Scan(
        user_id=user.id,
        input_type=result.extracted.source.value,
        band=result.assessment.band.value,
        score=result.assessment.score,
        confidence=result.assessment.confidence,
        category=result.assessment.category.value,
        model_version=result.model_version,
        rule_version=result.rule_version,
        sanitized_excerpt=sanitize(result.extracted.text, result.entities),
        indicators=[
            ScanIndicator(code=i.code, severity=i.severity.value, source=i.source)
            for i in result.assessment.indicators
        ],
    )
    session.add(scan)
    session.commit()
    return scan


def _item(scan: Scan) -> HistoryItem:
    return HistoryItem(
        id=scan.id,
        input_type=scan.input_type,
        band=scan.band,
        confidence=scan.confidence,
        category=scan.category,
        sanitized_excerpt=scan.sanitized_excerpt,
        indicator_codes=[i.code for i in scan.indicators],
        model_version=scan.model_version,
        rule_version=scan.rule_version,
        created_at=scan.created_at,
    )


def listing(session: Session, user: Profile, limit: int = 50) -> list[HistoryItem]:
    rows = session.scalars(
        select(Scan)
        .where(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
    ).all()
    return [_item(row) for row in rows]


def get(session: Session, user: Profile, scan_id: uuid.UUID) -> HistoryItem | None:
    # Ownership is part of the lookup, never a check after the fact.
    scan = session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    return _item(scan) if scan else None


def remove(session: Session, user: Profile, scan_id: uuid.UUID) -> bool:
    result = session.execute(
        sql_delete(Scan).where(Scan.id == scan_id, Scan.user_id == user.id)
    )
    session.commit()
    return result.rowcount > 0


def remove_all(session: Session, user: Profile) -> int:
    result = session.execute(sql_delete(Scan).where(Scan.user_id == user.id))
    session.commit()
    return result.rowcount
