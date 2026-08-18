"""Entity extraction. stdlib `re` only."""

import re

from app.contracts import Entity, EntityKind

# Order matters: email before UPI, else "a@b.com" reads as a UPI handle.
PATTERNS: list[tuple[EntityKind, re.Pattern[str]]] = [
    (EntityKind.URL, re.compile(r"\b(?:https?://|www\.)[^\s<>\"')\]]+", re.I)),
    (EntityKind.EMAIL, re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    # UPI: handle@psp where psp has no dot (paytm, oksbi, ybl, upi...).
    (EntityKind.UPI_HANDLE, re.compile(r"\b[\w.-]{3,}@[a-z]{3,12}\b")),
    (EntityKind.PHONE, re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b")),
    (EntityKind.AMOUNT, re.compile(r"(?:₹|\bRs\.?|\bINR)\s?[\d,]+(?:\.\d{2})?", re.I)),
    (
        EntityKind.URGENCY,
        re.compile(
            r"\b(urgent(?:ly)?|immediately|within \d+ (?:hours?|minutes?|days?)|"
            r"right now|last chance|expir(?:es|ed|ing)|final notice|act now|"
            r"turant|abhi|jaldi)\b",
            re.I,
        ),
    ),
]


def mask(kind: EntityKind, value: str) -> str:
    """Never return a raw contactable identifier -- see R3/I-04."""
    if kind == EntityKind.PHONE:
        digits = re.sub(r"\D", "", value)
        return f"{digits[:2]}{'*' * 6}{digits[-2:]}" if len(digits) >= 10 else "*" * len(value)
    if kind in (EntityKind.EMAIL, EntityKind.UPI_HANDLE):
        local, _, domain = value.partition("@")
        return f"{local[:1]}{'*' * max(len(local) - 1, 1)}@{domain}"
    if kind == EntityKind.URL:
        # Keep host, drop the path -- paths carry tokens and IDs.
        m = re.match(r"(https?://)?([^/]+)", value, re.I)
        host = m.group(2) if m else value
        return f"{host}/..." if "/" in value.split("://")[-1] else host
    return value


def entities(text: str) -> list[Entity]:
    found: list[Entity] = []
    taken: list[tuple[int, int]] = []
    for kind, pattern in PATTERNS:
        for m in pattern.finditer(text):
            span = (m.start(), m.end())
            # Skip anything already claimed by an earlier (higher-priority) kind.
            if any(span[0] < t[1] and t[0] < span[1] for t in taken):
                continue
            taken.append(span)
            found.append(Entity(kind=kind, value_redacted=mask(kind, m.group()), span=span))
    return sorted(found, key=lambda e: e.span[0])


def raw_urls(text: str) -> list[str]:
    """Unmasked URLs for `urlcheck`. Stays inside the pipeline, never serialised."""
    return [m.group() for m in PATTERNS[0][1].finditer(text)]
