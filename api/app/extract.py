"""Entity extraction. stdlib `re` only."""

import re

from app.contracts import Entity, EntityKind

# Non-numeric detectors, in priority order. Email must precede UPI, else
# "a@b.com" reads as a UPI handle. Amount precedes the digit-run pass so a
# large sum is labelled as money rather than as an unknown identifier.
PATTERNS: list[tuple[EntityKind, re.Pattern[str]]] = [
    (EntityKind.URL, re.compile(r"\b(?:https?://|www\.)[^\s<>\"')\]]+", re.I)),
    (EntityKind.EMAIL, re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    # UPI: handle@psp where psp has no dot (paytm, oksbi, ybl, upi...).
    (EntityKind.UPI_HANDLE, re.compile(r"\b[\w.-]{3,}@[a-z]{3,12}\b")),
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

# One pass for every long number, whatever its shape.
#
# Matching exact digit lengths does not work: any format not on the list
# passes through untouched, and a near-miss is worse than a clean miss --
# "4111 1111 1111 11119" had its first twelve digits masked as an Aadhaar
# number and the remaining "11119" stored in cleartext, so the output looked
# redacted while leaking. Consuming the whole run first makes a partial
# match structurally impossible; the digit count then picks the label.
DIGIT_RUN = re.compile(r"\+?\d[\d\s-]{5,}\d")
MIN_ID_DIGITS = 9


def _digit_kind(raw: str) -> EntityKind | None:
    digits = re.sub(r"\D", "", raw)
    count = len(digits)
    if count < MIN_ID_DIGITS:
        return None
    if count == 16:
        return EntityKind.CARD
    if count == 12 and digits.startswith("91"):
        return EntityKind.PHONE  # +91 mobile, not a 12-digit Aadhaar
    if count == 12:
        return EntityKind.AADHAAR
    if count == 11 and digits.startswith("0"):
        return EntityKind.PHONE  # STD dialling form
    if count == 10 and digits[0] in "6789":
        return EntityKind.PHONE
    # Account numbers, reference numbers, unrecognised card lengths. Mask
    # rather than guess -- over-redaction is the safe direction.
    return EntityKind.ID_NUMBER


LAST_FOUR = {EntityKind.CARD, EntityKind.AADHAAR, EntityKind.ID_NUMBER}


def mask(kind: EntityKind, value: str) -> str:
    """Never return a raw contactable or identifying value -- see R3/I-04."""
    if kind == EntityKind.PHONE:
        digits = re.sub(r"\D", "", value)
        return f"{digits[:2]}{'*' * 6}{digits[-2:]}" if len(digits) >= 10 else "*" * len(value)
    if kind in LAST_FOUR:
        # Last four only. Never keep a card's issuer prefix.
        digits = re.sub(r"\D", "", value)
        return f"{'*' * (len(digits) - 4)}{digits[-4:]}"
    if kind in (EntityKind.EMAIL, EntityKind.UPI_HANDLE):
        local, _, domain = value.partition("@")
        return f"{local[:1]}{'*' * max(len(local) - 1, 1)}@{domain}"
    if kind == EntityKind.URL:
        return _mask_url(value)
    return value


def _mask_url(value: str) -> str:
    """Keep the host, drop everything else.

    Path, query and userinfo all carry tokens and identifiers. The query
    carries them more often than the path does.
    """
    rest = re.sub(r"^https?://", "", value, flags=re.I)
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if "@" in authority:  # user:pw@host -- drop the credentials
        rest = rest[rest.index("@") + 1 :]
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    return f"{host}/..." if len(rest) > len(host) else host


def entities(text: str) -> list[Entity]:
    found: list[Entity] = []
    taken: list[tuple[int, int]] = []

    def claim(kind: EntityKind, match: re.Match[str]) -> None:
        span = (match.start(), match.end())
        # Skip anything already claimed by a higher-priority detector.
        if any(span[0] < t[1] and t[0] < span[1] for t in taken):
            return
        taken.append(span)
        found.append(Entity(kind=kind, value_redacted=mask(kind, match.group()), span=span))

    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text):
            claim(kind, match)

    for match in DIGIT_RUN.finditer(text):
        kind = _digit_kind(match.group())
        if kind is not None:
            claim(kind, match)

    return sorted(found, key=lambda e: e.span[0])


def raw_urls(text: str) -> list[str]:
    """Unmasked URLs for `urlcheck`. Stays inside the pipeline, never serialised."""
    return [m.group() for m in PATTERNS[0][1].finditer(text)]
