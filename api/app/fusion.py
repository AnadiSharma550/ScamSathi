"""Risk fusion + confidence gate.

Provisional weights from the synopsis: R = 0.45*Pm + 0.35*Sr + 0.20*Su.
No classifier exists yet, so its share is renormalised away and the result
says so. Adding the model later is a one-line change in `assess`.
"""

from app.contracts import (
    ExtractedContent,
    Indicator,
    InputType,
    RiskAssessment,
    RiskBand,
    ScamCategory,
    UnableReason,
)

W_MODEL, W_RULE, W_URL = 0.45, 0.35, 0.20
WEIGHTS_VERSION = "weights-0-rules-only"
THRESHOLD_VERSION = "thresholds-0"

CAUTION_AT, HIGH_AT = 0.35, 0.65

MIN_CHARS = 15
MIN_OCR_QUALITY = 0.6

# Which rule families imply which category. First match wins.
CATEGORY_BY_PREFIX = [
    ("rule.otp", ScamCategory.PHISHING),
    ("rule.credential", ScamCategory.PHISHING),
    ("rule.kyc", ScamCategory.PHISHING),
    ("rule.advance_fee", ScamCategory.PAYMENT_UPI),
    ("rule.pay_to_receive", ScamCategory.PAYMENT_UPI),
    ("rule.upi", ScamCategory.PAYMENT_UPI),
    ("rule.remote", ScamCategory.IMPERSONATION),
    ("rule.authority", ScamCategory.IMPERSONATION),
    ("rule.family", ScamCategory.IMPERSONATION),
    ("rule.prize", ScamCategory.PRIZE_REWARD),
    ("rule.job", ScamCategory.FAKE_JOB),
    ("rule.task", ScamCategory.FAKE_JOB),
    ("rule.instant_loan", ScamCategory.LOAN_INVESTMENT),
    ("url.", ScamCategory.PHISHING),
]


def _category(indicators: list[Indicator]) -> ScamCategory:
    strongest = sorted(indicators, key=lambda i: -i.weight)
    for ind in strongest:
        for prefix, category in CATEGORY_BY_PREFIX:
            if ind.code.startswith(prefix):
                return category
    return ScamCategory.LEGITIMATE


def assess(
    extracted: ExtractedContent,
    rule_score: float,
    url_score: float,
    indicators: list[Indicator],
    has_url: bool = False,
) -> RiskAssessment:
    # Only components that actually ran get a share of the denominator.
    # A component that had nothing to judge scored 0 because it was absent,
    # not because it found the input clean -- letting that 0 into the average
    # dilutes real evidence and reads as false reassurance (I-02).
    # ponytail: model share renormalised out until a classifier ships.
    # Ceiling: rules-only recall. Append (W_MODEL, Pm) to `parts`.
    has_prose = extracted.source != InputType.URL
    parts = [
        *([(W_RULE, rule_score)] if has_prose else []),
        *([(W_URL, url_score)] if has_url else []),
    ]
    total_weight = sum(w for w, _ in parts)
    score = sum(w * s for w, s in parts) / total_weight if total_weight else 0.0

    band = (
        RiskBand.HIGH if score >= HIGH_AT
        else RiskBand.CAUTION if score >= CAUTION_AT
        else RiskBand.LOW
    )

    # Confidence is computed separately from risk -- it describes the input,
    # not the verdict.
    confidence = 0.6  # capped: no classifier is corroborating the rules yet
    unable: UnableReason | None = None

    # A URL is the whole input, never "too short" -- the gate is for prose.
    if extracted.source != InputType.URL and extracted.char_count < MIN_CHARS:
        unable = UnableReason.TEXT_TOO_SHORT
    elif extracted.ocr_quality is not None and extracted.ocr_quality < MIN_OCR_QUALITY:
        unable = UnableReason.OCR_TOO_POOR

    if unable:
        band, confidence = RiskBand.UNABLE_TO_ASSESS, 0.0
    elif band == RiskBand.LOW:
        # Absence of evidence is weaker than presence of it. Never let a
        # clean rule sweep read as a confident all-clear (I-02).
        confidence = 0.4

    return RiskAssessment(
        band=band,
        score=round(score, 4),
        confidence=confidence,
        category=_category(indicators) if band != RiskBand.LOW else ScamCategory.LEGITIMATE,
        indicators=indicators,
        weights_version=WEIGHTS_VERSION,
        threshold_version=THRESHOLD_VERSION,
        unable_reason=unable,
    )
