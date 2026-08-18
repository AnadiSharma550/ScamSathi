"""Risk fusion + confidence gate.

Provisional weights from the synopsis: R = 0.45*Pm + 0.35*Sr + 0.20*Su.
Two documented departures from that plain weighted sum, both serving I-02
(false reassurance is the harm that matters):

1. Only components that actually ran get a share of the denominator.
2. The model may raise risk but never lower it below the deterministic
   rule and URL evidence, while it remains out-of-distribution.

Both are versioned via WEIGHTS_VERSION and revisited when the multilingual
corpus lands.
"""

from app.contracts import (
    ClassifierResult,
    ExtractedContent,
    Indicator,
    InputType,
    RiskAssessment,
    RiskBand,
    ScamCategory,
    UnableReason,
)

W_MODEL, W_RULE, W_URL = 0.45, 0.35, 0.20
WEIGHTS_VERSION = "weights-1"
THRESHOLD_VERSION = "thresholds-0"

CAUTION_AT, HIGH_AT = 0.35, 0.65

MIN_CHARS = 15
MIN_OCR_QUALITY = 0.6
MIN_MARGIN = 0.15

# Opposed enough to matter: one component confident, the other near-silent.
DISAGREE_HIGH = 0.75
DISAGREE_LOW = 0.15


def _weighted(parts: list[tuple[float, float]]) -> float:
    """Average over components that actually ran.

    A component that had nothing to judge scored 0 because it was absent,
    not because it found the input clean. Letting that 0 into the average
    dilutes real evidence and reads as false reassurance (I-02).
    """
    total = sum(w for w, _ in parts)
    return sum(w * s for w, s in parts) / total if total else 0.0


def _disagrees(p_model: float, rule_score: float) -> bool:
    return (p_model >= DISAGREE_HIGH and rule_score <= DISAGREE_LOW) or (
        p_model <= DISAGREE_LOW and rule_score >= DISAGREE_HIGH
    )

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
    model: ClassifierResult | None = None,
) -> RiskAssessment:
    # Only components that actually ran get a share of the denominator.
    # A component that had nothing to judge scored 0 because it was absent,
    # not because it found the input clean -- letting that 0 into the average
    # dilutes real evidence and reads as false reassurance (I-02).
    has_prose = extracted.source != InputType.URL
    # A text classifier has nothing to say about a bare URL.
    model_votes = model is not None and has_prose
    p_model = model.probs.get(ScamCategory.PHISHING, 0.0) if model_votes else 0.0

    deterministic = _weighted(
        [
            *([(W_RULE, rule_score)] if has_prose else []),
            *([(W_URL, url_score)] if has_url else []),
        ]
    )
    combined = _weighted(
        [
            *([(W_MODEL, p_model)] if model_votes else []),
            *([(W_RULE, rule_score)] if has_prose else []),
            *([(W_URL, url_score)] if has_url else []),
        ]
    )

    # The model may raise risk, never lower it below the rule and URL
    # evidence alone.
    #
    # This is not the plain weighted sum from the synopsis, and the reason is
    # I-02: the harm here is false reassurance. The current baseline is
    # trained on English SMS spam only, so a confident "clean" from it on a
    # Hinglish or Indian-context scam is out-of-distribution noise, not
    # evidence of safety -- and at W_MODEL=0.45 it was strong enough to
    # cancel a fired CRITICAL rule. Raising risk still works normally, so the
    # model contributes exactly the recall it is there for.
    #
    # Revert to `combined` alone once the model is trained on the
    # multilingual corpus and its calibration is validated per-language.
    score = max(deterministic, combined)

    band = (
        RiskBand.HIGH if score >= HIGH_AT
        else RiskBand.CAUTION if score >= CAUTION_AT
        else RiskBand.LOW
    )

    # Confidence is computed separately from risk -- it describes how much
    # the input and the components support any verdict, not which verdict.
    confidence = 0.55 + 0.30 * model.margin if model_votes else 0.55
    unable: UnableReason | None = None

    # A URL is the whole input, never "too short" -- the gate is for prose.
    if extracted.source != InputType.URL and extracted.char_count < MIN_CHARS:
        unable = UnableReason.TEXT_TOO_SHORT
    elif extracted.ocr_quality is not None and extracted.ocr_quality < MIN_OCR_QUALITY:
        unable = UnableReason.OCR_TOO_POOR
    elif model_votes and model.margin < MIN_MARGIN and rule_score < CAUTION_AT and url_score == 0:
        # The model is undecided and nothing else has an opinion. Only then
        # is there genuinely nothing to go on -- a low margin alongside solid
        # rule evidence is not a reason to discard the rule evidence.
        unable = UnableReason.MODEL_MARGIN_LOW

    if unable:
        band, confidence = RiskBand.UNABLE_TO_ASSESS, 0.0
    else:
        # Components pointing opposite ways is a reason to be less sure, not
        # a reason to withhold the result.
        if model_votes and _disagrees(p_model, rule_score):
            confidence *= 0.7
        if band == RiskBand.LOW:
            # Absence of evidence is weaker than presence of it. Never let a
            # clean sweep read as a confident all-clear (I-02).
            confidence = min(confidence, 0.5)
        confidence = round(confidence, 3)

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
