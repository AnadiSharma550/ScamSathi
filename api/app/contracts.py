"""Shared contracts. Every module speaks these types and nothing else.

Frozen Week 2 -- changing anything here is a three-person decision, because
all eight module boundaries are defined in terms of these models.
"""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field


class InputType(StrEnum):
    TEXT = "text"
    IMAGE = "image"
    URL = "url"


class RiskBand(StrEnum):
    LOW = "low"
    CAUTION = "caution"
    HIGH = "high"
    UNABLE_TO_ASSESS = "unable_to_assess"


class ScamCategory(StrEnum):
    LEGITIMATE = "legitimate"
    # Evidence exists but nothing attributes it to a category -- e.g. only
    # the binary classifier fired. Never claim a category we cannot support,
    # and never fall back to LEGITIMATE on an elevated band (R2).
    UNCATEGORISED = "uncategorised"
    PHISHING = "phishing"
    FAKE_JOB = "fake_job"
    PAYMENT_UPI = "payment_upi"
    IMPERSONATION = "impersonation"
    PRIZE_REWARD = "prize_reward"
    LOAN_INVESTMENT = "loan_investment"


class Severity(StrEnum):
    INFO = "info"
    MINOR = "minor"
    MAJOR = "major"
    CRITICAL = "critical"


class UnableReason(StrEnum):
    """Machine-readable so the UI can tell the user what to fix."""

    OCR_TOO_POOR = "ocr_too_poor"
    TEXT_TOO_SHORT = "text_too_short"
    MODEL_MARGIN_LOW = "model_margin_low"
    COMPONENT_DISAGREEMENT = "component_disagreement"


class EntityKind(StrEnum):
    URL = "url"
    PHONE = "phone"
    EMAIL = "email"
    UPI_HANDLE = "upi_handle"
    CARD = "card"
    AADHAAR = "aadhaar"
    # A long number we cannot attribute -- account or reference number, or a
    # card of an unrecognised length. Masked rather than guessed at.
    ID_NUMBER = "id_number"
    AMOUNT = "amount"
    URGENCY = "urgency"


class Language(StrEnum):
    EN = "en"
    HI = "hi"
    HINGLISH = "hinglish"
    UNKNOWN = "unknown"


class ExtractedContent(BaseModel):
    text: str
    source: InputType
    language_guess: Language = Language.UNKNOWN
    char_count: int = 0
    # None for text/url input -- only screenshots have OCR quality.
    ocr_quality: float | None = Field(default=None, ge=0.0, le=1.0)
    ocr_word_conf: float | None = Field(default=None, ge=0.0, le=100.0)


class Entity(BaseModel):
    kind: EntityKind
    value_redacted: str  # already masked; raw value never leaves `extract`
    span: tuple[int, int]


class Indicator(BaseModel):
    code: str  # e.g. "rule.otp_request", "url.ip_literal_host"
    severity: Severity
    source: str  # "rule" | "url" | "model"
    weight: float = Field(ge=0.0, le=1.0)
    rule_version: str | None = None
    evidence_span: tuple[int, int] | None = None


class ClassifierResult(BaseModel):
    probs: dict[ScamCategory, float]
    top: ScamCategory
    margin: float = Field(ge=0.0, le=1.0)  # gap between top-2
    model_version: str
    calibrated: bool = False


class RiskAssessment(BaseModel):
    band: RiskBand
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    category: ScamCategory
    indicators: list[Indicator] = []
    weights_version: str
    threshold_version: str
    unable_reason: UnableReason | None = None


class Explanation(BaseModel):
    headline: str
    why: list[str] = Field(default=[], max_length=5)
    actions: list[str] = Field(default=[], max_length=4)
    limitation_notice: str  # required -- R2, never optional
    language: Language
    generated_by: str = "template"  # "template" | "llm"


class ScanResult(BaseModel):
    assessment: RiskAssessment
    explanation: Explanation
    extracted: ExtractedContent
    entities: list[Entity] = []
    timing_ms: int
    model_version: str
    rule_version: str


# --- requests ---

MAX_TEXT_CHARS = 10_000
MAX_IMAGE_BYTES = 5 * 1024 * 1024


class TextScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT_CHARS)
    lang: Language = Language.EN
    # Requires a signed-in user. Guests setting this get 401, never a
    # silent write -- see R3.
    save: bool = False


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    lang: Language = Language.EN
    save: bool = False


class FeedbackVerdict(StrEnum):
    TOO_HIGH = "too_high"       # flagged something the user believes is fine
    TOO_LOW = "too_low"         # missed a scam -- the I-02 signal
    UNCLEAR = "unclear"         # right answer, unusable explanation
    CORRECT = "correct"


class FeedbackRequest(BaseModel):
    scan_id: UUID
    verdict: FeedbackVerdict
    # Short and optional. We want the signal, not a free-text channel for
    # users to paste the scam back in.
    comment: str | None = Field(default=None, max_length=500)


class HistoryItem(BaseModel):
    """A saved scan as the owner sees it. Never carries raw content."""

    id: UUID
    input_type: InputType
    band: RiskBand
    confidence: float
    category: ScamCategory
    sanitized_excerpt: str | None
    indicator_codes: list[str]
    model_version: str
    rule_version: str
    created_at: datetime
