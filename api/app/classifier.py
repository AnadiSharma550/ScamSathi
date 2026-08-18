"""Scam-probability classifier.

Produces `Pm` for the fusion formula: a single calibrated P(scam), not a
7-class distribution. The synopsis formula asks for scam probability, and
the category still comes from which rule families fired. Multi-class arrives
with the multilingual corpus.

The model artifact is not in source control, so `available()` is false on a
fresh clone and in CI. Callers must handle that -- risk fusion drops to
rules and URL evidence rather than failing.
"""

import os
from pathlib import Path

import joblib

from app.contracts import ClassifierResult, Indicator, ScamCategory, Severity

# Below this the model has nothing worth telling the user about.
INDICATOR_AT = 0.5
STRONG_AT = 0.9

MODEL_PATH = Path(os.getenv("MODEL_PATH", "/app/models/baseline.joblib"))

_model = None
_version = "none"
_loaded = False


def _load() -> None:
    global _model, _version, _loaded
    if _loaded:
        return
    _loaded = True
    if not MODEL_PATH.exists():
        return
    try:
        bundle = joblib.load(MODEL_PATH)
        _model, _version = bundle["model"], bundle["version"]
    except Exception:  # noqa: BLE001 - a broken artifact must not break scanning
        _model, _version = None, "none"


def available() -> bool:
    _load()
    return _model is not None


def version() -> str:
    _load()
    return _version if _model is not None else "none-rules-only"


def predict(text: str) -> ClassifierResult | None:
    """Calibrated P(scam), or None when no model is loaded."""
    _load()
    if _model is None:
        return None

    p_scam = float(_model.predict_proba([text])[0][1])
    return ClassifierResult(
        probs={
            ScamCategory.LEGITIMATE: round(1 - p_scam, 6),
            # Category attribution stays with the rule engine; this is the
            # binary scam mass, parked under PHISHING as the generic class.
            ScamCategory.PHISHING: round(p_scam, 6),
        },
        top=ScamCategory.PHISHING if p_scam >= 0.5 else ScamCategory.LEGITIMATE,
        margin=abs(2 * p_scam - 1),
        model_version=_version,
        calibrated=True,
    )


def indicator(result: ClassifierResult | None) -> list[Indicator]:
    """Evidence item for a model-driven detection.

    Without this, a message the model flags but no rule matches produces an
    elevated band with an empty evidence list -- a result that says warning
    signs were found and then lists none. Every non-uncertain result must
    carry traceable evidence (§4.3), and "the wording matches known scam
    messages" is traceable to this component.
    """
    if result is None:
        return []
    p_scam = result.probs.get(ScamCategory.PHISHING, 0.0)
    if p_scam < INDICATOR_AT:
        return []
    return [
        Indicator(
            code="model.scam_language",
            severity=Severity.MAJOR if p_scam >= STRONG_AT else Severity.MINOR,
            source="model",
            weight=round(p_scam, 4),
        )
    ]
