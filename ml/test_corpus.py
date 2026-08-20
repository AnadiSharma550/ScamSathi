"""Checks for the corpus gate. Run: python -m pytest ml/"""

import csv
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import corpus  # noqa: E402

SEED = Path(__file__).parent / "seed" / "ds04-hinglish-seed.csv"

GOOD = {
    "id": "t-1",
    "text": "Aapka KYC expire ho gaya hai, turant update karein",
    "label": "phishing",
    "language": "hinglish",
    "source_id": "DS-04",
    "synthetic": "true",
    "consent": "Team-authored",
    "comment": "",
}


def write(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "c.csv"
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=corpus.COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_seed_corpus_passes_validation():
    assert corpus.validate([SEED]) == 0


def test_accepts_a_well_formed_record(tmp_path):
    assert corpus.validate([write(tmp_path, [GOOD])]) == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("consent", ""),            # the licence gate
        ("label", "spam"),          # DS-01's vocabulary, not ours
        ("language", "en-IN"),
        ("source_id", "somewhere"),  # must reference the register
        ("synthetic", "yes"),
        ("id", ""),
        ("text", "short"),
    ],
)
def test_rejects_bad_field(tmp_path, field, value):
    bad = {**GOOD, field: value}
    assert corpus.validate([write(tmp_path, [bad])]) == 1, f"{field}={value!r} was accepted"


def test_rejects_unredacted_phone_number(tmp_path):
    leaky = {**GOOD, "text": "Turant paise bhejo is number par 9876543210 abhi"}
    assert corpus.validate([write(tmp_path, [leaky])]) == 1


def test_rejects_unredacted_email(tmp_path):
    leaky = {**GOOD, "text": "Apna detail bhejein anadi.sharma@example.com par turant"}
    assert corpus.validate([write(tmp_path, [leaky])]) == 1


@pytest.mark.parametrize(
    "leaky",
    [
        "Turant paise bhejo 98765 43210 par abhi",       # spaced phone
        "Call kijiye 919876543210 par turant abhi",      # 91-prefixed
        "Card number 4111 1111 1111 1111 bhejein",       # card
        "Aadhaar 1234 5678 9012 verify karein turant",   # aadhaar
        "Payment karo rahul.kumar@paytm par turant",     # UPI handle
    ],
)
def test_rejects_identifier_formats_the_app_can_detect(tmp_path, leaky):
    """The gate must be at least as strong as the app's own detectors."""
    record = {**GOOD, "text": leaky}
    assert corpus.validate([write(tmp_path, [record])]) == 1, f"accepted: {leaky}"


def test_gate_reuses_the_app_extractor():
    """One definition of an unredacted identifier, not two.

    The gate runs `app.extract.entities`, so anything the app can detect in
    a live scan is rejected here -- it cannot silently fall behind.
    """
    from app.contracts import EntityKind

    assert corpus.entities.__module__ == "app.extract"
    for kind in (EntityKind.PHONE, EntityKind.CARD, EntityKind.AADHAAR, EntityKind.ID_NUMBER):
        assert kind in corpus.FORBIDDEN_KINDS


def test_accepts_masked_identifiers(tmp_path):
    masked = {**GOOD, "text": "Turant paise bhejo is number par 98******10 abhi"}
    assert corpus.validate([write(tmp_path, [masked])]) == 0


def test_rejects_duplicate_ids(tmp_path):
    assert corpus.validate([write(tmp_path, [GOOD, GOOD])]) == 1


def test_kappa_is_one_for_identical_annotations(tmp_path):
    rows = [GOOD, {**GOOD, "id": "t-2", "label": "legitimate"}]
    a = write(tmp_path, rows)
    b = tmp_path / "b.csv"
    b.write_bytes(a.read_bytes())
    assert corpus.kappa(a, b) == 0


def test_kappa_below_target_fails(tmp_path, capsys):
    rows_a = [{**GOOD, "id": f"t-{n}", "label": "phishing"} for n in range(10)]
    rows_b = [
        {**GOOD, "id": f"t-{n}", "label": "phishing" if n < 5 else "legitimate"}
        for n in range(10)
    ]
    a = write(tmp_path, rows_a)
    b = tmp_path / "b.csv"
    with b.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=corpus.COLUMNS)
        writer.writeheader()
        writer.writerows(rows_b)
    assert corpus.kappa(a, b) == 1
    assert "BELOW TARGET" in capsys.readouterr().out
