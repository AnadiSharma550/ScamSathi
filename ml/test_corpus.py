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
