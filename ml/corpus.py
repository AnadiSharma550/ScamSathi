"""Corpus ingestion, validation and annotator agreement.

The schema gate for everything that enters `data/corpus/`. A record without
a licence basis, a source id, or a valid label does not get in -- which is
what keeps the dataset register honest rather than aspirational.

Usage:
    python ml/corpus.py validate data/corpus/ds04-hinglish.csv
    python ml/corpus.py stats    data/corpus/*.csv
    python ml/corpus.py kappa    annotator-a.csv annotator-b.csv
"""

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

COLUMNS = ["id", "text", "label", "language", "source_id", "synthetic", "consent", "comment"]

LABELS = {
    "legitimate",
    "phishing",
    "fake_job",
    "payment_upi",
    "impersonation",
    "prize_reward",
    "loan_investment",
}
LANGUAGES = {"en", "hi", "hinglish"}
BOOLS = {"true", "false"}

MIN_TEXT_CHARS = 10

# Run the application's own extractor over each record rather than keeping
# a second, weaker definition of what an unredacted identifier looks like.
# Using `entities` and not the raw patterns means the gate inherits the
# whole pipeline -- including digit-run classification -- so it is by
# construction exactly as strong as the app, and stays that way.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "api"))
from app.contracts import EntityKind  # noqa: E402
from app.extract import entities  # noqa: E402

# Contactable or identifying values. Amounts, urgency words and URL
# structure are evidence and must stay -- see annotation guide §6.
FORBIDDEN_KINDS = {
    EntityKind.PHONE,
    EntityKind.EMAIL,
    EntityKind.UPI_HANDLE,
    EntityKind.CARD,
    EntityKind.AADHAAR,
    EntityKind.ID_NUMBER,
}


def read(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def validate(paths: list[Path]) -> int:
    problems: list[str] = []
    seen_ids: set[str] = set()

    for path in paths:
        rows = read(path)
        if not rows:
            problems.append(f"{path}: empty")
            continue

        missing = set(COLUMNS) - set(rows[0].keys())
        if missing:
            problems.append(f"{path}: missing columns {sorted(missing)}")
            continue

        for n, row in enumerate(rows, start=2):
            where = f"{path}:{n}"
            if not row["id"]:
                problems.append(f"{where}: blank id")
            elif row["id"] in seen_ids:
                problems.append(f"{where}: duplicate id {row['id']}")
            else:
                seen_ids.add(row["id"])

            if len(row["text"].strip()) < MIN_TEXT_CHARS:
                problems.append(f"{where}: text shorter than {MIN_TEXT_CHARS} chars")
            if row["label"] not in LABELS:
                problems.append(f"{where}: unknown label {row['label']!r}")
            if row["language"] not in LANGUAGES:
                problems.append(f"{where}: unknown language {row['language']!r}")
            if not row["source_id"].startswith("DS-"):
                problems.append(f"{where}: source_id must reference the dataset register")
            if row["synthetic"].lower() not in BOOLS:
                problems.append(f"{where}: synthetic must be true/false")
            # The licence gate. No consent basis, no record.
            if not row["consent"].strip():
                problems.append(f"{where}: no consent/licence basis recorded")

            for entity in entities(row["text"]):
                if entity.kind in FORBIDDEN_KINDS:
                    problems.append(f"{where}: unredacted {entity.kind.value}")

    if problems:
        print(f"FAILED -- {len(problems)} problem(s):", file=sys.stderr)
        for problem in problems[:50]:
            print(f"  {problem}", file=sys.stderr)
        if len(problems) > 50:
            print(f"  ... and {len(problems) - 50} more", file=sys.stderr)
        return 1

    print(f"OK -- {len(seen_ids)} records across {len(paths)} file(s)")
    return 0


def stats(paths: list[Path]) -> int:
    rows = [row for path in paths for row in read(path)]
    if not rows:
        print("no records")
        return 1

    print(f"records: {len(rows)}\n")
    for field in ("label", "language", "source_id", "synthetic"):
        print(f"{field}:")
        for value, count in Counter(r[field] for r in rows).most_common():
            print(f"  {value or '(blank)':<16} {count:>6}  {count / len(rows):>6.1%}")
        print()

    # Synthetic records are training-only; the split step must honour this.
    synthetic = sum(1 for r in rows if r["synthetic"].lower() == "true")
    if synthetic:
        print(f"note: {synthetic} synthetic records -- training split only, never the test set")

    # Per-language label coverage: a corpus can look balanced overall while
    # a language has no examples of a whole category.
    print("\nlabel coverage by language:")
    languages = sorted({r["language"] for r in rows})
    print(f"  {'':<16}" + "".join(f"{lang:>10}" for lang in languages))
    for label in sorted(LABELS):
        counts = [
            sum(1 for r in rows if r["label"] == label and r["language"] == lang)
            for lang in languages
        ]
        flag = "  <- gap" if 0 in counts else ""
        print(f"  {label:<16}" + "".join(f"{c:>10}" for c in counts) + flag)
    return 0


def kappa(path_a: Path, path_b: Path) -> int:
    """Cohen's kappa on the overlap, overall and per language.

    Reported per language because a good overall figure can hide poor
    Hinglish agreement -- which is exactly the split we care about.
    """
    a = {r["id"]: r for r in read(path_a)}
    b = {r["id"]: r for r in read(path_b)}
    shared = sorted(set(a) & set(b))
    if not shared:
        print("no overlapping ids", file=sys.stderr)
        return 1

    def score(ids: list[str]) -> tuple[float, int]:
        if not ids:
            return float("nan"), 0
        labels_a = [a[i]["label"] for i in ids]
        labels_b = [b[i]["label"] for i in ids]
        n = len(ids)
        observed = sum(x == y for x, y in zip(labels_a, labels_b, strict=True)) / n

        count_a, count_b = Counter(labels_a), Counter(labels_b)
        expected = sum(
            (count_a[lbl] / n) * (count_b[lbl] / n) for lbl in LABELS
        )
        if expected == 1.0:
            return 1.0, n
        return (observed - expected) / (1 - expected), n

    overall, n = score(shared)
    print(f"overlap: {n} records")
    print(f"kappa (overall): {overall:.4f}  {'PASS' if overall >= 0.75 else 'BELOW TARGET 0.75'}")

    print("\nper language:")
    for lang in sorted(LANGUAGES):
        ids = [i for i in shared if a[i]["language"] == lang]
        value, count = score(ids)
        if count:
            print(f"  {lang:<10} n={count:<5} kappa={value:.4f}")

    print("\ndisagreements:")
    shown = 0
    for i in shared:
        if a[i]["label"] != b[i]["label"]:
            shown += 1
            if shown <= 20:
                print(f"  {i}: {a[i]['label']} vs {b[i]['label']} | {a[i]['text'][:60]}")
    print(f"  {shown} total")
    # A kappa below target means the guideline is at fault, not the people.
    return 0 if overall >= 0.75 else 1


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "stats"):
        p = sub.add_parser(name)
        p.add_argument("paths", nargs="+", type=Path)
    p = sub.add_parser("kappa")
    p.add_argument("annotator_a", type=Path)
    p.add_argument("annotator_b", type=Path)

    args = parser.parse_args()
    if args.command == "validate":
        sys.exit(validate(args.paths))
    if args.command == "stats":
        sys.exit(stats(args.paths))
    sys.exit(kappa(args.annotator_a, args.annotator_b))


if __name__ == "__main__":
    main()
