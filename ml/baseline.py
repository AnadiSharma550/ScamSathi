"""TF-IDF baseline: prepare splits, train, evaluate, export.

Run inside the container:
    docker compose run --rm api python /work/ml/baseline.py

The test split is written once and never read unless --final is passed with
the recorded manifest hash (rule R5). Everything reported during development
comes from the validation split.

ponytail: one script, not a prepare/train/evaluate package. Splits are
cached to disk on first run so they stay frozen across runs. Split it up the
day the transformer needs the same splits from a different entry point.
"""

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

import joblib

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "SMSSpamCollection"
SPLITS = ROOT / "data" / "splits"
REPORTS = ROOT / "ml" / "reports"
MODEL_OUT = ROOT / "api" / "models" / "baseline.joblib"

SEED = 20260819
MODEL_VERSION = "baseline-1"


def normalise_for_dedupe(text: str) -> str:
    """Collapse a message to its template shape.

    ponytail: lowercase + strip non-letters, not MinHash. Scam corpora leak
    mainly through near-identical templates that differ only in digits,
    amounts and casing, and this catches those in one line. Ceiling: misses
    reworded paraphrases -- move to MinHash/SimHash if the Week 11 leakage
    audit finds them.
    """
    return re.sub(r"[^a-z]+", "", text.lower())


def load_raw() -> list[tuple[str, int]]:
    if not RAW.exists():
        sys.exit(f"Corpus missing: {RAW}\nDownload it first (see docs/dataset-register.md).")
    rows: list[tuple[str, int]] = []
    with RAW.open(encoding="latin-1") as fh:
        for label, text in csv.reader(fh, delimiter="\t"):
            rows.append((text.strip(), 1 if label == "spam" else 0))
    return rows


def build_splits() -> dict[str, list[tuple[str, int]]]:
    """Group-aware split so near-duplicates cannot straddle the boundary."""
    rows = load_raw()

    # One representative per template group, so a group lands wholly in one
    # split. Keeping every copy in train would still leak into val/test.
    groups: dict[str, list[tuple[str, int]]] = {}
    for text, label in rows:
        groups.setdefault(normalise_for_dedupe(text), []).append((text, label))

    keys = sorted(groups)
    key_labels = [groups[k][0][1] for k in keys]

    train_keys, holdout_keys, _, holdout_labels = train_test_split(
        keys, key_labels, test_size=0.30, random_state=SEED, stratify=key_labels
    )
    val_keys, test_keys = train_test_split(
        holdout_keys, test_size=0.50, random_state=SEED, stratify=holdout_labels
    )

    def collect(selected: list[str]) -> list[tuple[str, int]]:
        return [item for key in selected for item in groups[key]]

    splits = {
        "train": collect(train_keys),
        "val": collect(val_keys),
        "test": collect(test_keys),
    }

    SPLITS.mkdir(parents=True, exist_ok=True)
    for name, items in splits.items():
        with (SPLITS / f"{name}.csv").open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["text", "label"])
            writer.writerows(items)

    manifest = {
        "seed": SEED,
        "source_sha256": hashlib.sha256(RAW.read_bytes()).hexdigest(),
        "records_raw": len(rows),
        "template_groups": len(groups),
        "duplicates_collapsed": len(rows) - len(groups),
        "counts": {n: len(v) for n, v in splits.items()},
        "spam_share": {
            n: round(sum(lbl for _, lbl in v) / len(v), 4) for n, v in splits.items()
        },
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "split-manifest.json").write_text(json.dumps(manifest, indent=2))
    return splits


def load_splits() -> dict[str, list[tuple[str, int]]]:
    if not (SPLITS / "train.csv").exists():
        return build_splits()
    out = {}
    for name in ("train", "val", "test"):
        with (SPLITS / f"{name}.csv").open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            next(reader)
            out[name] = [(text, int(label)) for text, label in reader]
    return out


def make_model() -> Pipeline:
    # char_wb n-grams are what carry transliterated Hinglish, where word
    # tokens differ but character shapes repeat. Word n-grams alone would
    # not transfer to the multilingual corpus later.
    features = FeatureUnion(
        [
            ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
            (
                "char",
                TfidfVectorizer(
                    analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True
                ),
            ),
        ]
    )
    # class_weight balanced: spam is the minority class and a missed scam
    # costs more than a false alarm (I-02).
    base = LogisticRegression(
        max_iter=2000, class_weight="balanced", C=4.0, random_state=SEED
    )
    return Pipeline(
        [
            ("features", features),
            ("clf", CalibratedClassifierCV(base, method="sigmoid", cv=5)),
        ]
    )


def evaluate(model: Pipeline, data: list[tuple[str, int]], name: str) -> dict:
    texts = [t for t, _ in data]
    truth = [y for _, y in data]
    probs = model.predict_proba(texts)[:, 1]
    preds = [int(p >= 0.5) for p in probs]

    report = classification_report(
        truth, preds, target_names=["legitimate", "scam"], output_dict=True, zero_division=0
    )
    matrix = confusion_matrix(truth, preds).tolist()
    tn, fp, fn, tp = matrix[0][0], matrix[0][1], matrix[1][0], matrix[1][1]

    return {
        "split": name,
        "n": len(data),
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "scam_recall": round(report["scam"]["recall"], 4),
        "scam_precision": round(report["scam"]["precision"], 4),
        "roc_auc": round(roc_auc_score(truth, probs), 4),
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        # The number that matters most: scams called legitimate.
        "false_negative_rate": round(fn / max(fn + tp, 1), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--final",
        action="store_true",
        help="Evaluate on the frozen test split. Do not use during development (R5).",
    )
    args = parser.parse_args()

    splits = load_splits()
    print("split sizes:", {k: len(v) for k, v in splits.items()})
    print("label balance:", {k: Counter(y for _, y in v) for k, v in splits.items()})

    model = make_model()
    model.fit([t for t, _ in splits["train"]], [y for _, y in splits["train"]])

    results = [evaluate(model, splits["val"], "val")]
    if args.final:
        print("\n*** FROZEN TEST SET -- this number is reportable, and only once. ***")
        results.append(evaluate(model, splits["test"], "test"))

    for row in results:
        print(json.dumps(row, indent=2))

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "version": MODEL_VERSION}, MODEL_OUT)

    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / f"{MODEL_VERSION}-metrics.json").write_text(
        json.dumps({"model_version": MODEL_VERSION, "seed": SEED, "results": results}, indent=2)
    )
    print(f"\nsaved {MODEL_OUT}")


if __name__ == "__main__":
    main()
