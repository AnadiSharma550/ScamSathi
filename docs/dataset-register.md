# Dataset Register

Every corpus used to train or evaluate a ScamSathi model is recorded here before it is used. No source enters `data/` without a row in this table, a recorded licence, and a checksum.

Raw and processed data live under `data/`, which is **gitignored**. This register and the split manifest are the only things in source control — they are what makes an experiment reproducible without redistributing data we do not own.

---

## Active sources

### DS-01 · UCI SMS Spam Collection v.1

| Field | Value |
|---|---|
| **Purpose** | English baseline for the TF-IDF classifier (`baseline-1`) |
| **Synopsis reference** | [4] |
| **Retrieved** | 19 Aug 2026 from `https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip` |
| **Archive SHA-256** | `1587ea43e58e82b14ff1f5425c88e17f8496bfcdb67a583dbff9eefaf9963ce3` |
| **Size** | 203,415 bytes (zip) → 477,907 bytes (`SMSSpamCollection`) |
| **Records** | 5,574 — 4,827 ham (86.6%), 747 spam (13.4%) |
| **Language** | English only |
| **Format** | Tab-separated, `label \t text`, latin-1 encoded |
| **Copyright** | Tiago Agostinho de Almeida and José María Gómez Hidalgo |
| **Licence** | Free use with no limitations except retention of the copyright notice and attribution. Not a standard SPDX licence — the terms are in `data/raw/readme`, which must be kept alongside the corpus. |
| **Attribution obligation** | The authors request a citation to their paper and to `http://www.dt.fee.unicamp.br/~tiago/smsspamcollection/`. **This citation is required in the final report.** |

**Upstream provenance** (the corpus is itself compiled from four sources — worth stating in the report, because it explains the register's limitations):

| Component | Count | Origin |
|---|---|---|
| SMS spam | 425 | Grumbletext, a UK consumer complaints forum |
| SMS ham | 450 | Caroline Tagg's PhD thesis |
| SMS ham | 3,375 | NUS SMS Corpus — mostly Singaporean students, collected with consent |
| ham + spam | 1,002 + 322 | SMS Spam Corpus v.0.1 Big (Gómez Hidalgo) |

**Known limitations — these bound what `baseline-1` can be claimed to do:**

- **English only.** No Hindi, no Devanagari, no Hinglish. The project's core multilingual requirement is entirely unmet by this source.
- **UK/Singapore SMS culture, circa 2005–2011.** Premium-rate shortcodes, ringtone subscriptions and "txt to 87121" competitions. Indian scam patterns — UPI collect requests, KYC expiry, AnyDesk tech support, task-based earning, instant loan apps — are **absent**.
- **Binary labels.** ham/spam only, so it cannot train the 7-class categorisation. It trains P(scam) for the fusion formula's `Pm`; category attribution stays with the rule engine.
- **Not SMS-representative of the product's actual inputs**, which include screenshots and pasted chat messages, not just SMS.

This is why `fusion` currently lets the model raise risk but not lower it — see `WEIGHTS_VERSION = weights-1`. Treating an out-of-distribution "clean" verdict as evidence of safety is exactly the false-reassurance failure in I-02.

---

## Planned sources

Not yet collected. Each needs a row above, with licence and checksum, before use.

| ID | Source | Purpose | Blocking issue |
|---|---|---|---|
| DS-02 | NCRP / RBI awareness material [2][3] | Derive Indian scam patterns and non-sensitive examples | Paraphrase where required; record provenance per item |
| DS-03 | Publicly published scam examples | Phishing, job, payment, impersonation in Indian context | Verify collection terms permit research use; strip personal identifiers |
| DS-04 | Hand-written Hindi / Hinglish examples | Cover the gap DS-01 cannot | **Seed started** — see below. Must be flagged `synthetic=true` and **excluded from the held-out test set** |
| DS-05 | Screenshot benchmark | CER/WER measurement by language and quality tier | Needs ground-truth transcriptions; include a degraded tier (see note below) |

**Note for DS-05:** rule patterns are `\b`-anchored, so OCR that drops an inter-word space silently defeats them — observed with `kyc_lure` on a low-quality render. The benchmark must include a degraded tier specifically to quantify how often this happens.

### DS-04 seed (started)

`ml/seed/ds04-hinglish-seed.csv` — 42 hand-written records, 25 Hinglish / 17 Devanagari Hindi, covering all seven labels with no per-language gaps.

Tracked in Git, unlike `data/`, because we hold the rights and it is small. Downloaded and derived data stays out of source control; content we authored does not.

**This is a seed, not a corpus.** 42 synthetic records train nothing. Its purposes are:

1. Give DS-02/DS-03 collection a validated schema to land in.
2. Encode the annotation guide's borderline cases as data — `ds04-027` (delivers an OTP, does not request one), `ds04-034` (forwarded warning), `ds04-033` (marketing spam is legitimate), `ds04-041` (talking about spam). These are the hard negatives a model trained only on scam text will get wrong.
3. Cover patterns entirely absent from DS-01: UPI collect-request reversal, AnyDesk remote access, electricity-disconnection, customs-clearance fee, SIM-fraud scare, Aadhaar-only instant loan.

Every record is `synthetic=true`, so it is training-only and must never enter the held-out test set.

---

## Tooling

`ml/corpus.py` is the gate. Nothing enters `data/corpus/` without passing it.

```bash
python ml/corpus.py validate ml/seed/ds04-hinglish-seed.csv
python ml/corpus.py stats    ml/seed/*.csv
python ml/corpus.py kappa    annotator-a.csv annotator-b.csv
```

- **`validate`** rejects a record with no consent/licence basis, an unknown label or language, a `source_id` that does not reference this register, a duplicate id, or an unredacted phone number or email address. The redaction check is a real gate, not advice — 15 tests in `ml/test_corpus.py` cover it, including that masked forms (`98******10`) pass while raw ones do not.
- **`stats`** prints label and language distribution plus a per-language coverage grid that flags any label with zero examples in a language. A corpus can look balanced overall while a language has no examples of a whole category.
- **`kappa`** computes Cohen's κ overall **and per language**, and exits non-zero below 0.75. Per-language matters because a good overall figure can hide poor Hinglish agreement, which is exactly the split we care about. A κ below target means the guideline is at fault, not the annotators — add a borderline row to the annotation guide and re-label.

---

## Record schema

Every record carries, per the synopsis:

| Field | Meaning |
|---|---|
| `text` | The message |
| `label` | Scam category, or `legitimate` |
| `language` | `en` / `hi` / `hinglish` |
| `source_id` | `DS-01`…, so any record traces to a licence |
| `synthetic` | `true` for team-authored or generated records |
| `consent` | Licence or consent basis for this record |

`synthetic=true` records may appear in training only. They must never reach the held-out test set.

---

## Splits

Produced by `ml/baseline.py`, recorded in `ml/reports/split-manifest.json`.

- Grouped by normalised template shape before splitting, so near-duplicates cannot straddle the boundary. Scam corpora leak mainly through templates that differ only in digits and casing.
- Stratified by label. 70 / 15 / 15 train / val / test.
- Seed `20260819`, recorded in the manifest along with the source checksum.

**The test split is frozen.** `ml/baseline.py` only touches it when `--final` is passed. Every number quoted during development comes from validation. No accuracy figure is reportable until it comes from the frozen test set (R5).

---

## Rule coverage measured on DS-04 (development signal only)

**Not a reportable accuracy figure.** `rules-2` was tuned against the DS-04 seed, so the seed can no longer measure it — this records what the exercise found, not how good the rules are.

`rules-1`, before any Devanagari work:

| | Records | Detected | Missed |
|---|---|---|---|
| Scam | 30 | 13 | **17 (57%)** |
| Legitimate | 12 | 10 | 2 false alarms |

Thirteen of the seventeen misses were Devanagari. Every pattern in `rules-1` was ASCII — English with a handful of romanised Hinglish tokens — so an unambiguous Hindi card-detail phish scored Low Risk. The project's multilingual claim was true of OCR and untrue of detection.

`rules-2` adds Devanagari and wider Hinglish forms across every family, and reaches 30/30 and 12/12 on the seed. Again: fitted to that seed, so the number means "the gaps found are closed", nothing more.

**Held-out check.** Fourteen fresh cases (ten scams, four legitimate) were written afterwards and run once, untouched by tuning: **14/14**. They now live in `api/tests/test_multilingual.py` as regression cover, which means they are spent as a measurement too.

Honest evaluation of the rule engine still requires DS-02/DS-03 and the frozen test split (R5).

### Two false-alarm classes worth remembering

Both came from the annotation guide's own borderline cases, and both are easy to reintroduce:

- **Urgency is a modifier, not evidence.** Legitimate marketing is urgent. `deadline_pressure` is now weighted below the Caution threshold so it cannot band a message alone.
- **Mentioning a thing is not doing it.** "KYC is up to date" is not a KYC lure (B2); an OTP *delivery* is not an OTP *request* (B1); "block this spam number" is not an account threat; "contact the bank" is advice a real fraud alert gives, not impersonation.

### The model abstains on Devanagari

`baseline-1` scored **0.979** on an ordinary Hindi discount advert — it has never seen Devanagari and guessed confidently. Since fusion lets the model raise risk but not lower it, that confident guess became a false alarm the rules could not overrule.

`classifier.in_distribution` now returns False when fewer than 60% of letters are Latin, so the model does not vote on Devanagari at all and those messages rely on the rule engine. Hinglish is Latin-script Hindi and stays in distribution. Remove the gate when the model is retrained on the multilingual corpus.
