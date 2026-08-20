# ScamSathi AI

Multilingual scam-risk detection. A user submits a message, a link, or a screenshot; the system returns a **risk band with evidence**, not a verdict.

**Picking up this project?** Start with [docs/HANDOFF.md](docs/HANDOFF.md) — current state, open issues, and what to do next.

Full plan and every non-obvious decision: [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md). Its §13 change log is the record of *why* things differ from the synopsis — read it before "fixing" something that looks wrong.

---

## Five rules that never bend

Violating any of these is a bug, however convenient.

| | Rule |
|---|---|
| **R1** | GenAI never computes, raises or lowers risk. It may only reword an already-computed, evidence-backed explanation. |
| **R2** | Never say "safe". Low Risk = "no strong warning signs found". Every result carries a limitation notice. A test fails the build if generated copy contains "safe", "legitimate" or "verified". |
| **R3** | Guest scans are never persisted. There is no guest write path — saving requires an authenticated user by construction, not by a flag. |
| **R4** | The server never fetches a submitted URL. `urlcheck` does structural analysis only and must never import an HTTP client. |
| **R5** | No accuracy number is quoted until it comes from the frozen test set. `ml/baseline.py` only touches it with `--final`. |

**Default when uncertain: `UNABLE_TO_ASSESS`, never `LOW`.** The harm model is false reassurance (issue I-02).

---

## Running things

**Everything runs in Docker.** The host has Python 3.14; the ML stack (scikit-learn, Pillow, pytesseract) needs 3.11, and Tesseract is not installed on the host at all.

```bash
docker compose up -d              # api :8000, db :5433
docker compose run --rm api python -m pytest -q     # 55 tests
docker compose run --rm api sh -c "ruff check . && python -m pytest -q"
docker compose run --rm api alembic upgrade head
```

Gotchas that cost time if forgotten:

- **Postgres is on host port 5433**, not 5432 — an unrelated container owns 5432 on this machine. Inside the compose network it is still 5432, so `DATABASE_URL` is unchanged.
- **Git Bash mangles container paths.** Prefix with `MSYS_NO_PATHCONV=1` when passing absolute container paths, and use `//c/...` for host mounts:
  ```bash
  MSYS_NO_PATHCONV=1 docker compose run --rm -v "//c/MajorProject/ScamSathi:/work" -w /work api python -m pytest ml/ -q
  ```
- **`ml/` tests and scripts need the repo root mounted at `/work`** — only `api/` is mounted by default.
- **Never pipe a heredoc into `python`** on this machine; the bare `python` resolves to a Microsoft Store stub and hangs. Use the Write tool or `python -c`.
- The frontend runs via the preview tooling, not `npm run dev` in a shell.

---

## Architecture

FastAPI **modular monolith**. Flat modules under `api/app/`, each a pure function of its inputs, composed **only** in `main.analyse`:

```
ingest → ocr → extract → urlcheck → rules → classifier → fusion → explain
```

- `contracts.py` is the seam. Every module speaks these Pydantic types and nothing else. Changing it ripples everywhere — think before editing.
- Modules do not import each other. If you need two, compose them in `main.analyse`.
- Determinism is a graded requirement: same input + same versions ⇒ same output. No wall-clock, no randomness, no network in the pipeline.

**Fusion has two deliberate departures from the synopsis formula** (both in §13, both serving I-02):
1. Only components that actually ran get a share of the denominator. An absent component scored 0 because it was *absent*, not because the input was clean.
2. The model may **raise** risk but never lower it below rule+URL evidence, while it remains out-of-distribution. `baseline-1` is trained on English SMS spam from 2005–2011 and knows nothing of UPI, KYC lures, AnyDesk or Hinglish.

Revert (2) only when the model is retrained on the multilingual corpus with per-language calibration.

---

## What is and is not done

Done: text/link/screenshot scanning, 16 rules, 10 URL checks, OCR (`eng+hin`), TF-IDF classifier, saved history with ownership isolation, feedback, rate limiting, Supabase JWT via JWKS, admin API (F10), CI green.

Not done: awareness hub (F7), analytics (F8/F11), PWA (F12), frontend sign-in, admin UI, MuRIL transformer.

### Administration

Admin routes are role-gated by `require_admin`, which reads `profiles.role` — never the token. The API covers the feedback queue, review with audit, de-identified metrics and indicator frequency. **There is no admin UI yet**; the endpoints are real and tested.

Two deliberate omissions: content management (F7 does not exist, so there is nothing to manage) and rule/model version tables (versions are code constants; a table would duplicate state).

Administrators cannot read scan text. The queue carries evidence codes, band and category but no excerpt — masked content is still the user's content. If a case cannot be judged without it, that needs an explicit consent flow, not a wider default.

Granting the role — the user must sign in once first so the profile row exists:

```bash
docker compose run --rm api python scripts/grant_admin.py --list
docker compose run --rm api python scripts/grant_admin.py <user-id>
```

A script, not a psql one-liner, because the grant is itself an administrative change and belongs in the audit trail.

**The real bottleneck is the corpus, not code.** The multilingual claim is currently true of OCR and a few regexes, not of the ML. `ml/corpus.py` gates anything entering the corpus; `ml/seed/ds04-hinglish-seed.csv` is the template.

---

## Conventions

- **Ponytail is active** (`.claude/skills/ponytail`). Take the laziest solution that works: stdlib before a dependency, delete before adding, no scaffolding for later. Mark deliberate shortcuts with a `ponytail:` comment naming the ceiling and the upgrade path.
- Never simplify away: input validation at trust boundaries, security controls, accessibility basics.
- Non-trivial logic leaves one runnable check behind. Safety rules are held by **tests**, not by convention — there is no second reviewer on this project.
- User-facing copy in `explain.py` is English only by design. Hindi needs a native speaker, not machine translation.
- Never commit `data/`, `api/models/`, `.env`, or the synopsis `.docx`/`.pptx` (they carry SAP IDs and the repo is public).
- Frontend is a thin harness to prove the backend works. Visual polish comes later; structural accessibility (labels, `aria-live`, never colour alone) does not.

## Solo build

Nilaksh Parihar and Saksham Upadhyay are on the submission; the implementation is solo. No PR reviewer exists — CI green plus the safety tests are the gate. See PROJECT_PLAN.md §8, including why Cohen's κ cannot honestly be reported without a second annotator.
