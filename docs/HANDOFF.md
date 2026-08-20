# Handoff — ScamSathi AI

**As of:** 20 Aug 2026 · **Repo:** https://github.com/AnadiSharma550/ScamSathi (public) · **Branch:** `main`, 13 commits, CI green
**Tests:** 149 passing — 128 API + 21 corpus gate

Read [CLAUDE.md](../CLAUDE.md) first. It loads automatically and carries the five rules, how to run things, the architecture, and the conventions. **This document does not repeat it** — it covers current state, why things are the way they are, and what to do next.

---

## 1. What we are building

A **multilingual scam-risk detection platform**. A user submits a message, a link, or a screenshot; the system returns a **risk band with evidence and safe actions**.

The single most important thing to understand: **it does not output "scam / not scam".** It outputs a risk band (Low / Caution / High / Unable to Assess) plus a separately-computed confidence, the evidence behind it, and what to do next. Risk is how strong the suspicious evidence is; confidence is how reliable the *input* is. That is why "Unable to Assess" exists as a fourth outcome rather than defaulting to Low.

It never says "safe". Low Risk means *no strong warning signs were found*, not a clearance. A test fails the build if generated copy contains "safe", "legitimate" or "verified".

Academic context: UPES major project, 24 weeks, 17 Aug 2026 → 31 Jan 2027, mid-term demo 11 Oct 2026. **Built solo** by Anadi Sharma — Nilaksh Parihar and Saksham Upadhyay are on the submission but not implementing. The plan was rewritten to say so; do not restore the three-person split.

---

## 2. Where the project actually stands

**All six Must features are done.**

| | Feature | Priority | State |
|---|---|---|---|
| F1 | Multi-input scanner | Must | ✅ text, link, screenshot |
| F2 | OCR review | Must | ✅ extracted text shown back |
| F3 | Hybrid risk analysis | Must | ✅ 23 rules + 10 URL checks + classifier |
| F4 | Explainable result | Must | ✅ evidence → action mapping |
| F5 | Guest mode | Must | ✅ no-retention, proven against the live DB |
| F10 | Admin API | Must | ✅ queue, review, audit, metrics — **no UI** |
| F6 | Optional account | Should | ⚠️ backend + JWKS done; **no frontend sign-in** |
| F9 | Feedback | Should | ⚠️ endpoint done, no UI |
| F7 | Awareness hub | Should | ❌ |
| F8 / F11 | Analytics | Should | ⚠️ admin metrics only; no personal trends |
| F12 | Installable PWA | Should | ❌ |

Active versions: `rules-2`, `baseline-1`, `weights-1`, `thresholds-0`.

**The frontend is one page.** A scanner with three tabs and a result view. That is deliberate — the user decided UI polish comes after the backend is complete. Keep structural accessibility (labels, `aria-live`, never colour alone) while doing so; visual design can wait, that cannot.

---

## 3. The honest gap

**The multilingual claim is true of OCR and the rule engine, and false of the ML.**

`baseline-1` is a TF-IDF + logistic regression trained on **DS-01, the UCI SMS Spam Collection** — English SMS from 2005–2011, UK/Singapore culture. It has never seen UPI, KYC lures, AnyDesk, Hinglish or Devanagari. Two consequences are wired into the code:

1. **The model may raise risk but never lower it** below the rule and URL evidence (`fusion.assess`). Wiring it in at the synopsis weight of 0.45 actually *reduced* recall — four unambiguous scams dropped from High to Caution because a confident out-of-distribution "clean" cancelled a fired CRITICAL rule.
2. **The model abstains on Devanagari** (`classifier.in_distribution`). It scored 0.979 on an ordinary Hindi discount advert. Under 60% Latin letters, it does not vote at all.

Both are documented departures from the synopsis formula, both serve issue I-02 (false reassurance is the harm that matters), and **both should be reverted when the model is retrained on a multilingual corpus with per-language calibration.**

**The corpus is the critical path.** Not code. DS-02/DS-03 do not exist yet. Until they do, there is no honest evaluation chapter — no per-class precision/recall, no confusion matrix, no calibration curve, no frozen-test number.

---

## 4. Things that will trip you up

Beyond the operational gotchas in CLAUDE.md:

- **`docs/PROJECT_PLAN.md` §13 is the decision log.** Every departure from the synopsis is recorded there with its rationale and its revert trigger. **Read it before "fixing" something that looks wrong** — most of the odd-looking code is deliberate and the reason is written down.
- **Two `sys.path` inserts exist on purpose.** `ml/corpus.py` imports `app.extract` so the corpus gate cannot fall behind the app's own detectors, and `api/scripts/grant_admin.py` adds its parent because Python puts the script's own directory on the path.
- **The lint hook can act on a half-finished state.** `.claude/hooks/lint.mjs` runs `ruff --fix` on every edit. It once deleted an import that was momentarily unused between two edits. If something vanishes, that is why.
- **The `.env` guard hook blocks writes to `.env`.** That is intentional — the repo is public. Edit it by hand.
- **Tests write to the dev database.** They are isolated by random user id so they are correct, but rows accumulate. A throwaway test DB would be cleaner.
- **DS-04 is spent as a measurement.** `rules-2` was tuned against it, and the 14 held-out cases written afterwards are now golden tests. Any number from either is a development signal, never a reportable accuracy figure (R5).

---

## 5. Deliberate shortcuts (the `ponytail:` ledger)

Ponytail is active. Each of these names its ceiling in a comment at the site. Run `grep -rn "ponytail:" api/app/ ml/` for the current list.

| Where | Shortcut | Upgrade when |
|---|---|---|
| `db.py` | Sync SQLAlchemy, not async | DB waits dominate |
| `ocr.py` | Pillow only, no OpenCV | The benchmark's photo tier shows deskew matters |
| `ratelimit.py` | In-process counters, no Redis | The API runs more than one instance |
| `rules.py` | Rules as Python data, not YAML packs | Admins edit rules without a deploy (Weeks 13–16) |
| `urlcheck.py` | Hand-rolled 2-label suffix list, no PSL | False positives show up in error analysis |
| `urlcheck.py` | Small hand-maintained brand-domain allowlist | It outgrows a screen |
| `ml/baseline.py` | One script; template-hash dedupe, not MinHash | The transformer needs the same splits; leakage audit finds paraphrases |

---

## 6. Known open issues, not yet fixed

From the security review. All real, none patched, each needing design rather than a quick fix:

1. **Multipart bodies spool to disk before the size check and rate limiter run.** FastAPI parses the form before dependencies, so a 10 GB upload is written before the 5 MB ceiling fires. Needs ASGI middleware ahead of routing.
2. **`ratelimit._MAX_KEYS` is not a real bound.** Daily-window slots stay live 24 h, so the prune cannot shrink anything once distinct keys exceed the cap.
3. **`pytesseract` writes a temp file**, so `ocr.py`'s "nothing touches disk" claim is overstated. Either acknowledge it or move to a direct binding.
4. **`urlcheck` keeps URL userinfo out of masking but rules never see it** — low impact, noted for completeness.

Run the reviewer before any milestone:

```
Agent(subagent_type="security-reviewer", prompt="Follow .claude/agents/security-reviewer.md. Review <scope>.")
```

It found 13 real findings on its first pass, including two that produced Low Risk with zero evidence. **Verify its claims yourself before acting** — it is right often enough to trust and wrong often enough to check.

---

## 7. What to do next

In priority order. The first is the only one that is genuinely blocking.

### 1. DS-02 / DS-03 corpus collection — the critical path
Everything in the evaluation chapter depends on it, and it has the longest lead time. The tooling is ready:

```bash
MSYS_NO_PATHCONV=1 docker compose run --rm -v "//c/MajorProject/ScamSathi:/work" -w /work \
  api python ml/corpus.py validate data/corpus/<file>.csv
```

The gate rejects a record with no consent basis, an unknown label, or an unredacted identifier, and it uses the app's own detectors so it cannot fall behind. `ml/seed/ds04-hinglish-seed.csv` is the schema template; `docs/annotation-guide.md` has the labelling rules and 12 borderline cases.

**DS-02 (NCRP/RBI awareness material) is the least legally fraught starting point** — public, citable, paraphrasable.

### 2. Frontend sign-in
The one untested path in the whole system. Supabase JWKS verification is wired and unit-tested against a local keypair, but **no real Supabase login has ever happened**. Until it does, F6 is unproven and the admin API has no way in.

### 3. Admin UI
The endpoints are real and tested but invisible. For a viva, "there are endpoints" is much weaker than a dashboard.

### 4. Awareness hub (F7)
Straightforward CRUD plus content authoring. Also unblocks the content-management half of F10 that was deliberately skipped.

### Scope buffer, if time runs short
Sacrifice in this order: **F11 aggregate analytics → F8 personal trends → F12 PWA → F7 reduced to ~6 articles.** The Musts do not move.

---

## 8. Blocked on the user

Things no agent can or should do:

- **Data collection judgement** — sourcing, licence checks, deciding what is fair use.
- **Hindi copy review.** `explain.py` is English-only *by design*; the plan requires a native speaker, not machine translation. The DS-04 seed shows the register and tone.
- **Cohen's κ.** It measures agreement between two *people*. Solo labelling cannot produce it and inventing a second annotator would be fabricating a result. Three honest options are in PROJECT_PLAN §8 — the best is asking Nilaksh or Saksham to label the 500-record overlap, which is a few hours and the one task where their participation is methodologically required.
- **Anything requiring account creation, credentials or accepting terms.**

Already done and not blocking: the Supabase project exists (`ptjqeuqmlqldlnudovff`), signs with ES256, and needs **no secret** — verification uses the public JWKS. `SUPABASE_URL` is not confidential.

---

## 9. Ground rules for whoever continues

1. **The five rules in CLAUDE.md are not negotiable.** They are enforced by tests, not convention, because there is no second reviewer on this project.
2. **When uncertain, return `UNABLE_TO_ASSESS`, never `LOW`.** The harm model is false reassurance. Three separate bugs this project has already shipped were all this same shape — output that looked confident and clean while evidence existed.
3. **Never quote an accuracy number** that did not come from the frozen test set with `--final` (R5).
4. **Record every departure from the synopsis** in PROJECT_PLAN §13, with the reason and the trigger to revert. That log is also the viva preparation — one person has to answer for all of it.
5. **Leave one runnable check behind** for non-trivial logic. Ponytail's rule, and the only reason regressions get caught here.
6. **Verify before claiming.** Run the code, read the output, then say what it does. Several findings this project acted on came from measuring rather than assuming — and at least one subagent finding was wrong on inspection.
