# Annotation Guide

How to label a record for the ScamSathi corpus.

**On agreement:** Cohen's kappa measures agreement between *two people*. This is a solo build, so see PROJECT_PLAN.md §8 for the three options — get a teammate to label the overlap (preferred), report intra-annotator consistency over a time gap and label it as such, or report neither. Do not report a kappa that did not come from two independent annotators. Everything below applies regardless of which option is taken; the guideline is the consistency control.

Read this whole document before labelling anything. The borderline cases in §4 are where agreement is actually won or lost.

---

## 1. The question you are answering

> **Would acting on this message, as written, expose the recipient to loss?**

You are labelling the *message*, not the sender, and not what actually happened. A real bank SMS that happens to sound alarming is `legitimate`. A scam that failed is still a scam.

You are **not** judging how convincing it is. A clumsy scam is still a scam.

---

## 2. Labels

| Label | Use when | Do not confuse with |
|---|---|---|
| `legitimate` | Ordinary message, or a genuine service notification | Marketing spam — see §3 |
| `phishing` | Seeks credentials, OTP, PIN, card details, or account access; includes KYC-expiry lures | `impersonation`, where the goal is a direct transfer |
| `fake_job` | Employment, internship or task-based earning offer used as bait | `loan_investment` |
| `payment_upi` | Seeks a payment, collect-request approval, or advance fee | `prize_reward`, where the hook is the winning |
| `impersonation` | Poses as a person or authority — bank, police, family emergency, remote-access "support" | `phishing`, where the goal is credentials |
| `prize_reward` | Lottery, lucky draw, gift, cashback that the recipient never entered | `payment_upi` |
| `loan_investment` | Instant loan, pre-approved credit, guaranteed returns, trading tips | `fake_job` |

**When two apply, label the *mechanism of loss*, not the story.** "You won a prize, pay ₹4,999 to release it" is `payment_upi` — the prize is the pretext, the fee is how money is lost. This rule resolves most disagreements.

---

## 3. Spam is not scam

Unsolicited marketing is **`legitimate`** for our purposes. The product's job is to warn about loss, not about annoyance, and labelling promotional messages as scams inflates the false-positive rate on exactly the traffic users receive most.

| Message | Label | Why |
|---|---|---|
| "50% off at Big Bazaar this weekend, reply STOP to opt out" | `legitimate` | Unwanted, but no loss mechanism |
| "Your Jio recharge of ₹239 was successful" | `legitimate` | Genuine notification |
| "Win a free iPhone! Click here to claim" | `prize_reward` | Unentered prize + action hook |

⚠️ **DS-01 (UCI SMS Spam) labels promotional spam as `spam`.** Its labels are *not* our labels. When re-annotating any DS-01 record, apply this section, not the original tag.

---

## 4. Borderline cases

These are the ones that break agreement. Decide them this way, every time.

| # | Case | Label | Reasoning |
|---|---|---|---|
| B1 | "Your OTP is 445566. Do not share it with anyone." | `legitimate` | *Delivers* an OTP. Only a request to **share** one is phishing. |
| B2 | "Dear customer, your KYC is expiring, visit your branch" — no link, no request | `legitimate` | Genuine advisories exist. Without a link, a request, or urgency, there is no loss mechanism. |
| B3 | Same as B2 but with a link | `phishing` | The link is the mechanism. |
| B4 | Real bank message with an alarming tone | `legitimate` | Tone is not evidence. Check for a request or a link. |
| B5 | Job offer from a real company, poorly written | `legitimate` | Bad writing is not fraud. Look for the fee or the credential request. |
| B6 | "Register for this internship — ₹500 registration fee" | `fake_job` | Genuine employers do not charge applicants. |
| B7 | Friend asks to borrow money, no urgency, normal phrasing | `legitimate` | Personal messages are not scams. B8 is the contrast. |
| B8 | "Mum I lost my phone, this is my new number, send ₹20,000 urgently" | `impersonation` | New number + urgency + money = the hijack pattern. |
| B9 | Forwarded scam **with a warning**: "careful, I got this fake message" | `legitimate` | The intent is protective. Note it in `comment` — these are useful hard negatives. |
| B10 | Screenshot where OCR lost half the text | *Do not label* | Mark `unreadable` and exclude. Do not guess at missing content. |
| B11 | Genuine debt-collection message with legal threat | `legitimate` | Unpleasant but real. Look for an unofficial payment channel — that would make it `payment_upi`. |
| B12 | Crypto "guaranteed 20% monthly returns" | `loan_investment` | Guaranteed-return promises are the marker. |

---

## 5. Fields to record

| Field | Notes |
|---|---|
| `text` | Verbatim. Do not fix spelling — misspelling is signal. |
| `label` | From §2 |
| `language` | `en` / `hi` / `hinglish`. Hinglish = Hindi words in Latin script, or mixed within one message. |
| `source_id` | `DS-01`… from the dataset register |
| `synthetic` | `true` if you wrote it |
| `consent` | Licence or consent basis |
| `comment` | **Required** whenever you hesitated. This is what adjudication reads. |

---

## 6. Redaction — before the record is saved

Replace real identifiers, always, even in public examples:

- phone → `98******10` · email → `a***@example.com` · UPI → `n***@paytm`
- account and card numbers → `XXXX`
- **Keep** the URL structure — `sbi-verify.xyz/login` is the evidence. Do not shorten or "clean" it.
- Keep amounts and dates. They carry signal.

Never commit a record containing a real person's contact details. If a message identifies a private individual, drop the record.

---

## 7. Process

Solo labelling — the default path:

1. Label in batches, following this guide. Never label from memory of a similar record.
2. Whenever you hesitate, fill in `comment` and, if the case generalises, add a row to §4. **The guideline is the consistency control when there is no second annotator**, so growing §4 is the actual quality work.
3. Re-read §4 at the start of each session. Drift is the solo failure mode.
4. Version this file. Any change after labelling begins requires re-checking affected records.

If a second annotator is available (preferred — see PROJECT_PLAN.md §8):

5. Label independently. **Do not discuss while labelling** — discussion inflates κ without improving the guideline.
6. Overlap sample: 500 records.
7. `python ml/corpus.py kappa a.csv b.csv` — reports overall and per language. A good overall κ can hide poor Hinglish agreement.
8. κ < 0.75 → the guideline is at fault, not the annotators. Add a borderline row to §4 and re-label the disputed slice.
9. Adjudicate disagreements and record the decision.

---

## 8. What never gets labelled

- Real user submissions to the deployed product — guest scans are not retained (R3), and saved scans require explicit consent before any research use.
- Anything containing credentials, live OTPs, or full card numbers. Drop the record.
- Content targeting a private individual.
