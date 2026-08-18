"""Template explanations.

R1: this module describes evidence that already exists. It never computes or
adjusts risk. When the optional LLM layer lands it reworders these strings and
nothing more.

English only for now -- the plan requires Hindi copy reviewed by a native
speaker, not machine-translated, so `hi` stays unshipped rather than wrong.
"""

from app.contracts import Explanation, Language, RiskAssessment, RiskBand, UnableReason

LIMITATION = (
    "ScamSathi provides decision support only. It cannot guarantee that any "
    "message or link is genuine, and a Low Risk result is not a clearance."
)

HEADLINE = {
    RiskBand.HIGH: "Strong warning signs. Treat this as a scam until proven otherwise.",
    RiskBand.CAUTION: "Some warning signs found. Check before you act.",
    RiskBand.LOW: "No strong warning signs found in this message.",
    RiskBand.UNABLE_TO_ASSESS: "Not enough to go on.",
}

UNABLE_HELP = {
    UnableReason.TEXT_TOO_SHORT: "The message is too short to analyse. Paste more of it.",
    UnableReason.OCR_TOO_POOR: "The screenshot was hard to read. Retake it in better light, or paste the text instead.",
    UnableReason.MODEL_MARGIN_LOW: "The signals were too mixed to call. Treat it with caution.",
    UnableReason.COMPONENT_DISAGREEMENT: "The checks disagreed with each other. Treat it with caution.",
}

# code -> (what we noticed, what to do)
EVIDENCE: dict[str, tuple[str, str]] = {
    "rule.otp_request": ("It asks you to share an OTP, PIN or CVV.", "Never share an OTP. No bank or company will ask for one."),
    "rule.otp_never_share_lure": ("It uses an OTP to create a sense of process.", "Never share an OTP, even to 'confirm' something."),
    "rule.credential_request": ("It asks for a password, card or account details.", "Do not enter details from a link. Open the official app yourself."),
    "rule.kyc_lure": ("It claims your KYC is expiring or incomplete.", "Check your KYC status in the bank's own app, not through this message."),
    "rule.account_block_threat": ("It threatens to block or suspend your account.", "Contact your bank on the number printed on your card."),
    "rule.deadline_pressure": ("It pushes you to act within a deadline.", "Slow down. Urgency is the most common pressure tactic."),
    "rule.advance_fee": ("It asks for a fee before you receive anything.", "Do not pay. Genuine offers do not charge you upfront."),
    "rule.pay_to_receive": ("It asks you to pay in order to claim something.", "Do not pay. This is the shape of an advance-fee scam."),
    "rule.upi_collect_request": ("It asks you to approve a payment request.", "Approving a collect request sends money out. Decline it."),
    "rule.remote_access_tool": ("It asks you to install remote-access software.", "Do not install it. This hands over your screen and accounts."),
    "rule.authority_impersonation": ("It claims to be from a bank or government body.", "Hang up and call the official number yourself."),
    "rule.family_emergency": ("It combines an emergency story with a money request.", "Call the person directly on a number you already have."),
    "rule.prize_lottery": ("It claims you have won a prize or lottery.", "You cannot win a draw you never entered."),
    "rule.job_no_interview": ("It offers income with no interview or screening.", "Check the company independently before sharing anything."),
    "rule.task_based_earning": ("It offers payment for small online tasks.", "Task-and-commission offers routinely end in a demand for deposits."),
    "rule.instant_loan": ("It offers instant credit with no documentation.", "Check the lender on the RBI register before applying."),
    "url.bad_scheme": ("The link does not use a normal web address.", "Do not open it."),
    "url.ip_literal_host": ("The link points at a raw IP address, not a domain name.", "Do not open it."),
    "url.punycode_host": ("The link's address uses characters that can imitate another name.", "Do not open it. Type the address yourself instead."),
    "url.credentials_in_url": ("The link hides a username or password inside the address.", "Do not open it."),
    "url.shortener": ("The link is shortened, so the destination is hidden.", "Ask the sender for the full address."),
    "url.deep_subdomain": ("The link's address is unusually nested.", "Check the address carefully before opening."),
    "url.suspicious_tld": ("The link uses a domain ending commonly seen in scams.", "Do not open it."),
    "url.no_tls": ("The link is not encrypted.", "Do not enter any details on it."),
    "url.brand_outside_domain": ("The link names a known brand but is not that brand's own website.", "Open the brand's app or type its address yourself."),
    "url.long_path": ("The link's address is unusually long.", "Check the address carefully before opening."),
}

FINANCIAL_ACTION = (
    "If money has already left your account, call 1930 and report at "
    "cybercrime.gov.in immediately."
)
FINANCIAL_CODES = {"rule.advance_fee", "rule.pay_to_receive", "rule.upi_collect_request", "rule.family_emergency"}


def build(assessment: RiskAssessment, language: Language = Language.EN) -> Explanation:
    if assessment.band == RiskBand.UNABLE_TO_ASSESS:
        help_line = UNABLE_HELP.get(
            assessment.unable_reason, "Try again with more of the message."
        )
        return Explanation(
            headline=HEADLINE[RiskBand.UNABLE_TO_ASSESS],
            why=[help_line],
            actions=["Do not act on this result. Check the message another way."],
            limitation_notice=LIMITATION,
            language=language,
        )

    # Strongest evidence first, deduplicated, capped by the contract.
    ranked = sorted(assessment.indicators, key=lambda i: -i.weight)
    why: list[str] = []
    actions: list[str] = []
    for ind in ranked:
        pair = EVIDENCE.get(ind.code)
        if not pair:
            continue
        if pair[0] not in why and len(why) < 5:
            why.append(pair[0])
        if pair[1] not in actions and len(actions) < 3:
            actions.append(pair[1])

    if not why:
        why = ["None of the known scam patterns matched this message."]
    if not actions:
        actions = ["Check with the sender through a channel you already trust."]

    if any(i.code in FINANCIAL_CODES for i in assessment.indicators):
        actions.append(FINANCIAL_ACTION)

    return Explanation(
        headline=HEADLINE[assessment.band],
        why=why,
        actions=actions[:4],
        limitation_notice=LIMITATION,
        language=language,
    )
