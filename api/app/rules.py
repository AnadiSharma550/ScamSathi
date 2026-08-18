"""Scam-pattern rules.

ponytail: rules live as Python data, not a YAML pack. There is no admin
rule editor yet, so a file format + loader + schema + pyyaml buys nothing a
list of tuples doesn't. Ceiling: rule changes need a deploy. Move to
`rulepacks/*.yaml` the day admins edit rules without shipping code (plan
Weeks 13-16).
"""

import re

from app.contracts import Indicator, Severity

RULE_VERSION = "rules-1"

# (code, family, severity, weight, pattern)
RULES: list[tuple[str, str, Severity, float, str]] = [
    # --- credential / OTP theft ---
    ("otp_request", "credential", Severity.CRITICAL, 0.85,
     r"\b(share|send|tell|forward|provide|batao|bhejo)\b.{0,30}\b(otp|one[\s-]?time[\s-]?password|pin|cvv)\b"),
    ("otp_never_share_lure", "credential", Severity.MAJOR, 0.6,
     r"\botp\b.{0,40}\b(verify|confirm|validate|activate)\b"),
    ("credential_request", "credential", Severity.CRITICAL, 0.8,
     r"\b(enter|update|confirm|verify|re-?submit)\b.{0,30}\b(password|net ?banking|user ?id|login|card (?:number|details)|account (?:number|details))\b"),
    ("kyc_lure", "credential", Severity.MAJOR, 0.65,
     r"\bkyc\b.{0,40}\b(expir\w+|pending|update|complete|suspend\w*|block\w*)\b"),

    # --- account pressure / urgency ---
    ("account_block_threat", "urgency", Severity.MAJOR, 0.6,
     r"\b(account|card|sim|number)\b.{0,30}\b(block|suspend|deactivat|clos|freez)\w*\b"),
    ("deadline_pressure", "urgency", Severity.MINOR, 0.35,
     r"\bwithin\s+\d+\s*(hour|hr|minute|min|day)s?\b|"
     r"\b(immediately|urgently|right now|last chance|final notice|act now|turant|abhi|jaldi)\b"),

    # --- payment ---
    ("advance_fee", "payment", Severity.MAJOR, 0.7,
     r"\b(registration|processing|security|refundable|activation|clearance|customs)\s+(fee|charge|amount|deposit)\b"),
    ("pay_to_receive", "payment", Severity.CRITICAL, 0.8,
     r"\b(pay|deposit|transfer|send)\b.{0,40}\b(to (?:claim|receive|release|unlock)|before (?:you )?(?:receive|claim))\b"),
    ("upi_collect_request", "payment", Severity.MAJOR, 0.65,
     r"\b(accept|approve|authorise|authorize)\b.{0,30}\b(collect|payment)\s*request\b"),

    # --- remote access ---
    ("remote_access_tool", "remote", Severity.CRITICAL, 0.85,
     r"\b(anydesk|teamviewer|quicksupport|screen[\s-]?shar\w+|remote (?:access|desktop))\b"),

    # --- impersonation ---
    ("authority_impersonation", "impersonation", Severity.MAJOR, 0.6,
     r"\b(?:from|this is|calling from)\b.{0,20}\b(bank|rbi|income tax|police|cyber cell|customs|courier|delivery)\b"),
    # Order-agnostic: Hinglish puts the amount before the verb
    # ("turant Rs 50,000 bhejo"), English puts it after.
    ("family_emergency", "impersonation", Severity.MAJOR, 0.65,
     r"\b(accident|hospital|emergency|arrested|in trouble|police station)\b.{0,80}"
     r"(?:\b(send|transfer|need|bhejo|bhej|dedo|de do)\b|(?:₹|\brs\.?|\binr)\s?[\d,]+)"),

    # --- reward / job / loan ---
    ("prize_lottery", "reward", Severity.MAJOR, 0.7,
     r"\b(you(?:'ve| have)? won|winner|lottery|lucky draw|prize|jackpot|cash reward)\b"),
    ("job_no_interview", "job", Severity.MAJOR, 0.6,
     r"\b(work from home|part[\s-]?time job|daily (?:income|earning)|no interview|earn\s*(?:₹|rs\.?|inr)?\s*[\d,]+\s*(?:per|/)\s*(?:day|hour))\b"),
    ("task_based_earning", "job", Severity.MAJOR, 0.65,
     r"\b(like (?:and|&) subscribe|complete (?:the )?task|rate (?:the )?(?:product|hotel)|telegram)\b.{0,40}\b(earn|paid|income|commission)\b"),
    ("instant_loan", "loan", Severity.MINOR, 0.45,
     r"\b(instant|pre[\s-]?approved|no documents?|without cibil)\b.{0,30}\b(loan|credit|cash)\b"),
]

COMPILED = [(c, f, s, w, re.compile(p, re.I | re.S)) for c, f, s, w, p in RULES]


def evaluate(text: str) -> tuple[float, list[Indicator]]:
    """Returns (score 0..1, indicators)."""
    hits: list[Indicator] = []
    families: set[str] = set()
    for code, family, severity, weight, pattern in COMPILED:
        m = pattern.search(text)
        if not m:
            continue
        families.add(family)
        hits.append(
            Indicator(
                code=f"rule.{code}",
                severity=severity,
                source="rule",
                weight=weight,
                rule_version=RULE_VERSION,
                evidence_span=(m.start(), m.end()),
            )
        )

    if not hits:
        return 0.0, []

    # Strongest signal dominates; independent families corroborate.
    score = max(h.weight for h in hits) + 0.1 * (len(families) - 1)
    return min(score, 1.0), hits
