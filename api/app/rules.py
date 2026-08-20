"""Scam-pattern rules.

ponytail: rules live as Python data, not a YAML pack. There is no admin
rule editor yet, so a file format + loader + schema + pyyaml buys nothing a
list of tuples doesn't. Ceiling: rule changes need a deploy. Move to
`rulepacks/*.yaml` the day admins edit rules without shipping code (plan
Weeks 13-16).

Each pattern carries its Devanagari and Hinglish forms inline rather than
being duplicated as a separate rule, so one scam family stays one code and
one weight regardless of the language it arrives in.

Two things to know when editing:

- **Word order flips.** Hindi puts the object before the verb, so English
  "share your OTP" is Devanagari "ओटीपी बताइए". Patterns that need both
  need both orders.
- **Urgency is a modifier, not evidence.** Legitimate marketing is urgent
  too. `deadline_pressure` is weighted below the Caution threshold so it
  cannot band a message on its own.
"""

import re

from app.contracts import Indicator, Severity

RULE_VERSION = "rules-2"

# (code, family, severity, weight, pattern)
RULES: list[tuple[str, str, Severity, float, str]] = [
    # --- credential / OTP theft ---
    ("otp_request", "credential", Severity.CRITICAL, 0.85,
     r"\b(share|send|tell|forward|provide|batao|bataao|batayein|bataiye|bhejo|bhejein|bhejiye)\b.{0,30}\b(otp|one[\s-]?time[\s-]?password|pin|cvv)\b"
     r"|(?:ओटीपी|पिन|सीवीवी|ओ ?टी ?पी).{0,40}(?:बताइए|बताएं|बताओ|भेजें|भेजिए|भेजो|साझा|दीजिए|दें)"
     r"|(?:बताइए|बताएं|बताओ|साझा कीजिए).{0,30}(?:ओटीपी|पिन|सीवीवी)"
     # Hinglish flips the order: "OTP aaya hoga, wo mujhe batayein".
     # Only Hinglish verbs here -- adding "share" would fire on the
     # legitimate "do not share it with anyone" delivery message (guide B1).
     r"|\b(otp|pin|cvv)\b.{0,40}\b(batao|bataao|batayein|bataiye|bhejo|bhejein|bhejiye)\b"),
    ("otp_never_share_lure", "credential", Severity.MAJOR, 0.6,
     r"\botp\b.{0,40}\b(verify|confirm|validate|activate)\b"
     r"|(?:ओटीपी).{0,40}(?:सत्यापित|पुष्टि|सक्रिय)"),
    ("credential_request", "credential", Severity.CRITICAL, 0.8,
     r"\b(enter|update|confirm|verify|re-?submit|daalein|daalo|dalein|chahiye)\b.{0,30}\b(password|net ?banking|user ?id|login|pin|card (?:number|details)|account (?:number|details))\b"
     r"|\b(password|net ?banking|user ?id|card number|upi pin|pin)\b.{0,25}\b(chahiye|batao|batayein|bhejo|bhejein|daalein|daalo)\b"
     r"|(?:पासवर्ड|नेट ?बैंकिंग|यूज़र ?आईडी|कार्ड ?नंबर|खाता ?संख्या|यूपीआई ?पिन).{0,40}(?:बताइए|बताएं|भेजें|भेजिए|सत्यापित|अपडेट|दर्ज|दीजिए|दें)"),
    ("kyc_lure", "credential", Severity.MAJOR, 0.65,
     r"\bkyc\b.{0,40}\b(expir\w+|pending|update|complete|suspend\w*|block\w*)\b"
     # "अपडेट है" (is up to date) is a genuine advisory; "अपडेट करें"
     # (update it) is the lure. Bare "अपडेट" fired on both -- guide B2.
     r"|(?:केवाईसी).{0,40}(?:समाप्त|एक्सपायर|लंबित|निलंबित|अधूरी|पूरी नहीं|अपडेट कर|पूरा कर|सत्यापित कर)"),
    ("sim_fraud_scare", "credential", Severity.MAJOR, 0.6,
     r"\bsim\b.{0,40}\b(illegal|fraud|misuse|blocked|issued)\b.{0,40}\b(verify|details|kyc)\b"
     r"|(?:सिम).{0,40}(?:अवैध|गलत|जारी).{0,40}(?:सत्यापित|विवरण)"),

    # --- account pressure / urgency ---
    # Requires the recipient's own thing to be under threat. Without the
    # possessive this fired on "ye number block kar dena" -- a user asking
    # someone to block a spam caller, which is the opposite of a scam.
    ("account_block_threat", "urgency", Severity.MAJOR, 0.6,
     r"\b(your|aapka|aapke|aapki)\b.{0,30}\b(account|card|sim|number|khata)\b.{0,45}\b(block|suspend|deactivat|clos|freez|band)\w*"
     r"|(?:आपका|आपके|आपकी).{0,30}(?:खाता|कार्ड|सिम|नंबर).{0,45}(?:ब्लॉक|निलंबित|बंद|बलॉक|फ़्रीज़)"),
    # Weighted below the Caution threshold: legitimate marketing is urgent
    # too, so urgency alone must never band a message.
    ("deadline_pressure", "urgency", Severity.MINOR, 0.3,
     r"\bwithin\s+\d+\s*(hour|hr|minute|min|day)s?\b"
     r"|\b(immediately|urgently|right now|last chance|final notice|act now|turant|jaldi)\b"
     r"|(?:तुरंत|तत्काल|शीघ्र|आज ही|अंतिम मौका|अंतिम सूचना)"
     r"|(?:\d+\s*(?:घंटे|मिनट|दिन)\s*में)"),

    # --- payment ---
    ("advance_fee", "payment", Severity.MAJOR, 0.7,
     r"\b(registration|processing|security|refundable|activation|clearance|customs)\s+(fee|charge|amount|deposit)\b"
     r"|(?:पंजीकरण|प्रोसेसिंग|प्रसंस्करण|सुरक्षा|सक्रियण|क्लीयरेंस|कस्टम)\s*(?:शुल्क|फ़ीस|फीस|राशि|जमा)"
     r"|(?:सुरक्षा\s*जमा\s*राशि)"),
    ("pay_to_receive", "payment", Severity.CRITICAL, 0.8,
     r"\b(pay|deposit|transfer|send)\b.{0,40}\b(to (?:claim|receive|release|unlock)|before (?:you )?(?:receive|claim))\b"
     r"|(?:पाने|प्राप्त करने|छुड़ाने|जीतने|क्लेम करने)\s*के\s*लिए.{0,40}(?:भुगतान|जमा|शुल्क|पैसे|भेज|राशि)"),
    ("upi_collect_request", "payment", Severity.MAJOR, 0.65,
     r"\b(accept|approve|authorise|authorize)\b.{0,30}\b(collect|payment)\s*request\b"
     r"|\b(collect|payment)\s*request\b.{0,30}\b(accept|approve|karein|karo|kijiye)\b"
     r"|(?:कलेक्ट|भुगतान)\s*(?:रिक्वेस्ट|अनुरोध).{0,30}(?:स्वीकार|एक्सेप्ट)"),
    ("wrong_transfer_refund", "payment", Severity.MAJOR, 0.65,
     r"\b(by mistake|galti se|accidentally)\b.{0,50}\b(sent|transferred|bhej)\w*\b.{0,50}\b(return|refund|wapas|send back)\b"
     r"|(?:गलती से).{0,60}(?:भेज).{0,60}(?:वापस)"),

    # --- remote access ---
    ("remote_access_tool", "remote", Severity.CRITICAL, 0.85,
     r"\b(anydesk|teamviewer|quicksupport|screen[\s-]?shar\w+|remote (?:access|desktop))\b"
     r"|(?:एनीडेस्क|टीमव्यूअर|स्क्रीन ?शेयर|रिमोट ?एक्सेस)"),

    # --- impersonation ---
    ("authority_impersonation", "impersonation", Severity.MAJOR, 0.6,
     r"\b(?:from|this is|calling from)\b.{0,20}\b(bank|rbi|income tax|police|cyber cell|customs|courier|delivery)\b"
     r"|\b(bank|rbi|police|cyber cell|customer care)\b.{0,20}\bse bol\w*\b"
     # Only the sender *claiming* to be an authority. "बैंक से संपर्क करें"
     # (contact the bank) is what a genuine fraud alert tells you to do.
     r"|(?:बैंक|आरबीआई|पुलिस|साइबर ?सेल|कस्टमर ?केयर|आयकर|कस्टम).{0,20}(?:से बोल|से कॉल कर रह)"),
    ("family_emergency", "impersonation", Severity.MAJOR, 0.65,
     r"\b(accident|hospital|emergency|arrested|in trouble|police station)\b.{0,80}"
     r"(?:\b(send|transfer|need|bhejo|bhej|dedo|de do)\b|(?:₹|\brs\.?|\binr)\s?[\d,]+)"
     r"|(?:अस्पताल|दुर्घटना|एक्सीडेंट|इमरजेंसी|गिरफ़्तार|गिरफ्तार).{0,80}(?:पैसे|रुपये|भेज|राशि)"),
    # The number-hijack shape: new number, urgency, money. Guide case B8.
    ("lost_phone_new_number", "impersonation", Severity.MAJOR, 0.7,
     r"\b(lost my phone|new number|this is my new)\b.{0,80}\b(send|transfer|urgent|money|rs\.?|₹)\b"
     r"|(?:फ़ोन खो गया|फोन खो गया|नया नंबर).{0,80}(?:पैसे|भेज|रुपये|तुरंत)"),

    # --- reward / job / loan ---
    ("prize_lottery", "reward", Severity.MAJOR, 0.7,
     r"\b(you(?:'ve| have)? won|winner|lottery|lucky draw|prize|jackpot|cash reward|cashback)\b"
     r"|\b(jeet\w+|inaam)\b.{0,30}\b(lakh|crore|rupaye|prize)\b"
     r"|(?:इनाम|पुरस्कार|लॉटरी|लकी ?ड्रॉ|जैकपॉट|कैशबैक|बधाई हो).{0,40}(?:जीत|मिला|चुना|पाने)"
     r"|(?:जीत गए|जीता है|चुना गया है)"),
    ("job_no_interview", "job", Severity.MAJOR, 0.6,
     r"\b(work from home|part[\s-]?time job|daily (?:income|earning)|no interview|earn\s*(?:₹|rs\.?|inr)?\s*[\d,]+\s*(?:per|/)\s*(?:day|hour))\b"
     r"|\b(ghar baithe|daily\s*\d+\s*rupaye)\b"
     r"|(?:घर बैठे|पार्ट ?टाइम ?नौकरी|प्रतिदिन ?कमाएँ|प्रतिदिन ?कमाएं).{0,40}(?:कमाएँ|कमाएं|कमाई|भुगतान|आय)"
     r"|(?:घर बैठे कमाएँ|घर बैठे कमाएं)"),
    ("task_based_earning", "job", Severity.MAJOR, 0.65,
     r"\b(like (?:and|&) subscribe|complete (?:the )?task|rate (?:the )?(?:product|hotel)|telegram)\b.{0,40}\b(earn|paid|income|commission)\b"
     r"|(?:वीडियो ?लाइक|टास्क ?पूरा|रेटिंग ?दें).{0,40}(?:कमाएँ|कमाएं|भुगतान|पैसे|कमीशन)"),
    ("job_offer_with_deposit", "job", Severity.CRITICAL, 0.75,
     r"\b(selected|shortlisted|offer letter)\b.{0,60}\b(deposit|registration fee|security amount|pay)\b"
     r"|(?:चयन हुआ|चुना गया|नौकरी के लिए).{0,60}(?:जमा|शुल्क|राशि भेज)"),
    ("instant_loan", "loan", Severity.MINOR, 0.45,
     r"\b(instant|pre[\s-]?approved|no documents?|without cibil)\b.{0,30}\b(loan|credit|cash)\b"
     r"|(?:तुरंत ?लोन|बिना ?गारंटी|बिना ?दस्तावेज़|बिना ?दस्तावेज|केवल ?आधार).{0,40}(?:लोन|ऋण|क्रेडिट)"
     r"|(?:लोन|ऋण).{0,30}(?:बिना ?गारंटी|बिना ?दस्तावेज़|केवल ?आधार से)"),
    ("guaranteed_return", "loan", Severity.MAJOR, 0.7,
     r"\bguaranteed\b.{0,25}\b(return|profit|income)\b"
     r"|\b\d{1,3}\s?%\s*(guaranteed|monthly|assured|per month)\b"
     r"|(?:गारंटीड|निश्चित).{0,25}(?:रिटर्न|मुनाफ़ा|मुनाफा|आय)"),

    # --- utility / delivery pretexts ---
    ("service_disconnection", "urgency", Severity.MAJOR, 0.6,
     r"\b(electricity|power|gas|connection)\b.{0,40}\b(disconnect\w*|cut off|kat jayega)\b"
     r"|(?:बिजली|गैस|कनेक्शन).{0,40}(?:कट ?जाएगा|काट ?दिया|बंद ?कर)"),
    ("parcel_customs_hold", "payment", Severity.MAJOR, 0.6,
     r"\b(parcel|package|shipment)\b.{0,40}\b(customs|held|stuck|detained)\b.{0,40}\b(fee|charge|pay|duty)\b"
     r"|(?:पार्सल|पैकेज).{0,40}(?:कस्टम|रुका).{0,40}(?:शुल्क|भुगतान|फ़ीस)"),
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
