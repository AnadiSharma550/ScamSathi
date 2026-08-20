"""Hindi and Hinglish detection.

These cases were written as a held-out check *after* the rules were tuned
against the DS-04 seed, and passed on first run. They are golden tests now,
so from here they are regression cover, not an unbiased measurement.

Nothing here is a reportable accuracy figure (R5). Real evaluation waits
for DS-02/DS-03 and the frozen test split.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def band(text: str) -> dict:
    r = client.post("/api/v1/scan/text", json={"text": text})
    assert r.status_code == 200, r.text
    return r.json()["assessment"]


DEVANAGARI_SCAMS = [
    "प्रिय ग्राहक, आपका डेबिट कार्ड निष्क्रिय हो गया है। पुनः सक्रिय करने के लिए कार्ड नंबर और सीवीवी भेजिए।",
    "आपने 5 लाख का पुरस्कार जीता है। राशि पाने के लिए 2,000 रुपये का प्रसंस्करण शुल्क जमा करें।",
    "बिजली कनेक्शन आज रात काट दिया जाएगा। तुरंत संपर्क करें।",
    "घर बैठे प्रतिदिन 2000 कमाएँ, केवल वीडियो लाइक करें और भुगतान पाएँ।",
    "गारंटीड 15% मासिक रिटर्न, आज ही निवेश करें।",
    "मैं साइबर सेल से बोल रहा हूँ, आपके नाम पर मामला दर्ज है।",
    "बैंक से बोल रहा हूँ, आपका डेबिट कार्ड ब्लॉक हो रहा है। कार्ड नंबर और CVV बताइए।",
    "मम्मी मेरा फ़ोन खो गया है, ये मेरा नया नंबर है। तुरंत पैसे भेजो।",
]

HINGLISH_SCAMS = [
    "Madam aapka parcel customs mein detained hai, clearance fee pay karein warna wapas chala jayega",
    "Bhai maine galti se aapke account mein 15,000 bhej diye, please wapas kar do",
    "Sir screen share kar lijiye QuickSupport se, main aapka problem solve kar dunga",
    "Aapka OTP mujhe bhejein warna transaction fail ho jayega",
    "Aapko paisa bhejne ke liye ye collect request accept karein aur PIN daalein",
]

LEGITIMATE = [
    "आपके खाते में 5,000 रुपये जमा हुए। शेष राशि देखने के लिए ऐप खोलें।",
    "आपका ऑर्डर कल तक पहुँच जाएगा। धन्यवाद।",
    "आपकी केवाईसी अपडेट है। किसी कार्रवाई की आवश्यकता नहीं है।",
    "इस वीकेंड 50% छूट, अभी खरीदें। रोकने के लिए STOP भेजें।",
    "Kal shaam ko milte hain, chai peene chalenge yaar",
    "Aapka OTP 778899 hai, kisi ke saath share na karein",
    "Ye number block kar dena, spam call aa rahe hain isse",
]


@pytest.mark.parametrize("text", DEVANAGARI_SCAMS)
def test_devanagari_scams_are_flagged(text):
    a = band(text)
    assert a["band"] in ("high", "caution"), a
    assert a["indicators"], "flagged with no evidence"


@pytest.mark.parametrize("text", HINGLISH_SCAMS)
def test_hinglish_scams_are_flagged(text):
    a = band(text)
    assert a["band"] in ("high", "caution"), a


@pytest.mark.parametrize("text", LEGITIMATE)
def test_legitimate_messages_are_not_flagged(text):
    """Includes the annotation guide's hard cases.

    An OTP *delivery* is not an OTP *request* (B1); a KYC advisory with no
    request is not a lure (B2); marketing urgency is not a scam (guide §3);
    asking someone to block a spam caller is not a threat.
    """
    a = band(text)
    assert a["band"] not in ("high", "caution"), a


def test_urgency_alone_cannot_raise_a_warning():
    """Legitimate marketing is urgent too, so urgency is a modifier.

    Unable-to-Assess is an acceptable outcome here and not a false alarm:
    the model is undecided and the rule evidence is below Caution, so
    "not enough to go on" is the honest answer.
    """
    a = band("Sale ends tonight, order immediately to avoid missing out on this offer")
    assert a["band"] not in ("high", "caution"), a


def test_model_abstains_on_devanagari():
    """`baseline-1` is Latin-script English only; on Hindi it guesses."""
    from app import classifier

    assert not classifier.in_distribution("आपका खाता निलंबित कर दिया जाएगा")
    assert classifier.in_distribution("Your account will be suspended")
    # Hinglish is Latin-script Hindi and stays in distribution.
    assert classifier.in_distribution("Aapka account block ho jayega turant")


def test_devanagari_relies_on_rules_not_the_model():
    """With the model abstaining, Devanagari detection must still work."""
    a = band(DEVANAGARI_SCAMS[0])
    assert a["band"] == "high"
    assert all(not i["code"].startswith("model.") for i in a["indicators"])
