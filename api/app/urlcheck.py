"""Structural URL analysis. stdlib `urllib.parse` only.

R4: this module never opens a network connection. Importing an HTTP client
here is a bug, not a feature.
"""

import re
from urllib.parse import urlsplit

from app.contracts import Indicator, Severity

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "gq", "cf", "tk", "ml",
    "work", "rest", "country", "kim", "loan",
}
# Brands impersonated in Indian scam messages.
BRANDS = {
    "sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "gpay",
    "amazon", "flipkart", "irctc", "epfo", "uidai", "aadhaar", "incometax",
    "netflix", "whatsapp", "instagram", "facebook", "google", "apple",
}
# ponytail: hand-rolled 2-label suffix list, no PSL dependency.
# Ceiling: misses rare multi-part suffixes. Swap in `publicsuffix2` if
# false positives on registrable-domain checks show up in error analysis.
MULTI_SUFFIXES = {
    "co.in", "co.uk", "org.in", "net.in", "gov.in", "ac.in", "res.in",
    "com.au", "co.jp", "com.br", "co.za",
}

# ponytail: tiny allowlist so real brand domains don't trip the
# impersonation check. Ceiling: hand-maintained. Move to a data file when it
# outgrows a screen, or drop it once a brand->domain map exists.
KNOWN_DOMAINS = {
    "onlinesbi.com", "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotak.com", "paytm.com", "phonepe.com",
    "amazon.in", "amazon.com", "flipkart.com", "irctc.co.in", "epfindia.gov.in",
    "uidai.gov.in", "incometax.gov.in", "netflix.com", "whatsapp.com",
    "instagram.com", "facebook.com", "google.com", "apple.com",
}

IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def registrable(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _flag(code: str, severity: Severity, weight: float) -> Indicator:
    return Indicator(code=f"url.{code}", severity=severity, source="url", weight=weight)


def analyse(urls: list[str]) -> tuple[float, list[Indicator]]:
    """Returns (score 0..1, indicators). Worst single URL drives the score."""
    if not urls:
        return 0.0, []

    best_score, best_flags = 0.0, []
    for url in urls:
        score, flags = _one(url)
        if score > best_score:
            best_score, best_flags = score, flags
    return best_score, best_flags


def _one(url: str) -> tuple[float, list[Indicator]]:
    parts = urlsplit(url if "://" in url else f"http://{url}")
    host = (parts.hostname or "").lower()
    flags: list[Indicator] = []

    if parts.scheme not in ("http", "https"):
        flags.append(_flag("bad_scheme", Severity.CRITICAL, 0.9))
    if not host:
        return 0.0, flags

    if IPV4.match(host):
        flags.append(_flag("ip_literal_host", Severity.MAJOR, 0.7))
    if host.startswith("xn--") or ".xn--" in host:
        flags.append(_flag("punycode_host", Severity.MAJOR, 0.6))
    if parts.username or parts.password:
        flags.append(_flag("credentials_in_url", Severity.CRITICAL, 0.8))
    if host in SHORTENERS or registrable(host) in SHORTENERS:
        flags.append(_flag("shortener", Severity.MINOR, 0.35))
    if host.count(".") >= 4:
        flags.append(_flag("deep_subdomain", Severity.MINOR, 0.3))
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        flags.append(_flag("suspicious_tld", Severity.MAJOR, 0.5))
    if parts.scheme == "http":
        flags.append(_flag("no_tls", Severity.MINOR, 0.2))

    # Brand named, but the registrable domain is not that brand's own --
    # the classic "sbi-verify.xyz" / "paytm.secure-login.com" shape.
    reg = registrable(host)
    if reg not in KNOWN_DOMAINS:
        label = reg.split(".")[0]
        haystack = f"{host}{parts.path}".lower()
        for brand in BRANDS:
            # Exact label match is the brand's own site; anything else
            # (sbi-verify, secure-sbi, sbi.evil.com) is impersonation shape.
            if brand in haystack and label != brand:
                flags.append(_flag("brand_outside_domain", Severity.CRITICAL, 0.75))
                break

    if len(parts.path) > 60:
        flags.append(_flag("long_path", Severity.INFO, 0.15))

    return min(sum(f.weight for f in flags), 1.0), flags
