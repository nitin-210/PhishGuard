"""
features.py
-----------
Turns one email into a list of NUMBERS the model can learn from.

The model cannot read English. So we hand it measurable clues that tend to be
different in phishing vs. legitimate mail -- things like "how many links?",
"does a link use a raw IP address?", "does the body contain urgency words?",
"does the sender's display name match its domain?".

Each clue is called a FEATURE. The order of features is fixed (FEATURE_NAMES)
so training and prediction always line up.

This file is pure Python (no heavy libraries) so it runs anywhere.
"""

import re

# ---------------------------------------------------------------------------
# Word lists -- the vocabulary that often shows up in phishing.
# ---------------------------------------------------------------------------
URGENCY_WORDS = ["urgent", "immediately", "now", "as soon as possible", "asap",
                 "within 24 hours", "act now", "final notice", "expires",
                 "before", "limited time"]
THREAT_WORDS = ["suspended", "locked", "blocked", "deleted", "unauthorized",
                "unusual", "failed", "fraud", "compromised", "disabled",
                "terminate", "closed"]
CREDENTIAL_WORDS = ["password", "login", "log in", "sign in", "verify",
                    "confirm your", "update your", "credentials", "ssn",
                    "card number", "cvv", "otp", "pin"]
MONEY_WORDS = ["prize", "winner", "won", "lottery", "refund", "payment",
               "invoice", "gift card", "bitcoin", "transfer", "$", "reward"]

FREE_EMAIL_PROVIDERS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                        "aol.com", "protonmail.com", "icloud.com"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "is.gd", "t.co", "ow.ly", "goo.gl",
                  "buff.ly", "rebrand.ly"]
SUSPICIOUS_TLDS = [".top", ".xyz", ".info", ".online", ".click", ".country",
                   ".gq", ".tk", ".ml", ".work", ".zip", ".support"]
KNOWN_BRANDS = ["paypal", "netflix", "amazon", "microsoft", "apple", "dhl",
                "fedex", "chase", "hdfc", "google", "linkedin", "instagram",
                "bank"]
# The real, official domains for the brands above (used to spot impostor links).
OFFICIAL_DOMAINS = {
    "paypal": "paypal.com", "netflix": "netflix.com", "amazon": "amazon.com",
    "microsoft": "microsoft.com", "apple": "apple.com", "dhl": "dhl.com",
    "fedex": "fedex.com", "chase": "chase.com", "hdfc": "hdfcbank.com",
    "google": "google.com", "linkedin": "linkedin.com", "instagram": "instagram.com",
}


def _impersonates_brand(host):
    """True if a link's host pretends to be a known brand but isn't its real domain.

    Catches two tricks:
      * digit/letter swaps:  paypa1-security.com, netf1ix-billing.net
      * brand name on a non-official domain:  microsoft-verify.info, chase-alert.com
    """
    h = host.lower()
    for brand, official in OFFICIAL_DOMAINS.items():
        on_official = (h == official or h.endswith("." + official))
        if on_official:
            continue
        # brand name appears on a domain that is NOT the official one
        if brand in h:
            return True
        # near-miss spelling (first 4 letters present) plus a digit/hyphen
        if brand[:4] in h and re.search(r"[\d-]", h):
            return True
    return False

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
IP_HOST_RE = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)
SENDER_RE = re.compile(r"(?:\"?(?P<name>[^\"<]*)\"?\s*)?<?(?P<email>[^<>\s]+@[^<>\s]+)>?")


# The fixed feature order. Keep training and prediction in sync via this list.
FEATURE_NAMES = [
    "num_links",
    "has_ip_url",
    "has_url_shortener",
    "has_at_symbol_in_url",
    "max_subdomains",
    "has_suspicious_tld",
    "longest_url_length",
    "num_urgency_words",
    "num_threat_words",
    "num_credential_words",
    "num_money_words",
    "has_generic_greeting",
    "num_exclamations",
    "body_length",
    "sender_is_free_email",
    "sender_name_brand_mismatch",
    "sender_domain_has_digit_or_hyphen",
    "lookalike_brand_domain",
    "link_impersonates_brand",
]


def _hosts(urls):
    hosts = []
    for u in urls:
        m = re.match(r"https?://([^/:@?]+)", u, re.IGNORECASE)
        if m:
            hosts.append(m.group(1).lower())
    return hosts


def _parse_sender(sender):
    """Return (display_name, email, domain) from a 'Name <a@b.com>' string."""
    if not sender:
        return "", "", ""
    m = SENDER_RE.search(sender)
    if not m:
        return "", "", ""
    name = (m.group("name") or "").strip()
    email = (m.group("email") or "").strip().lower()
    domain = email.split("@")[-1] if "@" in email else ""
    return name, email, domain


def _count(text, words):
    t = text.lower()
    return sum(t.count(w) for w in words)


def featurize_email(email):
    """
    email: dict with keys 'sender', 'subject', 'body'
    returns: (feature_vector: list[float], details: dict[name -> value])
    """
    sender = email.get("sender", "") or ""
    subject = email.get("subject", "") or ""
    body = email.get("body", "") or ""
    text = f"{subject}\n{body}"

    urls = URL_RE.findall(text)
    hosts = _hosts(urls)
    name, _email, domain = _parse_sender(sender)

    # ---- URL-based features ----
    num_links = len(urls)
    has_ip_url = 1 if any(IP_HOST_RE.match(u) for u in urls) else 0
    has_shortener = 1 if any(any(s in h for s in URL_SHORTENERS) for h in hosts) else 0
    # '@' inside a URL path is a classic redirect trick
    has_at_in_url = 1 if any("@" in u.split("//", 1)[-1] for u in urls) else 0
    max_subdomains = max([h.count(".") for h in hosts], default=0)
    has_susp_tld = 1 if any(h.endswith(t) for h in hosts for t in SUSPICIOUS_TLDS) else 0
    longest_url_len = max([len(u) for u in urls], default=0)

    # ---- Text-based features ----
    num_urgency = _count(text, URGENCY_WORDS)
    num_threat = _count(text, THREAT_WORDS)
    num_cred = _count(text, CREDENTIAL_WORDS)
    num_money = _count(text, MONEY_WORDS)
    generic = 1 if re.search(r"\b(dear (customer|user|member|account holder)|valued customer)\b",
                             text, re.IGNORECASE) else 0
    num_excl = text.count("!")
    body_len = len(body)

    # ---- Sender-based features ----
    free_email = 1 if domain in FREE_EMAIL_PROVIDERS else 0
    # Display name mentions a brand, but the domain is NOT that brand's domain
    name_l = name.lower()
    mismatch = 0
    for brand in KNOWN_BRANDS:
        if brand in name_l and brand not in domain:
            mismatch = 1
            break
    domain_digit_hyphen = 1 if re.search(r"[\d-]", domain.split(".")[0]) else 0
    # Look-alike: a brand name appears in the domain but with a digit/hyphen near it
    lookalike = 0
    for brand in KNOWN_BRANDS:
        if brand[:4] in domain and (re.search(r"[\d-]", domain) and brand not in domain):
            lookalike = 1
            break

    # ---- Link-based brand impersonation (the body links, not the sender) ----
    link_impersonation = 1 if any(_impersonates_brand(h) for h in hosts) else 0

    details = {
        "num_links": num_links,
        "has_ip_url": has_ip_url,
        "has_url_shortener": has_shortener,
        "has_at_symbol_in_url": has_at_in_url,
        "max_subdomains": max_subdomains,
        "has_suspicious_tld": has_susp_tld,
        "longest_url_length": longest_url_len,
        "num_urgency_words": num_urgency,
        "num_threat_words": num_threat,
        "num_credential_words": num_cred,
        "num_money_words": num_money,
        "has_generic_greeting": generic,
        "num_exclamations": num_excl,
        "body_length": body_len,
        "sender_is_free_email": free_email,
        "sender_name_brand_mismatch": mismatch,
        "sender_domain_has_digit_or_hyphen": domain_digit_hyphen,
        "lookalike_brand_domain": lookalike,
        "link_impersonates_brand": link_impersonation,
    }
    vector = [float(details[name]) for name in FEATURE_NAMES]
    return vector, details


# Human-friendly explanations used by predict.py when listing reasons.
FEATURE_EXPLANATIONS = {
    "num_links": "the email contains links",
    "has_ip_url": "a link points to a raw IP address instead of a domain",
    "has_url_shortener": "a link uses a URL shortener that hides its destination",
    "has_at_symbol_in_url": "a link uses an '@' redirect trick",
    "max_subdomains": "a link has many subdomains (often used to look legit)",
    "has_suspicious_tld": "a link uses a suspicious top-level domain (.top, .xyz, ...)",
    "longest_url_length": "an unusually long link",
    "num_urgency_words": "urgent, pressuring language",
    "num_threat_words": "threatening language about your account",
    "num_credential_words": "requests for login / password / verification",
    "num_money_words": "money, prize, or payment bait",
    "has_generic_greeting": "a generic greeting like 'Dear Customer'",
    "num_exclamations": "lots of exclamation marks",
    "body_length": "body length",
    "sender_is_free_email": "sender uses a free email provider",
    "sender_name_brand_mismatch": "the display name claims a brand the domain does not match",
    "sender_domain_has_digit_or_hyphen": "the sender domain contains digits or hyphens",
    "lookalike_brand_domain": "the sender domain looks like a brand but is misspelled",
    "link_impersonates_brand": "a link points to a domain impersonating a known brand (e.g. paypa1-security.com)",
}
