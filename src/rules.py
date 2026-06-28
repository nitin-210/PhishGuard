"""
rules.py
--------
A small RULE-BASED safety net that runs alongside the AI model.

Why have rules at all if we have a model?
  Machine-learning models reflect their training data and can miss obvious cases
  (e.g. a one-line phishing email with a raw-IP link). Some signals are so
  strong that a human would flag them no matter what -- those deserve a hard
  rule. Real-world security products almost always combine ML + rules for
  exactly this reason. The rules act as a floor: they can RAISE suspicion, never
  lower it.

Each rule looks at the feature `details` dict produced by features.py and, if it
fires, returns a short human-readable reason.
"""

# Each entry: (rule_id, function(details) -> bool, human reason)
CRITICAL_RULES = [
    ("ip_link_credentials",
     lambda d: d["has_ip_url"] and d["num_credential_words"] >= 1,
     "a link uses a raw IP address AND the email asks you to log in / verify"),

    ("ip_link_brand_spoof",
     lambda d: d["has_ip_url"] and (d["sender_name_brand_mismatch"] or d["lookalike_brand_domain"]),
     "a raw-IP link combined with a sender pretending to be a known brand"),

    ("lookalike_credentials",
     lambda d: d["lookalike_brand_domain"] and d["num_credential_words"] >= 1,
     "a look-alike (misspelled-brand) domain that asks for your login details"),

    ("at_trick",
     lambda d: d["has_at_symbol_in_url"],
     "a link uses an '@' redirect trick to disguise its real destination"),

    ("shortener_credentials",
     lambda d: d["has_url_shortener"] and d["num_credential_words"] >= 1,
     "a hidden (shortened) link combined with a request for your login details"),

    ("link_impersonates_brand",
     lambda d: d.get("link_impersonates_brand", 0) == 1,
     "a link points to a domain impersonating a known brand (e.g. paypa1-security.com)"),
]


def critical_rule_hits(details):
    """Return the list of human-readable reasons for every critical rule that fires."""
    hits = []
    for _id, fn, reason in CRITICAL_RULES:
        try:
            if fn(details):
                hits.append(reason)
        except KeyError:
            pass  # ignore if a feature is missing
    return hits
