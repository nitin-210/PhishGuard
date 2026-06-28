"""
make_dataset.py
---------------
Generates a labelled starter dataset of phishing (1) and legitimate (0) emails
and writes it to data/sample_emails.csv.

WHY THIS EXISTS:
We need data to train the model. Downloading real corpora (PhishTank, the Nazario
phishing corpus, Kaggle sets, Enron for legit mail) requires accounts/large files,
so this script builds a small, realistic, *reproducible* dataset to get the whole
pipeline working end to end. Once everything runs, SWAP THIS OUT for real data and
retrain -- the rest of the code does not change.

Run:  python src/make_dataset.py
"""

import csv
import os
import random

random.seed(42)  # reproducible -> you get the same dataset every run

# ---------------------------------------------------------------------------
# Building blocks used to assemble varied, realistic emails.
# ---------------------------------------------------------------------------

BRANDS = ["PayPal", "Netflix", "Amazon", "Microsoft", "Apple", "DHL",
          "FedEx", "Chase", "HDFC Bank", "Google", "LinkedIn", "Instagram"]

# Look-alike / malicious sender domains (digit swaps, hyphens, wrong TLDs)
BAD_DOMAINS = [
    "paypa1-security.com", "netf1ix-billing.net", "amaz0n-support.co",
    "microsoft-verify.info", "app1e-id.com", "dhl-tracking-update.top",
    "secure-chase-alert.com", "hdfc-bank-verify.xyz", "g00gle-team.com",
    "account-linkedln.com", "instagram-help-center.online",
]

SHORTENERS = ["bit.ly", "tinyurl.com", "is.gd", "t.co", "ow.ly"]

# Real, legitimate domains
GOOD_DOMAINS = {
    "PayPal": "paypal.com", "Netflix": "netflix.com", "Amazon": "amazon.com",
    "Microsoft": "microsoft.com", "Apple": "apple.com", "DHL": "dhl.com",
    "FedEx": "fedex.com", "Chase": "chase.com", "HDFC Bank": "hdfcbank.com",
    "Google": "google.com", "LinkedIn": "linkedin.com", "Instagram": "instagram.com",
}

COLLEAGUES = [
    ("Priya Sharma", "priya.sharma@company.com"),
    ("David Lee", "david.lee@company.com"),
    ("Aarav Mehta", "aarav.mehta@company.com"),
    ("Sara Khan", "sara.khan@company.com"),
]

URGENCY = ["immediately", "within 24 hours", "right now", "urgent action required",
           "before your account is closed", "as soon as possible"]
THREAT = ["your account has been suspended", "unusual sign-in activity detected",
          "your account will be permanently deleted", "your payment has failed",
          "your card has been blocked", "we detected unauthorized access"]


def rand_ip():
    return f"http://{random.randint(11,250)}.{random.randint(0,255)}." \
           f"{random.randint(0,255)}.{random.randint(1,254)}/login"


def _bad_link(brand, domain):
    """Pick one of several malicious-looking link styles."""
    style = random.random()
    if style < 0.34:
        return rand_ip()                                   # raw IP address
    elif style < 0.67:
        return f"http://{random.choice(SHORTENERS)}/{random.choice(['x9f2','win','verify','a12'])}"
    else:
        return f"http://{domain}/{brand.lower()}/verify?id={random.randint(1000,9999)}@secure"  # @ trick


def phishing_email():
    brand = random.choice(BRANDS)
    domain = random.choice(BAD_DOMAINS)
    # Sender display name impersonates a real brand, but the domain is fake
    sender = f"{brand} Support <{random.choice(['security','no-reply','account','alert'])}@{domain}>"
    link = _bad_link(brand, domain)
    threat = random.choice(THREAT)
    urgency = random.choice(URGENCY)

    # IMPORTANT: vary the STYLE so the model can't just key on length/greetings.
    # Real phishing ranges from wordy to one-line. We mix three styles.
    style = random.random()
    if style < 0.45:
        # (a) Wordy, classic style with a generic greeting
        subject = random.choice([
            f"[Action Required] {brand} account verification",
            f"Your {brand} account has been limited",
            f"Security alert: {threat}",
            f"Final notice regarding your {brand} account",
        ])
        body = (
            f"Dear Customer,\n\n"
            f"{threat.capitalize()}. You must verify your {brand} account {urgency}, "
            f"or it will be locked.\n\n"
            f"Please confirm your login and password here: {link}\n\n"
            f"Failure to act {urgency} will result in permanent suspension.\n\n"
            f"{brand} Security Team"
        )
    elif style < 0.8:
        # (b) Terse: short, no greeting, just the bait + link (this is the kind
        #     that previously slipped through)
        subject = random.choice(["Verify your account", "Account alert",
                                 "Action needed", f"{brand} security notice"])
        body = random.choice([
            f"{threat.capitalize()}. Confirm your login here: {link}",
            f"Verify your account {urgency}: {link}",
            f"Update your password to avoid suspension: {link}",
        ])
    else:
        # (c) Payment / money bait, also short
        subject = random.choice([f"{brand}: payment problem", "Refund pending",
                                 "Your invoice is overdue"])
        body = random.choice([
            f"Your payment failed. Update your card {urgency}: {link}",
            f"You have a pending refund. Claim it here: {link}",
            f"Invoice unpaid. Settle now to avoid a fee: {link}",
        ])
    return sender, subject, body, 1


def legit_email():
    kind = random.random()
    if kind < 0.18:
        # Short, casual colleague note (no links) -- proves "short" != "phishing"
        name, addr = random.choice(COLLEAGUES)
        sender = f"{name} <{addr}>"
        subject = random.choice(["Re: quick question", "thanks!", "see you at 3",
                                 "done"])
        body = random.choice([
            f"Sounds good, see you then.\n{name.split()[0]}",
            "Thanks, got it. Talk later.",
            "Approved on my end. Go ahead.",
            "Yes that works for me.",
        ])
        return sender, subject, body, 0
    if kind < 0.45:
        # Transactional message from a real brand
        brand = random.choice(BRANDS)
        domain = GOOD_DOMAINS[brand]
        sender = f"{brand} <{random.choice(['no-reply','info','receipts'])}@{domain}>"
        subject = random.choice([
            f"Your {brand} receipt", f"Your monthly {brand} statement is ready",
            f"Order confirmation from {brand}", f"Welcome to {brand}",
        ])
        body = (
            f"Hi Nitin,\n\n"
            f"Thanks for using {brand}. Here is a summary of your recent activity. "
            f"You can review the details in your account dashboard at "
            f"https://www.{domain}/account.\n\n"
            f"No action is needed. If you have questions, visit our help center.\n\n"
            f"Best regards,\nThe {brand} Team"
        )
        return sender, subject, body, 0
    elif kind < 0.7:
        # Internal colleague email
        name, addr = random.choice(COLLEAGUES)
        sender = f"{name} <{addr}>"
        subject = random.choice([
            "Notes from today's meeting", "Draft for review",
            "Lunch tomorrow?", "Project update - week 3",
        ])
        body = (
            f"Hi Nitin,\n\n"
            f"Just following up on our discussion. I've attached the latest draft. "
            f"Let me know your thoughts when you get a chance -- no rush.\n\n"
            f"You can also see the doc here: https://docs.company.com/project/draft\n\n"
            f"Thanks,\n{name.split()[0]}"
        )
        return sender, subject, body, 0
    else:
        # Service notification (GitHub / newsletter)
        sender = random.choice([
            "GitHub <notifications@github.com>",
            "Medium Daily Digest <noreply@medium.com>",
            "Coursera <no-reply@coursera.org>",
        ])
        subject = random.choice([
            "New comment on your pull request",
            "Your weekly reading list", "A new course you might like",
        ])
        body = (
            "Hello,\n\n"
            "Here's an update based on your activity. You can manage your "
            "notification preferences anytime in settings.\n\n"
            "View it here: https://www.example-service.com/notifications\n\n"
            "Thanks for being with us."
        )
        return sender, subject, body, 0


def build(n_each=120):
    rows = []
    for _ in range(n_each):
        rows.append(phishing_email())
        rows.append(legit_email())
    random.shuffle(rows)
    return rows


def main():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(here, "data", "sample_emails.csv")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    rows = build(120)  # 120 phishing + 120 legit = 240 emails
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["sender", "subject", "body", "label"])
        w.writerows(rows)
    n_phish = sum(r[3] for r in rows)
    print(f"Wrote {len(rows)} emails to {out}")
    print(f"  phishing: {n_phish}  |  legitimate: {len(rows) - n_phish}")


if __name__ == "__main__":
    main()
