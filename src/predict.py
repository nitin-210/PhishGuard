"""
predict.py
----------
Loads the trained model and scores a NEW email, then explains WHY.

Output:
  - a phishing probability (0-100%)
  - a verdict (PHISHING / SUSPICIOUS / LIKELY SAFE)
  - the top reasons that pushed the score up (only when not clearly safe)

How the reasons work:
  For logistic regression, each feature contributes
      contribution = weight * scaled_feature_value
  A large positive contribution means that clue pushed the email toward
  "phishing". We list the biggest positive contributors in plain English.

Run a built-in demo:   python src/predict.py
Score your own email:  import and call score_email({...}) from your code.
"""

import os
import sys
import numpy as np
import joblib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import featurize_email, FEATURE_NAMES, FEATURE_EXPLANATIONS
from rules import critical_rule_hits

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(HERE, "models", "phishguard_model.joblib")

# Thresholds for turning a probability into a verdict.
PHISH_THRESHOLD = 0.60
SUSPICIOUS_THRESHOLD = 0.35


def load_model(path=MODEL_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model not found at {path}. Run 'python src/train.py' first.")
    return joblib.load(path)


def score_email(email, bundle=None):
    """Return a dict: {score, model_prob, verdict, reasons[], rule_hits[], details}."""
    if bundle is None:
        bundle = load_model()
    model = bundle["model"]
    names = bundle["feature_names"]

    vec, details = featurize_email(email)
    x = np.array(vec, dtype=float).reshape(1, -1)
    prob = float(model.predict_proba(x)[0, 1])

    # Per-feature contribution toward the phishing class.
    scaler = model.named_steps["scaler"]
    clf = model.named_steps["clf"]
    x_scaled = scaler.transform(x)[0]
    contributions = clf.coef_[0] * x_scaled  # weight * scaled value

    reasons = []
    order = np.argsort(contributions)[::-1]
    for i in order:
        # Only mention clues that (a) push toward phishing and (b) are present.
        if contributions[i] > 0.05 and details[names[i]] not in (0, 0.0):
            reasons.append(FEATURE_EXPLANATIONS.get(names[i], names[i]))
        if len(reasons) >= 5:
            break

    # ---- Rule-based safety net (can only RAISE suspicion, never lower it) ----
    rule_hits = critical_rule_hits(details)

    # Decide the verdict from the model score first...
    if prob >= PHISH_THRESHOLD:
        verdict = "PHISHING"
    elif prob >= SUSPICIOUS_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"

    # ...then let any critical rule override a too-low verdict.
    score = prob
    if rule_hits:
        verdict = "PHISHING"
        score = max(prob, 0.9)
        # Put the strong rule reasons first so the explanation leads with them.
        reasons = rule_hits + [r for r in reasons if r not in rule_hits]

    # If the email is judged safe, don't list weak phishing "reasons" -- they
    # confuse users (a SAFE verdict shouldn't come with a list of red flags).
    if verdict == "LIKELY SAFE":
        reasons = []

    return {"score": score, "model_prob": prob, "verdict": verdict,
            "reasons": reasons, "rule_hits": rule_hits, "details": details}


def _print_result(email, result):
    print("-" * 64)
    print("From   :", email.get("sender", ""))
    print("Subject:", email.get("subject", ""))
    print(f"\nVerdict: {result['verdict']}   ({result['score']*100:.1f}% phishing risk)")
    if result["reasons"]:
        print("Why:")
        for r in result["reasons"]:
            print("   -", r)
    else:
        print("Why: no strong phishing signals found.")
    print("-" * 64)


def _demo():
    bundle = load_model()
    phishing = {
        "sender": "PayPal Support <security@paypa1-security.com>",
        "subject": "[Action Required] Your PayPal account has been limited",
        "body": ("Dear Customer,\n\nUnusual sign-in activity detected. You must "
                 "verify your account immediately or it will be suspended. "
                 "Confirm your login and password here: http://192.168.10.5/login\n\n"
                 "PayPal Security Team"),
    }
    legit = {
        "sender": "GitHub <notifications@github.com>",
        "subject": "New comment on your pull request",
        "body": ("Hi Nitin,\n\nSomeone commented on your pull request. "
                 "You can view it here: https://github.com/your/repo/pull/12\n\n"
                 "Manage notifications in settings."),
    }
    for e in (phishing, legit):
        _print_result(e, score_email(e, bundle))


if __name__ == "__main__":
    _demo()
