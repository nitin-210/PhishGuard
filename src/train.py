"""
train.py
--------
Trains the phishing classifier and saves it to models/phishguard_model.joblib.

Pipeline:
  1. Load data/sample_emails.csv
  2. Convert every email into a feature vector (features.py)
  3. Split into train/test so we can measure honest performance
  4. Train a Logistic Regression (simple, fast, and EXPLAINABLE)
  5. Print accuracy, precision, recall, F1, and a confusion matrix
  6. Save the trained model + the feature names for later use

Why Logistic Regression?
  It gives each feature a weight (coefficient). That lets predict.py say
  *why* an email was flagged -- great for a portfolio demo and your report.

Run:  python src/train.py
"""

import os
import sys
import csv

import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, precision_score, recall_score, f1_score)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import featurize_email, FEATURE_NAMES

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(HERE, "data", "sample_emails.csv")
MODEL_OUT = os.path.join(HERE, "models", "phishguard_model.joblib")


def load_xy(path):
    X, y = [], []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            vec, _ = featurize_email(row)
            X.append(vec)
            y.append(int(row["label"]))
    return np.array(X, dtype=float), np.array(y, dtype=int)


def main():
    print("Loading data from", DATA)
    X, y = load_xy(DATA)
    print(f"  {len(y)} emails | {int(y.sum())} phishing | {int((1 - y).sum())} legit")

    # Hold out 25% of the data to test on -- the model never sees it in training.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    # Scale features, then fit logistic regression. Pipeline keeps them together.
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])
    model.fit(X_train, y_train)

    # ---- Evaluate on the held-out test set ----
    y_pred = model.predict(X_test)
    print("\n=== Test-set performance ===")
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
    print(f"Precision: {precision_score(y_test, y_pred):.3f}  (of mails we flagged, how many were truly phishing)")
    print(f"Recall   : {recall_score(y_test, y_pred):.3f}  (of real phishing, how many we caught)")
    print(f"F1 score : {f1_score(y_test, y_pred):.3f}")
    print("\nConfusion matrix [rows=true, cols=predicted]:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"               pred legit  pred phish")
    print(f"  true legit      {cm[0,0]:>4}        {cm[0,1]:>4}")
    print(f"  true phish      {cm[1,0]:>4}        {cm[1,1]:>4}")
    print("\nFull report:\n", classification_report(y_test, y_pred,
          target_names=["legit", "phishing"]))

    # ---- 5-fold cross-validation for a more stable estimate ----
    cv = cross_val_score(model, X, y, cv=5, scoring="f1")
    print(f"5-fold CV F1: {cv.mean():.3f} (+/- {cv.std():.3f})")

    # ---- Which features matter most? (logistic regression weights) ----
    clf = model.named_steps["clf"]
    coefs = clf.coef_[0]
    order = np.argsort(np.abs(coefs))[::-1]
    print("\nTop signals the model learned (high = points to phishing):")
    for i in order[:8]:
        print(f"  {FEATURE_NAMES[i]:34} weight={coefs[i]:+.2f}")

    # ---- Save everything we need for prediction ----
    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, MODEL_OUT)
    print(f"\nSaved model to {MODEL_OUT}")


if __name__ == "__main__":
    main()
