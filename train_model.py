"""
Optional ML training example.

This script trains a Random Forest on a small, synthetic demonstration
dataset generated from URL patterns. The resulting model is for learning
and experimentation only; use a validated, representative dataset before
making security decisions in production.
"""

from pathlib import Path
import csv
import random
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from detector import extract_features

OUT = Path("models/url_model.joblib")
DATA = Path("data/demo_urls.csv")

SAFE_DOMAINS = ["example.com", "python.org", "github.com", "wikipedia.org", "microsoft.com"]
PHISH_DOMAINS = ["secure-login-alert", "account-verify-now", "update-credential", "paypal-security-check"]

def build_demo_dataset(n=2500):
    random.seed(42)
    rows = []
    for _ in range(n // 2):
        d = random.choice(SAFE_DOMAINS)
        rows.append((f"https://www.{d}/docs/{random.randint(1,999)}", 0))
    for _ in range(n // 2):
        d = random.choice(PHISH_DOMAINS)
        tld = random.choice(["top", "xyz", "click", "work"])
        rows.append((f"http://{d}.{tld}/login/verify?session={random.randint(100000,999999)}", 1))
    random.shuffle(rows)
    return rows

def main():
    rows = build_demo_dataset()
    DATA.parent.mkdir(exist_ok=True)
    with DATA.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)

    X = [list(extract_features(url).values()) for url, _ in rows]
    y = [label for _, label in rows]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=250, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    print(classification_report(y_test, model.predict(X_test)))
    OUT.parent.mkdir(exist_ok=True)
    joblib.dump(model, OUT)
    print(f"Saved demo model to {OUT}")

if __name__ == "__main__":
    main()
