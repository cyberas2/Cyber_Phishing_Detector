# 🛡️ Cyber_Phishing_Detector

**Cyber_Phishing_Detector** is an original educational cybersecurity project for analyzing URLs for phishing-related indicators.

It is inspired by the general problem addressed by existing phishing-URL detection projects, including the public `vaibhavbichave/Phishing-URL-Detection` repository, but this implementation is written independently and does **not** copy its source code, UI, or model artifacts. The reference project uses URL feature extraction, machine-learning classifiers, a Flask web application, templates, and a phishing dataset. See the upstream reference: https://github.com/vaibhavbichave/Phishing-URL-Detection

## Features

- URL-only analysis; the detector does not visit the target site.
- Risk score from 0–100.
- Explainable indicators.
- IP-address hostname detection.
- URL-shortener detection.
- Suspicious TLD heuristic.
- Punycode detection.
- Authentication/redirect keyword analysis.
- Host/path brand-term analysis.
- URL complexity and entropy indicators.
- Flask web interface.
- JSON API endpoint: `POST /api/analyze`.
- Optional Random Forest training example.

## Architecture

```text
Browser / API Client
        |
        v
     Flask
        |
        v
 URL Normalization
        |
        v
 Feature Extraction
        |
        +------> Explainable Risk Heuristics
        |
        +------> Optional ML Model
        |
        v
 Verdict + Score + Reasons
```

## Quick Start

### 1. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## API

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://example.com/login\"}"
```

## ML Experiment

The included `train_model.py` creates a **synthetic demonstration dataset** and trains a Random Forest. The synthetic dataset is intentionally not presented as a real-world benchmark.

```bash
python train_model.py
```

For research or production, replace the demonstration data with a properly licensed, representative phishing/benign URL dataset and report train/test methodology, class balance, temporal split, false-positive rate, recall, precision, F1, and calibration.

## Security Design

The web application does not fetch the supplied URL. This avoids turning the detector into an SSRF-style URL fetcher and keeps the demo focused on lexical URL analysis.

Do not enter passwords, API keys, authentication tokens, internal URLs, or other confidential information.

## Limitations

A URL-string detector cannot prove that a site is safe or malicious. Modern phishing detection can require reputation, DNS/TLS signals, page content, redirects, hosting information, and continuously updated threat intelligence. This project intentionally avoids actively visiting submitted URLs.

## Roadmap

- [ ] Real-world dataset ingestion pipeline
- [ ] Model versioning
- [ ] Explainable feature contribution
- [ ] Calibration and confidence intervals
- [ ] Batch CSV analysis
- [ ] SQLite analysis history
- [ ] Docker deployment
- [ ] CI tests
- [ ] Optional threat-intelligence integrations using server-side secrets

## Ethics

Use only for defensive research, education, and systems you are authorized to analyze.
