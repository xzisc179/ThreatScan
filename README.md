# ThreatScan

> A real-time phishing URL threat analyzer that combines blacklist matching with rule-based URL feature scoring to identify potentially malicious and suspicious links.

## Overview

ThreatScan is a lightweight web-based URL threat analysis system built with **Python and Flask**.

The application analyzes a submitted URL using multiple security-oriented signals, including URL structure, domain characteristics, suspicious keywords, entropy, subdomain depth, URL encoding, redirect patterns, and HTTPS usage.

It combines these signals with a blacklist engine to produce:

- **Risk score**
- **Threat verdict**
- **Confidence level**
- **Detection reasons**
- **Extracted URL features**

ThreatScan also supports **batch analysis of up to 20 URLs** through a REST API.

## Key Features

- 🔎 **Real-time URL Analysis**
  - Analyze individual URLs through the web interface.
  - Generate a risk score and threat verdict.

- 🛡️ **Blacklist Detection**
  - Checks domains against a predefined malicious-domain blacklist.
  - Immediately flags known blacklisted domains.

- 🧩 **URL Feature Extraction**
  - URL length
  - Domain length
  - Special-character counts
  - IP-address detection
  - HTTPS detection
  - Subdomain depth
  - Suspicious keyword frequency
  - Domain entropy
  - Suspicious TLD detection
  - Digit ratio
  - Redirect parameters
  - URL encoding

- ⚙️ **Rule-Based Risk Scoring**
  - Applies weighted security heuristics to extracted URL features.
  - Produces a normalized risk score from 0 to 1.

- 📊 **Explainable Results**
  - Displays the signals that contributed to the detected risk level.
  - Shows selected extracted URL features.

- 📦 **Batch URL Analysis**
  - Analyze multiple URLs through the `/api/batch` endpoint.
  - Supports up to 20 URLs per request.

- 🌐 **Web Interface**
  - Flask backend
  - Responsive HTML/CSS/JavaScript frontend
  - Interactive risk visualization and result panels

## How It Works

ThreatScan follows a two-stage detection process:

```text
URL Input
   │
   ▼
URL Parsing & Feature Extraction
   │
   ├── Domain characteristics
   ├── URL structure
   ├── Suspicious keywords
   ├── Entropy
   ├── TLD analysis
   ├── Redirect patterns
   └── Encoding / HTTPS signals
   │
   ▼
Blacklist Check
   │
   ├── Known malicious domain → MALICIOUS
   │
   └── Otherwise
          │
          ▼
   Rule-Based Risk Scoring
          │
          ▼
   Risk Score + Verdict + Reasons
```

## Detection Signals

The rule-based scorer considers signals such as:

| Signal | Example Indicator |
|---|---|
| IP Address | URL uses an IP instead of a domain |
| HTTPS | Missing HTTPS connection |
| URL Length | Unusually long URLs |
| Subdomains | Excessive subdomain depth |
| Hyphens | Multiple hyphens in a domain |
| Keywords | `login`, `verify`, `account`, `password` |
| Domain Entropy | High randomness in domain names |
| Digit Ratio | High proportion of digits in domain |
| Suspicious TLD | `.tk`, `.ml`, `.xyz`, `.top`, etc. |
| Redirect Parameters | `redirect=`, `url=`, `link=` |
| URL Encoding | Encoded characters such as `%20` |
| Query Parameters | Large number of query parameters |

## Verdict Levels

| Risk Score | Verdict |
|---:|---|
| 0–34% | SAFE |
| 35–64% | POTENTIALLY SUSPICIOUS |
| 65–100% | SUSPICIOUS |

Known domains present in the blacklist are directly classified as **MALICIOUS**.

## Tech Stack

**Backend**
- Python
- Flask
- Flask-CORS

**Frontend**
- HTML5
- CSS3
- JavaScript

**Security / Analysis**
- URL parsing
- Regular expressions
- Shannon entropy
- Rule-based risk scoring
- Blacklist matching

## Project Structure

```text
ThreatScan/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
└── templates/
    └── index.html
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/xzisc179/ThreatScan.git
cd ThreatScan
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

The Flask server runs on:

```text
http://localhost:5000
```

Open the URL in a web browser to access the ThreatScan interface.

## API Endpoints

### Analyze a Single URL

```http
POST /api/check
```

Request:

```json
{
  "url": "https://example.com"
}
```

The API returns the detected verdict, risk score, confidence level, detection method, reasons, extracted features, and timestamp.

### Analyze Multiple URLs

```http
POST /api/batch
```

Request:

```json
{
  "urls": [
    "https://example.com",
    "http://suspicious-domain.tk"
  ]
}
```

The endpoint analyzes up to 20 URLs per request.

## Example URLs

### Lower-risk examples

```text
https://github.com
https://google.com
```

### Suspicious examples

```text
http://192.168.1.1/login?redirect=http://evil.com
http://secure-paypal-login.verify-account.tk/signin
```

> These examples are intended for local testing of the detection logic. Do not visit suspicious URLs in a normal browser.

## Limitations

ThreatScan is a **rule-based URL analysis system**, not a production-grade threat-intelligence platform or a trained machine-learning classifier.

Its results depend on predefined heuristics, thresholds, and blacklist entries. A legitimate URL may occasionally be flagged as suspicious, while sophisticated malicious URLs may evade detection.

The system should therefore be treated as an **analysis and educational security tool**, not as the sole security mechanism for real-world threat prevention.

## Future Improvements

- Train and evaluate a supervised phishing URL classification model.
- Expand and automate blacklist updates.
- Add external threat-intelligence feeds.
- Add model performance metrics such as precision, recall, F1-score, and ROC-AUC.
- Add persistent scan history and analytics.
- Deploy the application using a production WSGI server.
- Add automated unit and API tests.

## License

This project is intended for educational and portfolio purposes.