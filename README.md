# 🛡️ ThreatScan — URL Threat Analyzer

Detect suspicious/malicious URLs using **ML heuristics** + **blacklist matching**.

## Project Structure

```
url-checker/
├── app.py              ← Flask backend (ML + blacklist engine)
├── requirements.txt    ← Python dependencies
├── templates/
│   └── index.html      ← Frontend UI
└── README.md
```

## ⚡ Quick Setup (VSCode)

### 1. Install dependencies
```bash
cd url-checker
pip install -r requirements.txt
```

### 2. Run the backend
```bash
python app.py
```
Server starts at → `http://localhost:5000`

### 3. Open the UI
Visit `http://localhost:5000` in your browser.

---

## 🔍 How Detection Works

### Method 1 — Blacklist
Hard-coded list of known malicious domains. Instant match → verdict: **MALICIOUS**.

### Method 2 — ML Heuristics (Rule-Based Classifier)
Extracts 18 features from the URL and scores each:

| Feature | What it detects |
|---|---|
| IP as hostname | Attackers avoid registering domains |
| `@` symbol | Credential misdirection trick |
| No HTTPS | Unencrypted / unverified site |
| Suspicious TLD | `.tk .ml .ga .cf .xyz .top` etc. |
| URL length | Long URLs hide malicious paths |
| Subdomain depth | `login.bank.evil.com` pattern |
| Hyphens count | `secure-paypal-login.com` pattern |
| Keyword hits | login, verify, paypal, account, etc. |
| Domain entropy | High randomness = generated domain |
| Digit ratio | Random-looking domain names |
| Redirect params | `?url=`, `?redirect=` |
| URL encoding | Obfuscated characters |

### Verdict Scale
| Risk Score | Verdict |
|---|---|
| 0 – 34% | ✅ SAFE |
| 35 – 64% | ⚠️ POTENTIALLY SUSPICIOUS |
| 65 – 100% | 🚨 SUSPICIOUS / MALICIOUS |

---

## 🧪 Test URLs

**Safe:**
- `https://github.com`
- `https://google.com`

**Suspicious:**
- `http://192.168.1.1/login?redirect=http://evil.com`
- `http://secure-paypal-login.verify-account.tk/signin`

**Malicious (blacklisted):**
- `http://phishing-example.com`
- `https://bank-verify.ml/login`

---

## 🔌 API

### POST `/api/check`
```json
{ "url": "https://example.com" }
```
Returns: `{ verdict, risk_score, confidence, method, reasons, features }`

### POST `/api/batch`
```json
{ "urls": ["https://url1.com", "http://url2.tk"] }
```
Returns: `{ results: [...] }`
