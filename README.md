# ScamCheck AI — Production-Ready AI Scam Detection Platform

> **"Check Before You Click"** — An intelligent, beginner-friendly cybersecurity platform built to identify scam messages, phishing links, QR-code traps (quishing), and malicious files across English, Khmer (ភាសាខ្មែរ), and mixed Khmer-English scripts.

---

## 1. Project Overview

People frequently receive suspicious messages, links, files, and QR codes but cannot easily tell whether they are safe before clicking, opening, scanning, or sending money. **ScamCheck AI** bridges this gap by offering multi-modal threat analysis, transparent evidence-based risk scoring (0–100), simple non-jargon explanations, and actionable safety recommendations.

### Key Pillars
- **Multi-Modal Inspection**: Scans messages, raw URLs, physical QR codes (in quarantined memory), and uploaded files.
- **14-Class Threat Taxonomy**: Granular classification far beyond binary safe/scam flags.
- **Native Multilingual Detection**: Full support for English (`en`), Khmer (`km`), and mixed Khmer-English (`km-en`) communications.
- **Evidence-Weighted Risk Score (0–100)**: Transparent score calculation based on 5 weighted pillars.
- **Human-in-the-Loop Feedback**: Users validate detections to build a verified dataset for future model fine-tuning.
- **Admin Operations Hub**: Real-time telemetry, model benchmark metrics (Accuracy, Precision, Recall, F1), and verified dataset export.
- **Zero Blind Auto-Execution**: Files are analyzed via static inspection and QR codes are extracted in a sandbox without browser auto-navigation.

---

## 2. System Architecture

ScamCheck AI operates on a modern, decoupled microservice architecture:

```
┌────────────────────────────────────────────────────────────┐
│               Frontend: React + Vite + TypeScript          │
│        (Bilingual EN/KM UI, Glassmorphism, Tailwind/CSS)    │
└──────────────┬──────────────────────────────┬──────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────────┐ ┌───────────────────────────┐
│   Node.js / Express Backend   │ │   Python FastAPI AI Engine│
│   (Port 5000)                │ │   (Port 8000)             │
├──────────────────────────────┤ ├───────────────────────────┤
│ • JWT & API-Key Auth (SHA256)│ │ • Message Context Analyzer│
│ • Rate Limiting & Audit Logs │ │ • Unicode Language Detector│
│ • Prisma ORM & PostgreSQL 16 │ │ • Deep Technical URL Parser│
│ • Async Job Queuing (BullMQ) │ │ • OpenCV QR Code Decoder  │
│ • Community Scam Reports     │ │ • Static Binary / PE / PDF│
│ • Scan History Repository    │ │ • Model Benchmark & Eval  │
└──────────────────────────────┘ └───────────────────────────┘
```

---

## 3. Threat Classification Taxonomy

The platform classifies inputs into 14 distinct categories and never claims 100% certainty:

| Category | Description | Example Indicators |
| :--- | :--- | :--- |
| `SAFE` | Verified legitimate or benign content | Normal correspondence, known trusted domain |
| `PHISHING` | Credential or identity theft attempt | Urgent account lockout claims, fake login pages |
| `INVESTMENT_SCAM`| Unrealistic financial/crypto returns | "Guaranteed 1000% daily returns", Telegram pump groups |
| `JOB_SCAM` | Fake remote employment offers | "Earn $300/day liking videos", upfront registration fees |
| `ROMANCE_SCAM` | Relationship-building for financial exploitation | Quick professions of love, requests for emergency funds |
| `FAKE_SHOP` | Counterfeit or non-existent storefronts | Ridiculously low prices, payment via gift cards |
| `IMPERSONATION` | Spoofing trusted organizations or banks | ABA Bank, Wing, ACLEDA, PayPal, Telegram brand imitation |
| `PAYMENT_SCAM` | Fraudulent invoices or transfer requests | Fake payment receipts, QR code payment diversion |
| `PRIZE_SCAM` | Unsolicited lottery or giveaway claims | "Congratulations! You won $500", claim gift links |
| `MALWARE` | Malicious executables or weaponized files | Executable headers (`MZ`, `ELF`), PDF JavaScript streams |
| `ACCOUNT_TAKEOVER`| Attempts to hijack session or OTP | "Send back the 6-digit code you just received" |
| `SOCIAL_ENGINEERING`| Psychological manipulation or pressure | Fear, urgency, authority impersonation |
| `OTHER` | Miscellaneous suspicious patterns | Uncategorized suspicious activity |
| `UNKNOWN / NEEDS_REVIEW`| Insufficient evidence | Flagged for manual analyst verification |

---

## 4. Multilingual Analysis Engine

ScamCheck AI features specialized Unicode range analysis and bilingual tokenizers supporting:

1. **Pure English**: Standard international phishing, gift, and job scams.
2. **Pure Khmer (`km`)**: Native script analysis targeting common regional scams:
   - *"អ្នកបានឈ្នះរង្វាន់ចំនួន ៥០០ ដុល្លារ សូមផ្ញើព័ត៌មានផ្ទាល់ខ្លួនជាបន្ទាន់"*
   - Bank impersonation targeting ABA Bank, Wing Bank, and ACLEDA.
3. **Mixed Khmer-English (`km-en`)**: Modern Telegram and messaging syntax:
   - *"Congratulations អ្នកឈ្នះ $500 ចុច link នេះដើម្បី claim រង្វាន់"*

---

## 5. Transparent Risk Scoring Model (0–100)

ScamCheck AI derives its composite risk score using weighted evidence:

$$\text{Risk Score} = (0.25 \times \text{Msg}) + (0.30 \times \text{URL}) + (0.20 \times \text{Indicators}) + (0.15 \times \text{Reputation}) + (0.10 \times \text{Behavior})$$

*(Note: For text messages without embedded URLs, the scoring engine dynamically normalizes weights across the remaining dimensions so text-only scams are not artificially deflated).*

| Score Range | Risk Level | Plain-Language Meaning |
| :--- | :--- | :--- |
| **0 – 19** | `SAFE` | No suspicious indicators identified. Proceed with normal caution. |
| **20 – 39** | `LOW RISK` | Minor anomalies detected; safe under normal conditions. |
| **40 – 59** | `MEDIUM RISK` | Elevated risk. Multiple warning signs require caution. |
| **60 – 79** | `HIGH RISK` | Dangerous. Do not click links, send money, or share codes. |
| **80 – 100** | `CRITICAL RISK` | Severe threat. Immediate indicators of phishing or malware. |

---

## 6. Supported Analysis Modes

### 1. Message Scanner (`/api/analyze/message`)
Analyzes urgency, threats, OTP requests, fake authority, brand impersonation, and pressure to act immediately.

### 2. Technical URL Scanner (`/api/analyze/url`)
Performs static URL decomposition without relying solely on an LLM:
- Typosquatting detection using Levenshtein distance against top global and Cambodian brands.
- Raw IP address hostname identification (`http://192.168.1.1/...`).
- Compound ccTLD parsing (`.com.kh`, `.co.uk`).
- Suspicious TLD inspection (`.tk`, `.xyz`, `.top`, `.click`, `.buzz`).
- URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`).
- Executable or malicious extension paths (`.apk`, `.exe`, `.scr`, `.bat`).

### 3. QR Code Scanner (`/api/analyze/qr`)
- Uses OpenCV's `QRCodeDetector` to decode QR matrices from uploaded images.
- Extracts target data safely in quarantined memory.
- Feeds extracted URLs to the URL Scanner **without browser auto-navigation**.

### 4. Static File Scanner (`/api/analyze/file`)
- Magic byte inspection (`MZ` Windows PE, `\x7fELF` Linux, `%PDF-` documents, `PK\x03\x04` ZIP archives).
- Office VBA macro detection (`word/vbaProject.bin`).
- PDF active stream inspection (`/JavaScript`, `/Launch`, `/EmbeddedFiles`).
- Shannon entropy calculation to detect packed or encrypted payloads.
- Strictly enforces non-execution on the host server.

---

## 7. Quickstart Setup Guide

### Prerequisites
- **Node.js**: v18+ (tested on v20+)
- **Python**: v3.10+ (tested on Python 3.14)
- **npm** or **yarn**

### 1. Python FastAPI AI Engine
```bash
# In project root
python -m pip install fastapi uvicorn pydantic opencv-python numpy python-multipart qrcode pillow
python -m uvicorn ai_engine.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation: `http://127.0.0.1:8000/docs`

### 2. Node.js Express Backend
```bash
cd backend
npm install
npm run build
npm run dev
```
Backend runs on `http://localhost:5000/api/v1`

### 3. Frontend Web Application
```bash
# In project root
npm install
npm run dev
```
Frontend opens at `http://localhost:5174`

### 4. Single-Command Docker Deployment (Full Stack)
```bash
docker compose up -d
```
Spins up the Python AI Engine, Express API, ClamAV antivirus daemon, PostgreSQL, and Redis automatically.

### 5. Telegram Scam Scanner Bot
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
python integrations/telegram_bot.py
```

### 6. Browser Extension (Chrome, Edge, Brave)
1. Open `chrome://extensions` and enable **Developer mode**.
2. Click **Load unpacked** and select `browser_extension/`.

---

## 8. Verification & Automated Test Suites

ScamCheck AI includes comprehensive test suites across both frontend and backend layers:

```bash
# 1. Run Python AI Engine tests (16 tests)
python -m pytest ai_engine/tests/

# 2. Run Backend Production & Security Integration tests (313 tests in 27 files)
npm run backend:test

# 3. Verify Code Quality & Linting (0 warnings, 0 errors across 170 files)
npx oxlint

# 4. Verify Frontend Production Build & TypeScript Check
npx tsc --noEmit
npm run build
```

---

## 9. Production Docker Deployment

To launch the fully containerized stack (Frontend SPA via Nginx reverse proxy, Node.js API Gateway, Python AI Engine, Redis, and PostgreSQL/SQLite):

```bash
# 1. Copy production environment file and configure strong secrets
cp .env.example .env

# 2. Build and launch all microservices in background
docker compose up -d --build

# 3. View container health status
docker compose ps
```

- **Frontend Application**: `http://localhost` (Port 80)
- **API Documentation**: `http://localhost/api/docs` (Swagger UI via reverse proxy)
- **Health Probes**: `http://localhost/api/v1/health` (Backend & Database), `http://localhost:8000/health` (AI Engine)

---

## 10. Admin Operations & Continuous Improvement

Navigate to the **Admin Ops** modal from the header:
- **Telemetry Cards**: Total scans, scam detection count, high-risk URLs, and live false-positive rate.
- **Model Evaluation Matrix**: Precision, Recall, Accuracy, and F1 score against a verified balanced benchmark.
- **Verified Dataset Explorer**: View and verify submissions across English, Khmer, and Mixed scripts.
- **JSON Dataset Export**: Download clean datasets for future offline model fine-tuning.

---

## 11. Security & Responsible Disclosure

- **Never Executes Uploaded Files**: All file scanning is strictly static header and entropy analysis in unprivileged quarantine.
- **Quarantined QR Extraction**: Prevents "quishing" by isolating extracted links and treating unreadable/obscured barcodes with elevated caution.
- **Stateless HMAC Password Resets**: Cryptographically signed recovery tokens without persistent database exposure.
- **PII Scrubbing**: PII redactor automatically masks credit card numbers, passwords, OTPs, and SSNs before sending context to external LLM explainers.
- **Hashed Secrets & IP Anonymization**: API keys and client IP addresses are stored exclusively as salted SHA-256 digests.
- **Continuous Integration**: Automated GitHub Actions workflow (`.github/workflows/ci.yml`) enforces linting, type safety, and all 329 tests on every pull request.

