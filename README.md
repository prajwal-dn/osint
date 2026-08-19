<div align="center">

# ⚡ OSINTProbe — Live Intelligence Engine

> **⚠️ DISCLAIMER: This tool is built strictly for EDUCATIONAL & RESEARCH PURPOSES.** 
> While it contains a fully functional **Live Mode** that performs legitimate OSINT scraping (eCourts CNR Deep Scraping, Shodan IP mapping, Groq LLM Forensic Analysis), users are solely responsible for ensuring compliance with local laws and terms of service of any queried endpoints.

**A forensic-grade Open Source Intelligence platform for criminal profiling, identity resolution, and multi-source reconnaissance.**

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Vue 3](https://img.shields.io/badge/Frontend-Vue%203-42b883?style=flat-square&logo=vue.js)](https://vuejs.org/)
[![XGBoost](https://img.shields.io/badge/ML-XGBoost%20(FEBRL4)-FF6600?style=flat-square)](https://xgboost.readthedocs.io/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python)](https://www.python.org/)
[![DPDP Compliant](https://img.shields.io/badge/Compliance-DPDP%20Act%20§17(1)(c)-blue?style=flat-square)](https://www.meity.gov.in/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

<br/>

> **OSINTProbe** transforms raw OSINT signals into a structured forensic case-file — complete with a chronological investigation timeline, explainable ML identity scoring, an interactive evidence graph, a grounded AI copilot, and a one-click print-ready dossier.

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Forensic Feature Suite](#-forensic-feature-suite)
- [Intelligence Adapters](#-intelligence-adapters)
- [Machine Learning Engine](#-machine-learning-engine)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [API Reference](#-api-reference)
- [How to Run an Investigation](#-how-to-run-an-investigation)
- [Compliance & Audit](#-compliance--audit)
- [License](#-license)

---

## 🧭 Overview

OSINTProbe is a dual-mode (Simulation / Live) intelligence platform built for forensic investigators. It orchestrates six OSINT adapters in parallel, resolves identity candidates using a trained XGBoost ML model, and surfaces all findings through a rich forensic dashboard — not a raw JSON dump.

**Two Modes:**
| Mode | Description | Speed |
|---|---|---|
| 🧪 **Simulation** | Synthetic mock adapters. 250+ realistic Indian personas. No external calls. | Instant |
| ⚡ **Live** | Real OSINT recon — Sherlock, Shodan, VirusTotal, SpiderFoot, eCourts. Requires API keys. | ~10–30s |

---

## 🔬 Forensic Feature Suite

### 1. 🕐 Forensic Investigation Timeline
Every finding is time-stamped and sequenced into a **chronological chain of evidence** — not a flat list of API responses.

```
10:32:05 ─ 🎯 Target Initialized (USERNAME)
     ↓
10:32:20 ─ 🌐 Passive Reconnaissance & DNS/WHOIS Probing
     ↓
10:32:45 ─ 👤 Social Account Claimed: Instagram
     ↓
10:33:03 ─ 📡 Host Infrastructure Discovered (182.76.xx.xx)
     ↓
10:33:17 ─ 🛡️ Threat Verdict Assessed: Clean
     ↓
10:33:33 ─ 🧬 Candidate Identity Matched (87.4% confidence)
```

Each step is tagged with an investigation category (`social`, `network`, `host`, `legal`, `breach`, `ml`) and rendered as interactive timeline cards in the dashboard.

---

### 2. 🔬 Explainable Evidence Scoring
Every identity match includes a **full XGBoost feature contribution breakdown** — no black-box scores.

Click **"Why this score? ▼"** on any candidate match to reveal:

| Feature | Method | Score |
|---|---|---|
| Given Name Similarity | Jaro-Winkler | `94%` |
| Surname Similarity | Jaro-Winkler | `88%` |
| Date of Birth | Exact Match | `EXACT (1.0)` |
| Postcode / PIN | Exact Match | `MATCH (1.0)` |
| State | Exact Match | `MATCH (1.0)` |
| Suburb / Locality | Jaro-Winkler | `72%` |

The XGBoost model was trained on the **FEBRL4 public benchmark** (Christen 2008), achieving **F1 ≥ 0.972**, **Precision 0.984**, **Recall 0.961** across 8 identity fields.

---

### 3. 🤖 Forensic Copilot AI
A **grounded, evidence-bound AI assistant** — not a generic chatbot. The Copilot answers only from the collected case evidence and cites its sources.

**Example queries:**
```
"Summarize the evidence collected in this case."
  → Executive briefing: social footprint, host exposure, breach hits, ML matches

"What are the strongest connections for this suspect?"
  → XGBoost linkage analysis with feature signal breakdown

"What should I investigate next?"
  → Prioritized next-step recommendations from the case synthesizer
```

Every response is tagged with **Grounded References** (e.g. `Sherlock Module`, `XGBoost Record Linkage Model`, `eCourts CNR Search`).

---

### 4. 🕸 Advanced Investigation Graph
A fullscreen **interactive SVG identity graph** that combines ML scores, OSINT signals, and explainability into one visual.

**Graph structure:**
```
                    ┌── 🌐 Instagram (@handle)
                    │       100% Active ────────── [click for: Sherlock verified]
                    │
🎯 TARGET ──────────┼── 🌐 Twitter (@handle)
                    │       100% Active
                    │
                    ├── 👤 Candidate A
                    │       87.4% Confidence ───── [click for: Name 94%, DOB exact]
                    │
                    └── 👤 Candidate B
                            43.1% Confidence ───── [click for: Surname 61%, no DOB]
```

- **Color-coded edges**: 🟢 Green `>75%` · 🟡 Yellow `>40%` · 🔴 Red `<40%`
- **Mid-edge confidence badges**: clickable, show exact percentage
- **Edge click modal**: answers *"Why is this connection being made?"* with full ML reasoning

---

### 5. 📄 One-Click Case Report
Generate a **print-ready forensic dossier** directly from the dashboard. Click **"📄 Generate Formal Report"** to produce:

- **Case Header**: Case Ref, Investigator ID, Timestamp, Mode
- **Target Specification**: Query type and anchor value
- **Executive Intelligence Summary**: Aggregated findings across all adapters
- **Chronological Investigation Timeline**: Full timestamped evidence chain
- **Identity Resolution Matrix**: Top candidate matches with confidence scores
- **Recommended Actions**: Prioritized next investigative steps
- **DPDP Compliance Notice**: Legal disclaimer per §17(1)(c)

Supports **browser print / Save as PDF** out of the box.

---

## 🔌 Intelligence Adapters

| Adapter | Source | Data Extracted | Modes |
|---|---|---|---|
| **Sherlock** | Social OSINT | Platform handle presence across 10+ networks | Sim + Live |
| **SpiderFoot** | Passive Recon | DNS, WHOIS, threat intel, data leaks, network entities | Sim + Live |
| **Shodan** | Host Scanning | Exposed IPs, open ports, ISP, OS fingerprint | Sim + Live |
| **VirusTotal** | Threat Intel | Malicious / Suspicious / Harmless / Undetected engine verdicts | Sim + Live |
| **eCourts CNR** | Judicial Records | IPC case numbers, offence taxonomy, court status | Sim + Live |
| **HIBP / Breach** | Breach Data | Exposed data fields mapped to phone/email identifiers | Sim + Live |

---

## 🧠 Machine Learning Engine

**Model:** XGBoost Binary Classifier (Record Linkage)
**Training Data:** FEBRL4 public benchmark dataset (Christen 2008)
**Task:** Probabilistic identity deduplication — given two records, predict if they refer to the same person.

### Feature Vector (8 fields)

| Feature | Method | Purpose |
|---|---|---|
| `given_name_sim` | Jaro-Winkler | First name — handles typos and transliteration variants |
| `surname_sim` | Jaro-Winkler | Last name — catches suffix drops and regional spelling |
| `street_sim` | Jaro-Winkler | Street number — weak alone, strong in combination |
| `suburb_sim` | Jaro-Winkler | Locality / area — detects relocated vs. duplicate records |
| `state_sim` | Jaro-Winkler | State name — stabilises borderline confidence scores |
| `dob_exact` | Exact Match | Date of birth — **highest-weight feature** |
| `postcode_exact` | Exact Match | 6-digit PIN code — strong discriminator across large pools |
| `id_sim` | Jaro-Winkler | Social / UID field — catches transposed ID digits |

### Benchmark Results (FEBRL4)

| Metric | Score |
|---|---|
| Precision | **0.984** |
| Recall | **0.961** |
| F1 Score | **0.972** |
| Threshold | `> 0.30` match probability |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  OSINTProbe Dashboard                   │
│              Vue 3 · Vanilla CSS · SVG                  │
│                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Timeline │ │  Graph   │ │ Copilot  │ │  Report  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │
└───────┼─────────────┼────────────┼─────────────┼────────┘
        │             │            │             │
        └─────────────┼────────────┘             │
                      │ fetch /api/investigate   │
                      │ fetch /api/copilot       │
                      ▼                          │
┌─────────────────────────────────────────────────────────┐
│              FastAPI Backend  (port 8000)               │
│                                                         │
│  /api/investigate ──► Adapter Orchestrator              │
│      ├── Sherlock   (social handles)                    │
│      ├── SpiderFoot (passive recon)                     │
│      ├── Shodan     (host scanning)                     │
│      ├── VirusTotal (threat intel)                      │
│      ├── eCourts    (judicial records)                  │
│      └── HIBP/Breach (data exposure)                    │
│                                                         │
│  /api/copilot  ──► Evidence-grounded Q&A engine         │
│  /api/audit-log/{case_id} ──► Immutable audit trail     │
│  /api/personas ──► Benchmark persona directory          │
│                                                         │
│  ┌─────────────────────────────────────┐                │
│  │      XGBoost Identity Resolution   │                │
│  │   FEBRL4-trained · 8 Features      │                │
│  │   Jaro-Winkler + Exact Matching    │                │
│  └─────────────────────────────────────┘                │
│                                                         │
│  📝 audit_log.jsonl — append-only, DPDP §17(1)(c)       │
└─────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
osint-tool-project/
├── README.md
├── .gitignore
└── osint-tool/
    ├── backend/
    │   ├── main.py                        # FastAPI app · all endpoints · audit logger
    │   ├── .env.example                   # API keys template (copy → .env)
    │   ├── audit_log.jsonl                # Append-only query audit trail (gitignored)
    │   ├── adapters/
    │   │   ├── mock_adapters.py           # Simulation-mode synthetic data adapters
    │   │   └── real_adapters.py           # Live OSINT adapters (Sherlock, Shodan, VT…)
    │   ├── ml/
    │   │   ├── entity_resolution.py       # XGBoost Record Linkage — trainer & scorer
    │   │   └── entity_resolution_model.joblib  # Pre-trained model artifact
    │   └── data/
    │       ├── persona_generator.py       # Synthetic persona builder (Faker en_IN)
    │       └── synthetic_personas.json    # 250 benchmark personas
    └── frontend/
        └── index.html                     # Vue 3 SPA · SVG Graph · Copilot · Timeline
```

---

## 🚀 Quick Start

### Prerequisites

- Python **3.9+**
- pip
- A modern browser (Chrome / Firefox / Edge)

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/prajwal-dn/osint.git
cd osint-tool-project
```

---

### Step 2 — Backend Setup

#### 🪟 Windows (PowerShell)

```powershell
# Create & activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1
# If blocked by execution policy:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Install dependencies
pip install fastapi uvicorn xgboost scikit-learn recordlinkage pandas faker joblib python-dotenv

# (Optional) Add API keys for Live mode
Copy-Item osint-tool\backend\.env.example osint-tool\backend\.env

# Launch the API server
cd osint-tool\backend
uvicorn main:app --reload --port 8000
```

#### 🐧 Linux / Kali Linux

```bash
# Create & activate virtual environment
python3 -m venv venv && source venv/bin/activate

# Install dependencies
pip install fastapi uvicorn xgboost scikit-learn recordlinkage pandas faker joblib python-dotenv

# (Optional) Add API keys for Live mode
cp osint-tool/backend/.env.example osint-tool/backend/.env

# Launch the API server
cd osint-tool/backend
uvicorn main:app --reload --port 8000
```

> **Kali system-wide fallback** (if venv is unavailable):
> ```bash
> sudo pip install fastapi uvicorn xgboost scikit-learn recordlinkage pandas faker joblib python-dotenv --break-system-packages
> python3 -m uvicorn main:app --reload --port 8000
> ```

Backend docs: **`http://localhost:8000/docs`**

---

### Step 3 — Frontend Setup

```powershell
# Windows
cd osint-tool\frontend
python -m http.server 8080
```

```bash
# Linux / Kali
cd osint-tool/frontend
python3 -m http.server 8080
```

Open **`http://localhost:8080`** in your browser.

> **Shortcut:** You can also open `osint-tool/frontend/index.html` directly in your browser (file:// protocol) with the backend running on port 8000.

---

### Step 4 — (Optional) Configure Live Mode API Keys

Copy `.env.example` to `.env` in the backend directory and populate:

```env
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
HIBP_API_KEY=your_haveibeenpwned_key
SPIDERFOOT_URL=http://localhost:5001   # if running SpiderFoot locally
```

---

## 🔗 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/investigate` | Run a full intelligence investigation |
| `POST` | `/api/copilot` | Ask the Forensic Copilot a question about a case |
| `GET` | `/api/audit-log/{case_id}` | Retrieve the full audit trail for a case |
| `GET` | `/api/personas` | List all 250 benchmark personas |
| `GET` | `/docs` | Interactive Swagger API documentation |

### `POST /api/investigate` — Request Body

```json
{
  "case_id":        "FIR-2026-00812",   // optional — auto-generated if blank
  "investigator_id": "INS-Sharma",      // optional — defaults to ANALYST-USER
  "query_type":     "username",          // "username" | "name" | "phone"
  "query_value":    "isaac_bakshi27",    // required
  "reason":         "Cybercrime complaint ref #4821",  // optional
  "threshold":      0.3,                // ML match threshold (0.0–1.0)
  "mode":           "SIMULATION"        // "SIMULATION" | "LIVE"
}
```

### `POST /api/copilot` — Request Body

```json
{
  "question":  "What are the strongest connections for this suspect?",
  "case_file": { /* full result object from /api/investigate */ }
}
```

---

## 🎯 How to Run an Investigation

1. **Select a Query Type**: Choose between `Username`, `Full Name`, or `Phone Number`.
2. **Enter the Target**: Type any identifier in the search field.
3. **Set Engine Mode**: `Simulation` for instant demo results; `Live` for real recon.
4. **Click ▶ Run Investigation** — the full pipeline executes and the case file populates.
5. **Explore the Tabs:**
   - **📁 Case File** — live OSINT findings across all six adapters
   - **⏳ Forensic Timeline** — chronological chain of evidence from first signal to final match
   - **🔗 Identity Links** — XGBoost candidate matches with "Why this score? ▼" explainability
   - **🤖 Copilot AI** — ask natural-language questions grounded in the case evidence
   - **📋 Session Audit Log** — immutable record of every query in this session
6. **Open the Graph**: Click **🔎 Open Fullscreen Identity Graph** — explore the network diagram and click any edge to see *why* that connection exists.
7. **Generate Report**: Click **📄 Generate Formal Report** to export a print-ready forensic dossier.

**Quick demo with a preset profile:**
- Open the **Personas** page from the top nav.
- Click any profile (e.g. `@isaac_bakshi27`) → it auto-fills the search form.
- Hit **▶ Run Investigation**.

---

## 📜 Compliance & Audit

OSINTProbe is designed for **authorized forensic use**. Every query execution is automatically written to an append-only JSONL audit log containing:

```jsonl
{
  "case_id": "FIR-2026-00812",
  "investigator_id": "INS-Sharma",
  "query_type": "username",
  "query_value": "isaac_bakshi27",
  "reason": "Cybercrime complaint ref #4821",
  "mode": "SIMULATION",
  "logged_at": "2026-08-19T14:32:11.482Z"
}
```

- **Simulation mode** operates entirely on synthetic data — no real individuals are queried or stored.
- **Live mode** requires case-authorised access and is subject to DPDP Act Section 17(1)(c) compliance requirements.
- The persona dataset is built on `Faker(en_IN)` + real public reference data (India Post PIN directory, NCRB crime taxonomy, FEBRL4 benchmark). No real personal data is used.

---

## 📄 License

MIT License — Open for academic research, forensic simulation, and technical demonstration.

**Production deployment** against real individuals requires case-authorised access under **India's Digital Personal Data Protection Act (DPDP) Section 17(1)(c)** and applicable BPRD forensic investigation guidelines.

---

<div align="center">

Built with FastAPI · Vue 3 · XGBoost · SVG · FEBRL4

</div>