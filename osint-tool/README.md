# 🕵️‍♂️ OSINT Investigation Tool — Criminal & Suspect Profiling Engine

A high-fidelity, simulation-grade Open Source Intelligence (OSINT) investigation dashboard and entity-resolution platform designed for forensic profiling, cross-platform reconnaissance, and identity linking.

> ⚠️ **Simulation Mode Disclaimer**: This system operates on synthetic demo datasets (250+ generated Indian persona profiles) and dynamic mock adapters (Sherlock, Shodan, VirusTotal, SpiderFoot, eCourts). No real individuals are queried or stored.

---

## ✨ Features

- **🔍 Multi-Source Intelligence Orchestration**:
  - **Sherlock Adapter**: Cross-platform social handle availability and profile detection across 10+ networks.
  - **SpiderFoot Adapter**: Automated passive/active OSINT recon (Whois, DNS, Threat Intel, Leaks).
  - **Shodan Host Lookup**: Exposed IP addresses, open ports, and ISP data profiling.
  - **VirusTotal Reputation**: Domain/IP security score breakdown & verdict metrics.
  - **eCourts CNR Search**: Structural court record lookup with IPC offense taxonomy & CNR tracking.
  - **HIBP Breach Records**: Data exposure checks mapped to phone/email identifiers.

- **🧬 Machine Learning Entity Resolution**:
  - Powered by **XGBoost** trained on the **FEBRL4 public benchmark dataset** (Christen 2008).
  - Evaluates 8 identity fields (Name Jaro-Winkler, DOB, Suburb, Postcode, Phone) to compute probabilistic identity match confidence scores.

- **🕸 Interactive Forensic Network Diagram**:
  - Fullscreen SVG identity graph visualization displaying target anchors, social platforms, and probabilistic candidate links with confidence badges.

- **📜 Immutable Audit & Compliance**:
  - Mandatory Case/FIR Reference, Investigator ID, and Reason logging.
  - Append-only JSONL audit trail tracking every query execution for forensic compliance.

- **👥 250+ Synthetic Indian Persona Directory**:
  - Pre-populated benchmark directory with search filters (Username, Name, Phone) for instant case testing.

---

## 🛠 Project Structure

```
.
├── .gitignore
├── README.md                      # Root Setup & Operating Guide
└── osint-tool/
    ├── backend/
    │   ├── main.py                # FastAPI REST API & Audit Logger
    │   ├── adapters/
    │   │   └── mock_adapters.py   # Multi-source OSINT data synthesis adapters
    │   ├── ml/
    │   │   ├── entity_resolution.py  # XGBoost Record Linkage model trainer & scorer
    │   │   └── entity_resolution_model.joblib
    │   └── data/
    │       ├── persona_generator.py  # Synthetic persona builder
    │       └── synthetic_personas.json # 250 Persona benchmark database
    ├── frontend/
    │   └── index.html             # Vue 3 Dashboard + SVG Graph Modal
    └── README.md                  # Subdirectory Documentation
```

---

## 🚀 Quick Start Guide

### 1. Clone Repository & Navigate to Directory
```bash
git clone https://github.com/prajwal-dn/osint.git
cd osint
```

---

### 2. Backend Setup & Run

Choose the instructions matching your Operating System below:

---

#### 🪟 **Option A: Windows Setup (PowerShell / Command Prompt)**

**1. Create and Activate Virtual Environment:**
```powershell
# Create virtual environment
python -m venv venv

# Activate in PowerShell:
.\venv\Scripts\Activate.ps1
# (Note: If execution is disabled in PowerShell, run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass)

# OR Activate in Command Prompt (CMD):
.\venv\Scripts\activate.bat
```

**2. Install Required Dependencies:**
```powershell
pip install fastapi uvicorn xgboost scikit-learn recordlinkage pandas faker joblib
```

**3. Launch Backend API Server:**
```powershell
cd osint-tool\backend
uvicorn main:app --reload --port 8000
```
> *Or without venv:* `python -m uvicorn main:app --reload --port 8000`

---

#### 🐧 **Option B: Linux / Kali Linux Setup**

**Virtual Environment Mode (Recommended):**
```bash
# 1. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install all required dependencies
pip install fastapi uvicorn xgboost scikit-learn recordlinkage pandas faker joblib

# 3. Start backend server
cd osint-tool/backend
uvicorn main:app --reload --port 8000
```

**Kali Linux Direct Override Mode (System-wide install):**
```bash
# 1. Install dependencies overriding system package lock
sudo pip install fastapi uvicorn xgboost scikit-learn recordlinkage pandas faker joblib --break-system-packages

# 2. Start backend server
cd osint-tool/backend
python3 -m uvicorn main:app --reload --port 8000
```

---

*Backend API Interactive Documentation will be available at:* **`http://localhost:8000/docs`**

---

### 3. Frontend Setup & Run

Serve the frontend using Python's built-in HTTP server:

#### **On Windows (PowerShell / CMD):**
```powershell
cd osint-tool\frontend
python -m http.server 8080
```
*(Or simply double-click `osint-tool\frontend\index.html` to open directly in your web browser).*

#### **On Linux / Kali Linux:**
```bash
cd osint-tool/frontend
python3 -m http.server 8080
```

Open **`http://localhost:8080`** in your web browser to launch the OSINT Investigation Dashboard.

---

## 🎯 How to Test

1. **Preset Demo Profiles**:
   - Go to **Personas** in the top navigation bar.
   - Pick any profile (e.g. `SIM-0000 · Saanvi Bansal` or `@isaac_bakshi27`) and click **Use in Investigation**.
2. **Custom Target Search**:
   - Enter any custom **Name**, **Username**, or **Phone Number** (e.g. *Rohan Sharma*).
   - Provide a mock Case ID (e.g. `FIR-2026-881`), Investigator ID (`INV-901`), and Reason.
   - Click **► Run Investigation**.
3. **Forensic Identity Graph**:
   - Click **`🔎 Open Fullscreen Identity Graph`** at the top right to pop open the network diagram visualization.

---

## 📄 License & Compliance

Designed for simulation and technical demonstration purposes under BPRD forensic investigation guidelines. Production deployment requires case-authorized access under DPDP Act Section 17(1)(c).
