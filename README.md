# 🕵️‍♂️ OSINT Investigation Tool — Criminal & Suspect Profiling Engine

A high-fidelity, simulation-grade Open Source Intelligence (OSINT) investigation dashboard and entity-resolution platform designed for forensic profiling, cross-platform reconnaissance, and identity linking.

> ⚠️ **Simulation Mode Disclaimer**: In **Simulation** mode this system operates entirely on synthetic demo datasets (250+ generated Indian persona profiles) and dynamic mock adapters (Sherlock, Shodan, VirusTotal, SpiderFoot, eCourts). No real individuals are queried or stored. **Live** mode performs real network reconnaissance against public endpoints and requires authorized use.

---

## ✨ Features

- **🔍 Multi-Source Intelligence Orchestration** (each adapter ships in a **Simulation** mock variant and a **Live** real variant):
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
  - Case/FIR Reference, Investigator ID, and Reason logging (auto-generated when left blank).
  - Append-only JSONL audit trail tracking every query execution for forensic compliance.

- **👥 250+ Synthetic Indian Persona Directory**:
  - Pre-populated benchmark directory with search filters (Username, Name, Phone) for instant case testing.

- **⚡ Live / Simulation Mode Toggle**:
  - One-click switch in the sidebar. **Simulation** (default) is instant and uses synthetic adapters; **Live** runs real OSINT recon and may take up to ~30s.

---

## 🛠 Project Structure

```
.
├── .gitignore
├── README.md                      # Setup & Operating Guide
└── osint-tool/
    ├── backend/
    │   ├── main.py                # FastAPI REST API & Audit Logger
    │   ├── adapters/
    │   │   ├── mock_adapters.py   # Synthetic / simulation data adapters
    │   │   └── real_adapters.py   # Live OSINT adapters (Sherlock, Shodan, VT, HIBP, SpiderFoot, eCourts)
    │   ├── ml/
    │   │   ├── entity_resolution.py          # XGBoost Record Linkage trainer & scorer
    │   │   └── entity_resolution_model.joblib
    │   ├── data/
    │   │   ├── persona_generator.py          # Synthetic persona builder
    │   │   └── synthetic_personas.json       # 250 Persona benchmark database
    │   ├── .env.example           # Optional API keys template (copy to .env)
    │   └── audit_log.jsonl        # Append-only query audit trail (gitignored)
    └── frontend/
        └── index.html             # Vue 3 Dashboard + SVG Graph Modal
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
pip install fastapi uvicorn xgboost scikit-learn recordlinkage pandas faker joblib python-dotenv
```

**3. (Optional) Configure API Keys:**
Copy `.env.example` to `.env` and add your Shodan / VirusTotal / HIBP keys to unlock deep live scans:
```powershell
Copy-Item osint-tool\backend\.env.example osint-tool\backend\.env
```

**4. Launch Backend API Server:**
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
pip install fastapi uvicorn xgboost scikit-learn recordlinkage pandas faker joblib python-dotenv

# 3. (Optional) Copy .env.example to .env and add API keys

# 4. Start backend server
cd osint-tool/backend
uvicorn main:app --reload --port 8000
```

**Kali Linux Direct Override Mode (System-wide install):**
```bash
# 1. Install dependencies overriding system package lock
sudo pip install fastapi uvicorn xgboost scikit-learn recordlinkage pandas faker joblib python-dotenv --break-system-packages

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

1. **Choose an Engine Mode**:
   - **Simulation** (default): instant synthetic results using mock adapters.
   - **Live**: real OSINT recon against public endpoints — requires network access and may take up to ~30s.
2. **Preset Demo Profiles**:
   - Go to **Personas** in the top navigation bar.
   - Pick any profile (e.g. `SIM-0000 · Saanvi Bansal` or `@isaac_bakshi27`) and click **Use in Investigation**.
3. **Custom Target Search**:
   - Enter any custom **Name**, **Username**, or **Phone Number** (e.g. *Rohan Sharma*).
   - Case ID, Investigator ID, and Reason are optional — auto-generated if left blank.
   - Click **▶ Run Investigation**.
4. **Forensic Identity Graph**:
   - Click **`🔎 Open Fullscreen Identity Graph`** at the top right to pop open the network diagram visualization.

---

## 📄 License & Compliance

Designed for simulation and technical demonstration purposes under BPRD forensic investigation guidelines. Production deployment requires case-authorized access under DPDP Act Section 17(1)(c).