# RK310 — Criminal/Suspect Profile Generator using OSINT Techniques
### BPRD problem statement, SIH-style internal hackathon build

## ⚠️ Simulation mode
This runs entirely on synthetic data. No real individuals are queried.
Production deployment would require case-authorized access under
DPDP Act Section 17(1)(c).

## What's inside
- `backend/ml/entity_resolution.py` — XGBoost entity-resolution model,
  trained & validated on the real FEBRL public record-linkage benchmark
  (F1 = 0.999 on held-out test split)
- `backend/data/persona_generator.py` — synthetic Indian persona generator
  (Faker en_IN), with deliberately planted "hard case" identity duplicates
- `backend/adapters/mock_adapters.py` — mock adapters matching real
  Sherlock / eCourts / breach-lookup API response shapes
- `backend/main.py` — FastAPI backend: case-ID-gated queries, mandatory
  investigator ID + reason, full audit logging, case-file-style output
- `frontend/index.html` — Vue.js + vis.js investigation dashboard
  (single file, no build step — open directly or serve statically)

## How to run

1. Install backend deps (already scoped in this environment, but for a
   fresh machine):
   ```
   pip install recordlinkage pandas scikit-learn xgboost faker fastapi uvicorn joblib
   ```

2. Generate demo data + train the model (only needed once):
   ```
   cd backend/data && python3 persona_generator.py
   cd ../ml && python3 entity_resolution.py
   ```

3. Start the backend:
   ```
   cd backend && uvicorn main:app --reload --port 8000
   ```

4. Open `frontend/index.html` in a browser (it points at
   `http://localhost:8000` by default — edit `API_BASE` in the `<script>`
   tag if you serve the backend elsewhere).

5. Click "Browse demo personas" to auto-fill a query, fill in a Case ID /
   Investigator ID / reason, and click "Run Investigation".

## Try this for the demo
Query name **"Chaitanya Sarin"** — this is one of the planted hard-case
duplicates. The identity resolution panel should show a ~99.98% confidence
match to their duplicate profile (SIM-0040), demonstrating the entity
resolution engine catching a genuinely ambiguous case.

## Next steps before the finale
- Swap `mock_adapters.py` functions for real Sherlock/eCourts calls
  (same function signatures, same output schema — drop-in)
- Add role-based access control (investigator vs supervisor) to the API
- Add data retention/purge policy for cleared-suspect profiles
- Move audit log from JSONL file to an append-only DB table
