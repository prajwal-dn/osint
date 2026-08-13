"""
OSINT Investigation Tool -- Backend API
==========================================
Every query MUST be tied to a case ID (per DPDP Act S.17(1)(c) framing --
processing is justified because it's tied to investigation of an offence,
not open-ended lookup). Every query is written to an append-only audit log.

Run: uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "adapters"))
sys.path.append(os.path.join(os.path.dirname(__file__), "ml"))
sys.path.append(os.path.join(os.path.dirname(__file__), "data"))

from mock_adapters import (sherlock_adapter, ecourts_adapter, breach_lookup_adapter,
                           shodan_adapter, virustotal_adapter, spiderfoot_adapter,
                           generate_recommendations, _load_personas)
from entity_resolution import score_pair

app = FastAPI(title="OSINT Investigation Tool (Simulation Mode)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")


class QueryRequest(BaseModel):
    case_id: str          # REQUIRED: every query must cite a case/FIR reference
    investigator_id: str  # REQUIRED: who is running this query
    query_type: str       # "username" | "name" | "phone"
    query_value: str
    reason: str            # short justification, goes into audit log
    threshold: float = 0.3 # match threshold (0.0 - 1.0)


def _write_audit(entry: dict):
    entry["logged_at"] = datetime.now().isoformat()
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


@app.post("/api/investigate")
def investigate(req: QueryRequest):
    """
    Main investigation endpoint. Runs the query across mock data sources,
    resolves overlapping identities, and returns a case-file-style summary.
    """
    if not req.case_id or not req.investigator_id or not req.reason:
        raise HTTPException(400, "case_id, investigator_id, and reason are required for every query.")

    _write_audit({
        "case_id": req.case_id,
        "investigator_id": req.investigator_id,
        "query_type": req.query_type,
        "query_value": req.query_value,
        "reason": req.reason,
    })

    findings = {"sherlock": None, "ecourts": None, "breach": None,
                "shodan": None, "virustotal": None, "spiderfoot": None}

    # Run SpiderFoot recon for all queries
    findings["spiderfoot"] = spiderfoot_adapter(req.query_value)

    if req.query_type == "username":
        findings["sherlock"]    = sherlock_adapter(req.query_value)
        findings["shodan"]      = shodan_adapter(req.query_value)
        findings["virustotal"]  = virustotal_adapter(req.query_value)
    elif req.query_type == "name":
        findings["ecourts"]     = ecourts_adapter(req.query_value)
        findings["shodan"]      = shodan_adapter(req.query_value)
        findings["virustotal"]  = virustotal_adapter(req.query_value)
    elif req.query_type == "phone":
        findings["breach"]      = breach_lookup_adapter(req.query_value)
        findings["virustotal"]  = virustotal_adapter(req.query_value)
    else:
        raise HTTPException(400, "query_type must be one of: username, name, phone")

    # Entity resolution: find candidate identity matches across the persona pool
    resolved_matches = resolve_identity_candidates(req.query_value, req.threshold)

    # Recommended actions synthesised from all findings
    recommendations = generate_recommendations(findings, resolved_matches)

    case_file = {
        "case_id": req.case_id,
        "generated_at": datetime.now().isoformat(),
        "query": {"type": req.query_type, "value": req.query_value},
        "raw_findings": findings,
        "identity_resolution": resolved_matches,
        "recommended_actions": recommendations,
        "disclaimer": "FORENSIC NOTICE: Authorized OSINT investigation output generated under DPDP Act Section 17(1)(c) compliance guidelines.",
    }
    return case_file


def resolve_identity_candidates(query_value: str, threshold: float = 0.3, top_k: int = 5):
    """
    Compares the queried persona against all others in the pool and returns
    the highest-confidence identity matches -- this is where the ML model
    (trained on real FEBRL benchmark data) does its job.
    Dynamically generates anchor attributes for non-preset custom queries.
    """
    personas = _load_personas()

    anchor = None
    for p in personas:
        if query_value.lower() in [u.lower() for u in p["usernames"]] or \
           query_value.lower() in f"{p['given_name']} {p['surname']}".lower():
            anchor = p
            break
        elif query_value == p.get("phone"):
            anchor = p
            break

    if anchor is None:
        # Construct dynamic anchor representation from arbitrary custom input
        parts = query_value.strip().split()
        g_name = parts[0] if parts else query_value
        s_name = parts[1] if len(parts) > 1 else "Kumar"
        anchor = {
            "persona_id": f"PER-GEN-{abs(hash(query_value))%10000:04d}",
            "given_name": g_name,
            "surname": s_name,
            "usernames": [query_value],
            "phone": query_value,
            "postcode": "110001",
            "street_number": "12",
            "suburb": "Central",
            "state": "Delhi",
            "soc_sec_id": "999-00-1234",
            "date_of_birth": "19920514",
        }

    scored = []
    for p in personas:
        if p["persona_id"] == anchor["persona_id"]:
            continue
        try:
            score, features = score_pair(anchor, p)
        except Exception:
            continue
        if score > threshold:
            scored.append({
                "persona_id": p["persona_id"],
                "match_confidence": round(score, 4),
                "name_shown": f"{p['given_name']} {p['surname']}",
                "state": p["state"],
                "features": features,
            })

    scored.sort(key=lambda x: -x["match_confidence"])
    return scored[:top_k]


@app.get("/api/audit-log/{case_id}")
def get_audit_log(case_id: str):
    """Retrieve the full audit trail for a given case -- accountability feature."""
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    entries = []
    with open(AUDIT_LOG_PATH) as f:
        for line in f:
            entry = json.loads(line)
            if entry["case_id"] == case_id:
                entries.append(entry)
    return entries


@app.get("/api/personas")
def list_personas():
    """Demo helper: list available synthetic personas to query against."""
    personas = _load_personas()
    return [{"persona_id": p["persona_id"], "given_name": p["given_name"],
             "surname": p["surname"], "usernames": p["usernames"],
             "phone": p["phone"], "state": p["state"]} for p in personas]


@app.get("/")
def root():
    return {"status": "ok", "mode": "SIMULATION", "message": "OSINT Investigation Tool backend running."}
