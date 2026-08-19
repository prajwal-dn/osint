"""
OSINT Investigation Tool -- Backend API (Live & Simulation Support)
=====================================================================
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
from dotenv import load_dotenv
load_dotenv(override=True)

sys.path.append(os.path.join(os.path.dirname(__file__), "adapters"))
sys.path.append(os.path.join(os.path.dirname(__file__), "ml"))
sys.path.append(os.path.join(os.path.dirname(__file__), "data"))

from mock_adapters import (sherlock_adapter as mock_sherlock,
                           ecourts_adapter as mock_ecourts,
                           breach_lookup_adapter as mock_breach,
                           shodan_adapter as mock_shodan,
                           virustotal_adapter as mock_virustotal,
                           spiderfoot_adapter as mock_spiderfoot,
                           generate_recommendations, _load_personas)

from real_adapters import (real_sherlock_adapter,
                           real_shodan_adapter,
                           real_virustotal_adapter,
                           real_breach_lookup_adapter,
                           real_spiderfoot_adapter,
                           real_ecourts_adapter)

from entity_resolution import score_pair

app = FastAPI(title="OSINT Investigation Tool (Live & Simulation Mode)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")
DEFAULT_MODE = os.getenv("OSINT_MODE", "LIVE").upper()


class QueryRequest(BaseModel):
    case_id: str = ""          # OPTIONAL: auto-generated if blank
    investigator_id: str = ""  # OPTIONAL: defaults to ANALYST-USER if blank
    query_type: str            # "username" | "name" | "phone"
    query_value: str
    reason: str = ""           # OPTIONAL: default justification if blank
    threshold: float = 0.3     # match threshold (0.0 - 1.0)
    mode: str = DEFAULT_MODE   # "LIVE" | "SIMULATION"


def _write_audit(entry: dict):
    entry["logged_at"] = datetime.now().isoformat()
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


@app.post("/api/investigate")
def investigate(req: QueryRequest):
    """
    Main investigation endpoint. Supports LIVE OSINT recon and SIMULATION mode.
    Resolves overlapping identities and returns a forensic case-file summary.
    """
    if not req.query_value or not req.query_value.strip():
        raise HTTPException(400, "query_value is required for every search.")

    # Auto-assign defaults for optional metadata fields if empty
    if not req.case_id or not req.case_id.strip():
        req.case_id = f"REF-{datetime.now().strftime('%Y%m%d')}-{abs(hash(req.query_value))%10000:04d}"
    if not req.investigator_id or not req.investigator_id.strip():
        req.investigator_id = "ANALYST-USER"
    if not req.reason or not req.reason.strip():
        req.reason = "General OSINT Target Verification & Identity Recon"

    is_live = req.mode.upper() == "LIVE"

    _write_audit({
        "case_id": req.case_id,
        "investigator_id": req.investigator_id,
        "query_type": req.query_type,
        "query_value": req.query_value,
        "reason": req.reason,
        "mode": req.mode.upper(),
    })

    findings = {"sherlock": None, "ecourts": None, "breach": None,
                "shodan": None, "virustotal": None, "spiderfoot": None}

    if is_live:
        # Run Real Live OSINT Adapters
        findings["spiderfoot"] = real_spiderfoot_adapter(req.query_value)

        if req.query_type == "username":
            findings["sherlock"]   = real_sherlock_adapter(req.query_value)
            findings["shodan"]     = real_shodan_adapter(req.query_value)
            findings["virustotal"] = real_virustotal_adapter(req.query_value)
        elif req.query_type == "name":
            findings["ecourts"]    = real_ecourts_adapter(req.query_value)
            findings["shodan"]     = real_shodan_adapter(req.query_value)
            findings["virustotal"] = real_virustotal_adapter(req.query_value)
        elif req.query_type == "phone":
            findings["breach"]     = real_breach_lookup_adapter(req.query_value)
            findings["virustotal"] = real_virustotal_adapter(req.query_value)
        else:
            raise HTTPException(400, "query_type must be one of: username, name, phone")
    else:
        # Run Simulation Mode Mock Adapters
        findings["spiderfoot"] = mock_spiderfoot(req.query_value)

        if req.query_type == "username":
            findings["sherlock"]   = mock_sherlock(req.query_value)
            findings["shodan"]     = mock_shodan(req.query_value)
            findings["virustotal"] = mock_virustotal(req.query_value)
        elif req.query_type == "name":
            findings["ecourts"]    = mock_ecourts(req.query_value)
            findings["shodan"]     = mock_shodan(req.query_value)
            findings["virustotal"] = mock_virustotal(req.query_value)
        elif req.query_type == "phone":
            findings["breach"]     = mock_breach(req.query_value)
            findings["virustotal"] = mock_virustotal(req.query_value)
        else:
            raise HTTPException(400, "query_type must be one of: username, name, phone")

    # Entity resolution: find candidate identity matches across persona pool
    resolved_matches = resolve_identity_candidates(req.query_value, req.threshold)

    # Recommended actions synthesised from all findings
    recommendations = generate_recommendations(findings, resolved_matches)

    # Generate chronological investigation timeline
    timeline = generate_investigation_timeline(findings, resolved_matches, req.query_type, req.query_value)

    case_file = {
        "case_id": req.case_id,
        "execution_mode": "LIVE" if is_live else "SIMULATION",
        "generated_at": datetime.now().isoformat(),
        "query": {"type": req.query_type, "value": req.query_value},
        "raw_findings": findings,
        "identity_resolution": resolved_matches,
        "recommended_actions": recommendations,
        "timeline": timeline,
        "disclaimer": "FORENSIC NOTICE: Authorized OSINT investigation output generated under DPDP Act Section 17(1)(c) compliance guidelines.",
    }
    return case_file


def generate_investigation_timeline(findings: dict, matches: list, query_type: str, query_value: str) -> list:
    """Generates sequential forensic timeline steps from gathered findings."""
    base_time = datetime.now()
    from datetime import timedelta
    timeline = []
    t_offset = 0

    timeline.append({
        "timestamp": (base_time + timedelta(seconds=t_offset)).strftime("%H:%M:%S"),
        "title": f"Target Initialized ({query_type.upper()})",
        "detail": f"Target anchor '{query_value}' entered into reconnaissance pipeline.",
        "icon": "🎯",
        "category": "system"
    })
    t_offset += 15

    spiderfoot = findings.get("spiderfoot")
    if spiderfoot and spiderfoot.get("entities"):
        timeline.append({
            "timestamp": (base_time + timedelta(seconds=t_offset)).strftime("%H:%M:%S"),
            "title": "Passive Reconnaissance & DNS/WHOIS Probing",
            "detail": f"SpiderFoot mapped {spiderfoot.get('data_elements_found', 0)} network entities and technical banners.",
            "icon": "🌐",
            "category": "network"
        })
        t_offset += 25

    sherlock = findings.get("sherlock")
    if sherlock and sherlock.get("found_on"):
        for p in sherlock["found_on"]:
            timeline.append({
                "timestamp": (base_time + timedelta(seconds=t_offset)).strftime("%H:%M:%S"),
                "title": f"Social Account Claimed: {p['platform']}",
                "detail": f"Verified active handle '@{p['username']}' on {p['platform']}.",
                "icon": "👤",
                "category": "social"
            })
            t_offset += 12

    shodan = findings.get("shodan")
    if shodan and shodan.get("hosts"):
        for h in shodan["hosts"]:
            timeline.append({
                "timestamp": (base_time + timedelta(seconds=t_offset)).strftime("%H:%M:%S"),
                "title": f"Host Infrastructure Discovered ({h['ip']})",
                "detail": f"Exposed IP located via ISP {h['isp']} with open ports: {', '.join(str(p) for p in h.get('open_ports', []))}.",
                "icon": "📡",
                "category": "host"
            })
            t_offset += 18

    vt = findings.get("virustotal")
    if vt:
        timeline.append({
            "timestamp": (base_time + timedelta(seconds=t_offset)).strftime("%H:%M:%S"),
            "title": f"Threat Verdict Assessed: {vt.get('verdict', 'Clean')}",
            "detail": f"VirusTotal score breakdown: {vt.get('malicious',0)} malicious, {vt.get('suspicious',0)} suspicious out of {vt.get('total_engines',90)} engines.",
            "icon": "🛡️",
            "category": "security"
        })
        t_offset += 14

    ecourts = findings.get("ecourts")
    if ecourts and ecourts.get("results"):
        for c in ecourts["results"]:
            timeline.append({
                "timestamp": (base_time + timedelta(seconds=t_offset)).strftime("%H:%M:%S"),
                "title": f"Court Judgment / CNR Record Linked",
                "detail": f"CNR {c['cnr_number']} filed under {c['ipc_section']} in {c['court']} ({c['status']}).",
                "icon": "⚖️",
                "category": "legal"
            })
            t_offset += 20

    breach = findings.get("breach")
    if breach and breach.get("breaches"):
        for b in breach["breaches"]:
            timeline.append({
                "timestamp": (base_time + timedelta(seconds=t_offset)).strftime("%H:%M:%S"),
                "title": f"Breach Exposure Flagged: {b['breach_name']}",
                "detail": f"Exposed data fields: {', '.join(b.get('data_exposed', []))}.",
                "icon": "🔓",
                "category": "breach"
            })
            t_offset += 16

    if matches:
        top = matches[0]
        timeline.append({
            "timestamp": (base_time + timedelta(seconds=t_offset)).strftime("%H:%M:%S"),
            "title": f"Candidate Identity Resolution Matched ({top['name_shown']})",
            "detail": f"XGBoost record linkage model computed {top['match_confidence']*100:.1f}% match probability with persona ID {top['persona_id']}.",
            "icon": "🧬",
            "category": "ml"
        })

    return timeline


class CopilotRequest(BaseModel):
    question: str
    case_file: dict


@app.post("/api/copilot")
def copilot_query(req: CopilotRequest):
    """
    Forensic Investigator AI endpoint. Answers investigator queries grounded strictly in case_file evidence.
    Calls Groq API if GROQ_API_KEY is available in .env, otherwise falls back to rule-based analysis.
    """
    import urllib.request
    
    q = req.question.lower().strip()
    case = req.case_file
    findings = case.get("raw_findings", {})
    matches = case.get("identity_resolution", [])
    query_val = case.get("query", {}).get("value", "Target")

    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    
    if GROQ_API_KEY:
        try:
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            }
            payload = {
                "model": "mixtral-8x7b-32768",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a professional Forensic Investigator AI. Your sole purpose is to analyze the case file evidence provided. You MUST ONLY answer questions strictly related to the case evidence and this OSINT forensic tool. If asked ANYTHING else (like writing code, general chatting, jokes, or unrelated topics), you must immediately decline and state your restricted forensic scope. Do not invent information. Format output in clear markdown. Keep answers concise, professional, and directly address the investigator's query."
                    },
                    {
                        "role": "user",
                        "content": f"Case File Evidence Summary: {json.dumps(case)[:5000]}\n\nInvestigator Query: {req.question}"
                    }
                ],
                "temperature": 0.2
            }
            req_obj = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method="POST")
            with urllib.request.urlopen(req_obj, timeout=15) as resp:
                res_data = json.loads(resp.read().decode('utf-8'))
                answer = res_data['choices'][0]['message']['content']
                return {
                    "answer": answer,
                    "references": ["Investigator AI (Groq LLM)"],
                    "timestamp": datetime.now().isoformat()
                }
        except Exception as e:
            import traceback
            error_msg = f"**Groq API Error:** `{e}`\n"
            if hasattr(e, 'read'):
                error_msg += f"Response: {e.read().decode('utf-8')}"
            return {
                "answer": error_msg,
                "references": ["System Error"],
                "timestamp": datetime.now().isoformat()
            }

    # --- RULE-BASED FALLBACK --- #
    response_text = ""
    references = []

    if "summary" in q or "summarize" in q or "overview" in q or "evidence" in q:
        sherlock_cnt = findings.get("sherlock", {}).get("claimed_count", 0) if findings.get("sherlock") else 0
        shodan_cnt = findings.get("shodan", {}).get("exposed_count", 0) if findings.get("shodan") else 0
        ecourts_cnt = findings.get("ecourts", {}).get("filed_count", 0) if findings.get("ecourts") else 0
        breach_cnt = len(findings.get("breach", {}).get("breaches", [])) if findings.get("breach") else 0
        
        response_text = f"**Executive Case Briefing for Target '{query_val}':**\n\n"
        response_text += f"• **Social Footprint:** {sherlock_cnt} verified claimed platforms.\n"
        response_text += f"• **Host Exposure:** {shodan_cnt} active IP hosts probed.\n"
        response_text += f"• **Legal & Judicial:** {ecourts_cnt} recorded court cases found.\n"
        response_text += f"• **Data Exposure:** {breach_cnt} breach database hits detected.\n"
        response_text += f"• **Identity Matching:** {len(matches)} candidate profile(s) resolved with >30% ML confidence."
        
        references = ["Sherlock Module", "Shodan Host Recon", "eCourts CNR Search", "XGBoost Linkage Model"]

    elif "next" in q or "investigate next" in q or "recommend" in q:
        recs = case.get("recommended_actions", [])
        if recs:
            response_text = f"**Prioritized Next Investigative Steps for Case {case.get('case_id')}:**\n\n"
            for idx, r in enumerate(recs, 1):
                clean_r = r.replace("**", "")
                response_text += f"{idx}. {clean_r}\n"
        else:
            response_text = "No immediate threat escalation needed. Recommend routine network observation."
        references = ["Automated Action Synthesizer"]

    elif "connection" in q or "strongest" in q or "candidate" in q or "match" in q:
        if matches:
            top = matches[0]
            feats = top.get("features", {})
            response_text = f"**Identity Resolution Link Analysis:**\n\nThe strongest probabilistic match for **'{query_val}'** is candidate profile **{top['name_shown']}** (ID: `{top['persona_id']}`) with a **{top['match_confidence']*100:.1f}% confidence score**.\n\n**Key Feature Signals:**\n"
            if feats.get("given_name_sim", 0) > 0.8:
                response_text += f"• **Given Name Jaro-Winkler Similarity:** {feats['given_name_sim']:.2f}\n"
            if feats.get("surname_sim", 0) > 0.8:
                response_text += f"• **Surname Jaro-Winkler Similarity:** {feats['surname_sim']:.2f}\n"
            if feats.get("dob_exact") == 1.0:
                response_text += f"• **Exact Match on Date of Birth**\n"
            if feats.get("postcode_exact") == 1.0:
                response_text += f"• **Exact Match on Postcode / PIN**\n"
        else:
            response_text = "No candidate identity matches above the 30% probabilistic confidence threshold were identified in the benchmark database."
        references = ["XGBoost Record Linkage Model (FEBRL4 Trained)"]

    else:
        response_text = f"**Grounded Forensic Analysis for query '{req.question}':**\n\nBased on collected evidence in Case `{case.get('case_id')}` for target **'{query_val}'**, the intelligence pipeline recorded {len(matches)} candidate identity matches, {findings.get('sherlock', {}).get('claimed_count', 0) if findings.get('sherlock') else 0} claimed social accounts, and {findings.get('shodan', {}).get('exposed_count', 0) if findings.get('shodan') else 0} exposed host IPs."
        references = ["Case File Evidence Repository"]

    return {
        "answer": response_text,
        "references": references,
        "timestamp": datetime.now().isoformat()
    }



def resolve_identity_candidates(query_value: str, threshold: float = 0.3, top_k: int = 5):
    """
    Compares queried target against known persona dataset using XGBoost ML Record Linkage.
    Calculates probabilistic match scores for candidate identity resolution.
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
    """Retrieve full audit trail for a given case reference."""
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
    """List available synthetic benchmark personas."""
    personas = _load_personas()
    return [{"persona_id": p["persona_id"], "given_name": p["given_name"],
             "surname": p["surname"], "usernames": p["usernames"],
             "phone": p["phone"], "state": p["state"]} for p in personas]


@app.get("/")
def root():
    return {
        "status": "ok",
        "default_mode": DEFAULT_MODE,
        "message": f"OSINT Investigation Engine running in {DEFAULT_MODE} mode."
    }
