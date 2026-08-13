"""
Mock Data Source Adapters
===========================
Return responses shaped exactly like the real APIs would, but sourced
from our synthetic persona dataset instead of live queries.

Swapping these for real adapters later is a drop-in replacement —
the rest of the pipeline doesn't change.
"""

import json
import os
import random
import hashlib
from datetime import datetime

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_personas.json")

# Stable random: seed from identifier so results are consistent per query
def _rng(seed_str: str) -> random.Random:
    h = int(hashlib.md5(seed_str.encode()).hexdigest(), 16) % (2**32)
    return random.Random(h)


def _load_personas():
    with open(DATA_PATH) as f:
        return json.load(f)["personas"]


# ── IPC taxonomy (NCRB distribution) ───────────────────────────────────────
IPC_CODES = [
    ("IPC-379", "Theft"),
    ("IPC-420", "Cheating / Fraud"),
    ("IPC-66C", "Cyber Fraud / Identity Theft"),
    ("IPC-406", "Criminal Breach of Trust"),
    ("IPC-302", "Murder"),
    ("IPC-498A", "Cruelty by Husband/Relatives"),
    ("NDPS-22", "Narcotic Drugs (NDPS Act)"),
    ("IPC-376", "Rape"),
    ("IPC-307", "Attempt to Murder"),
    ("IPC-323", "Voluntarily Causing Hurt"),
]

COURTS = [
    "Patna District Court", "Bengaluru City Civil Court",
    "Chennai Metropolitan Magistrate", "Mumbai Sessions Court",
    "Delhi District Court", "Hyderabad District Court",
    "Kolkata City Sessions Court", "Ahmedabad District Court",
    "Jaipur Sessions Court", "Lucknow District Court",
]

ISPS = ["Jio", "Airtel", "BSNL", "Vodafone Idea", "ACT Fibernet", "Tata Communications"]
OS_LIST  = ["Linux 5.x", "Windows Server 2019", "Ubuntu 22.04", "FreeBSD 13", "CentOS 7"]
PORT_POOLS = [22, 80, 443, 3306, 8080, 8443, 21, 25, 587, 3389, 5432, 6379]
BREACH_DB = [
    ("TechForum_2023", ["username", "email", "password_hash"]),
    ("IndianJobPortal_2022", ["phone", "name", "resume_data"]),
    ("ECommerceLeakIN_2024", ["phone", "address", "order_history"]),
    ("TelecomDump_2021", ["phone", "IMEI", "location_history"]),
    ("HealthApp_2023", ["phone", "medical_records", "aadhaar_masked"]),
    ("SocialNetworkIN_2022", ["username", "email", "profile_photo"]),
]


# ─────────────────────────────────────────────────────────────────────────────
# SHERLOCK
# ─────────────────────────────────────────────────────────────────────────────
ALL_PLATFORMS = ["LinkedIn", "Instagram", "Twitter/X", "Facebook", "Telegram",
                 "GitHub", "Reddit", "Snapchat", "Pinterest", "YouTube"]

def sherlock_adapter(username: str):
    """
    Mimics Sherlock output: which platforms the username is found on.
    Returns claimed (confirmed found) vs available (not found) status.
    Generates dynamic platforms if username is not in persona database.
    """
    personas = _load_personas()
    rng = _rng(username)
    matches = [p for p in personas if username.lower() in [u.lower() for u in p["usernames"]]]

    if matches:
        persona = matches[0]
        claimed = set(persona["platforms_present"])
        persona_id = persona["persona_id"]
    else:
        # Dynamic generator for custom/arbitrary queries
        n_claimed = rng.randint(2, 5)
        claimed = set(rng.sample(ALL_PLATFORMS, n_claimed))
        persona_id = f"PER-GEN-{abs(hash(username))%10000:04d}"

    checked = list(claimed)
    extras = [p for p in ALL_PLATFORMS if p not in claimed]
    rng.shuffle(extras)
    checked += extras[:max(2, 6 - len(claimed))]

    platforms = []
    for plat in checked:
        slug = plat.lower().replace("/", "").replace(" ", "")
        is_claimed = plat in claimed
        platforms.append({
            "platform": plat,
            "username": username if is_claimed else "",
            "url": f"https://{slug}.com/{username}" if is_claimed else None,
            "status": "claimed" if is_claimed else "available",
        })

    platforms.sort(key=lambda x: x["status"])  # claimed first

    claimed_count = sum(1 for p in platforms if p["status"] == "claimed")
    return {
        "username": username,
        "found_on": [p for p in platforms if p["status"] == "claimed"],
        "platforms": platforms,
        "claimed_count": claimed_count,
        "total_checked": len(platforms),
        "linked_persona_id": persona_id,
        "source": "sherlock_mock",
        "queried_at": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ECOURTS
# ─────────────────────────────────────────────────────────────────────────────
def ecourts_adapter(name: str, state: str = None):
    """
    Mimics eCourts case-lookup with IPC codes, court names, year, status.
    Generates dynamic cases for arbitrary search names.
    """
    personas = _load_personas()
    matches = [p for p in personas if name.lower() in f"{p['given_name']} {p['surname']}".lower()]
    if state:
        matches = [p for p in matches if p["state"] == state]

    results = []

    if matches:
        for p in matches:
            rng = _rng(p["persona_id"] + "ecourts")
            if rng.random() > 0.30:
                state_code = p["state"][:2].upper()
                court_code = rng.randint(10, 99)
                case_num   = rng.randint(100000, 999999)
                year       = rng.randint(2019, 2025)
                ipc, desc  = rng.choice(IPC_CODES)
                court      = rng.choice(COURTS)
                case_type  = "Criminal" if ipc.startswith(("IPC", "NDPS")) else "Civil"
                status     = rng.choice(["Pending", "Under Trial", "Disposed", "Acquitted"])
                results.append({
                    "cnr_number": f"{state_code}{court_code}{case_num}{year}",
                    "persona_id": p["persona_id"],
                    "ipc_section": ipc,
                    "offence": desc,
                    "case_type": case_type,
                    "court": court,
                    "year": year,
                    "status": status,
                })
    else:
        # Dynamic court record generation for custom name input
        rng = _rng(name + "ecourts")
        n_cases = rng.randint(1, 2)
        for _ in range(n_cases):
            state_code = rng.choice(["DL", "MH", "KA", "TN", "WB", "UP", "BR"])
            court_code = rng.randint(10, 99)
            case_num   = rng.randint(100000, 999999)
            year       = rng.randint(2020, 2025)
            ipc, desc  = rng.choice(IPC_CODES)
            court      = rng.choice(COURTS)
            case_type  = "Criminal" if ipc.startswith(("IPC", "NDPS")) else "Civil"
            status     = rng.choice(["Pending", "Under Trial", "Disposed"])
            results.append({
                "cnr_number": f"{state_code}{court_code}{case_num}{year}",
                "persona_id": f"PER-GEN-{abs(hash(name))%10000:04d}",
                "ipc_section": ipc,
                "offence": desc,
                "case_type": case_type,
                "court": court,
                "year": year,
                "status": status,
            })

    return {
        "query": name,
        "results": results,
        "filed_count": len(results),
        "source": "ecourts_mock",
        "queried_at": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# SHODAN  (new)
# ─────────────────────────────────────────────────────────────────────────────
def shodan_adapter(identifier: str):
    """
    Mimics Shodan host lookup: IP addresses, ISP, open ports, OS.
    Seeded from identifier so results are deterministic.
    """
    rng = _rng(identifier + "shodan")
    n_hosts = rng.randint(1, 3)

    hosts = []
    for i in range(n_hosts):
        ip = f"{rng.randint(10,200)}.{rng.randint(1,255)}.{rng.randint(1,255)}.{rng.randint(1,255)}"
        isp = rng.choice(ISPS)
        os_  = rng.choice(OS_LIST)
        ports = sorted(rng.sample(PORT_POOLS, rng.randint(2, 4)))
        hosts.append({
            "ip": ip,
            "isp": isp,
            "os": os_,
            "open_ports": ports,
            "last_seen": f"{rng.randint(2023,2025)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
        })

    return {
        "query": identifier,
        "hosts": hosts,
        "exposed_count": len(hosts),
        "source": "shodan_mock",
        "queried_at": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# VIRUSTOTAL  (new)
# ─────────────────────────────────────────────────────────────────────────────
def virustotal_adapter(identifier: str):
    """
    Mimics VirusTotal reputation: harmless / malicious / suspicious / undetected counts.
    """
    rng = _rng(identifier + "vt")
    total = 90
    malicious   = rng.randint(0, 5)
    suspicious  = rng.randint(0, 4)
    undetected  = rng.randint(10, 25)
    harmless    = total - malicious - suspicious - undetected

    verdict = "Clean" if malicious == 0 and suspicious <= 1 else \
              "Suspicious" if malicious <= 2 else "Malicious"

    return {
        "query": identifier,
        "harmless":   harmless,
        "malicious":  malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "total_engines": total,
        "verdict": verdict,
        "source": "virustotal_mock",
        "queried_at": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# BREACH LOOKUP
# ─────────────────────────────────────────────────────────────────────────────
def breach_lookup_adapter(identifier: str):
    """
    Mimics HaveIBeenPwned-style response for phone/email identifiers.
    Generates dynamic breach hits for custom inputs.
    """
    personas = _load_personas()
    matches = [p for p in personas if identifier in (p["phone"], p.get("email", ""))]

    rng = _rng(identifier + "breach")
    n = rng.randint(1, 3)
    chosen = rng.sample(BREACH_DB, min(n, len(BREACH_DB)))
    persona_id = matches[0]["persona_id"] if matches else f"PER-GEN-{abs(hash(identifier))%10000:04d}"

    return {
        "identifier": identifier,
        "breaches": [{"breach_name": b[0], "data_exposed": b[1]} for b in chosen],
        "linked_persona_id": persona_id,
        "source": "breach_lookup_mock",
        "queried_at": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# SPIDERFOOT OSINT RECON  (new)
# ─────────────────────────────────────────────────────────────────────────────
def spiderfoot_adapter(identifier: str):
    """
    Mimics SpiderFoot OSINT Automation Engine output:
    Passive/Active intelligence modules (sfp_whois, sfp_dns, sfp_shodan, sfp_spider).
    """
    rng = _rng(identifier + "spiderfoot")

    modules_run = [
        "sfp_whois (Domain/IP Registrar)",
        "sfp_dns (DNS Records & Subdomains)",
        "sfp_social (Social Footprint)",
        "sfp_threats (Threat Intelligence Feeds)",
        "sfp_leakdb (Data Leak Repositories)"
    ]

    total_data_elements = rng.randint(45, 240)
    high_risk_elements  = rng.randint(0, 5)

    entities_found = [
        {"type": "IP Address", "val": f"{rng.randint(10,200)}.{rng.randint(1,255)}.{rng.randint(1,255)}.{rng.randint(1,255)}", "module": "sfp_dns"},
        {"type": "Domain Name", "val": f"{identifier.lower().replace('+','').replace('-','')}.org", "module": "sfp_whois"},
        {"type": "Email Address", "val": f"{identifier.lower()}@sec-mail.in", "module": "sfp_leakdb"},
        {"type": "Web Server Header", "val": "nginx/1.22.1 (Ubuntu)", "module": "sfp_spider"}
    ]

    return {
        "query": identifier,
        "modules_executed": len(modules_run),
        "data_elements_found": total_data_elements,
        "high_risk_count": high_risk_elements,
        "entities": entities_found,
        "status": "COMPLETED",
        "scan_id": f"SF-{rng.randint(100000, 999999)}",
        "source": "spiderfoot_mock",
        "queried_at": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# RECOMMENDED ACTIONS  (new)
# ─────────────────────────────────────────────────────────────────────────────
def generate_recommendations(findings: dict, matches: list) -> list:
    """
    Produces context-aware recommended next steps based on aggregated findings.
    """
    actions = []
    sherlock   = findings.get("sherlock")
    ecourts    = findings.get("ecourts")
    breach     = findings.get("breach")
    shodan     = findings.get("shodan")
    vt         = findings.get("virustotal")
    spiderfoot = findings.get("spiderfoot")

    if spiderfoot and spiderfoot.get("high_risk_count", 0) > 0:
        actions.append(f"**Review** SpiderFoot OSINT recon alert: {spiderfoot['high_risk_count']} high-risk entity footprint(s) flagged")
    if sherlock and sherlock.get("claimed_count", 0) >= 2:
        actions.append("**Cross-reference** social handles against cybercrime complaint database")
    if vt and vt.get("malicious", 0) > 0:
        actions.append(f"**Audit** open hosts for malicious payload hosting or C2 activity ({vt['malicious']} engines flagged)")
    if shodan and shodan.get("exposed_count", 0) > 0:
        actions.append(f"**Monitor** {shodan['exposed_count']} exposed host(s) for suspicious services or credential exposure")
    if sherlock and sherlock.get("claimed_count", 0) >= 3:
        actions.append("**Flag** social accounts for coordinated inauthentic behaviour patterns")
    if ecourts and ecourts.get("filed_count", 0) > 0:
        cases = ecourts.get("results", [])
        ipcs  = ", ".join(set(c["ipc_section"] for c in cases))
        actions.append(f"**Verify** court records — {ecourts['filed_count']} case(s) found ({ipcs})")
    if breach and breach.get("breaches"):
        actions.append("**Check** breach exposure for credential stuffing risk across linked identifiers")
    if matches and len(matches) > 0:
        actions.append(f"**Investigate** {len(matches)} identity match(es) with >30% confidence for duplicate persona")
    if not actions:
        actions.append("No immediate escalation recommended — continue routine monitoring")

    return actions


if __name__ == "__main__":
    personas = _load_personas()
    sample = personas[0]
    uname = sample["usernames"][0]
    print("Sherlock mock:", json.dumps(sherlock_adapter(uname), indent=2))
    print("\nShodan mock:", json.dumps(shodan_adapter(uname), indent=2))
    print("\nVT mock:", json.dumps(virustotal_adapter(uname), indent=2))
