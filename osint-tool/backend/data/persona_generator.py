"""
Synthetic Persona Generator
============================
Generates realistic-but-fake Indian personas for demo purposes.

IMPORTANT: No real individuals' data is used. This exists specifically
because live OSINT lookups on real people require case-authorized access
under DPDP Act Section 17(1)(c) -- which a hackathon demo cannot provide.

Uses Faker's en_IN locale (real Indian name/address distributions, not
real individuals) to keep personas statistically realistic.
"""

import random
import json
from faker import Faker
from datetime import datetime, timedelta

fake = Faker("en_IN")
Faker.seed(42)
random.seed(42)

INDIAN_STATES = ["Maharashtra", "Delhi", "Karnataka", "Tamil Nadu", "West Bengal",
                  "Uttar Pradesh", "Gujarat", "Rajasthan", "Telangana", "Kerala"]

CASE_CATEGORIES = ["Cybercrime - Financial Fraud", "Cybercrime - Identity Theft",
                    "Missing Person", "Narcotics", "Cyberstalking",
                    "Online Harassment", "Counterfeit Goods Sale"]

SOCIAL_PLATFORMS = ["Instagram", "Twitter/X", "Facebook", "Telegram", "LinkedIn"]


def _username_variants(given_name, surname):
    """Generate realistic username variants a person might use across platforms."""
    g, s = given_name.lower(), surname.lower()
    variants = [
        f"{g}_{s}{random.randint(10,99)}",
        f"{g}.{s}",
        f"{g[0]}{s}",
        f"{s}_{g}",
        f"{g}{random.randint(1980,2005)}",
    ]
    return variants


def generate_persona(persona_id: int, make_ambiguous: bool = False, twin_of: dict = None):
    """
    Generate one synthetic persona record.
    If twin_of is given, creates a 'hard case' -- a record that's a genuine
    identity match to twin_of but with realistic real-world noise (nickname,
    different platform formatting, minor data entry variation) so the
    entity-resolution model has something non-trivial to resolve.
    """
    if twin_of:
        given_name = twin_of["given_name"]
        surname = twin_of["surname"]
        dob = twin_of["date_of_birth"]
        state = twin_of["state"]
        postcode = twin_of["postcode"]
        # introduce realistic noise
        street_number = str(int(twin_of["street_number"]) + random.choice([0, 0, 1]))
        suburb = twin_of["suburb"] if random.random() > 0.3 else fake.city()
    else:
        given_name = fake.first_name()
        surname = fake.last_name()
        dob = fake.date_of_birth(minimum_age=18, maximum_age=55).strftime("%Y%m%d")
        state = random.choice(INDIAN_STATES)
        postcode = fake.postcode()
        street_number = str(random.randint(1, 999))
        suburb = fake.city()

    soc_sec_id = str(random.randint(1000000, 9999999))  # mock ID, NOT real Aadhaar format on purpose

    persona = {
        "persona_id": f"SIM-{persona_id:04d}",
        "given_name": given_name,
        "surname": surname,
        "street_number": street_number,
        "suburb": suburb,
        "state": state,
        "postcode": postcode,
        "date_of_birth": dob,
        "soc_sec_id": soc_sec_id,
        "phone": f"+91-{random.randint(70000,99999)}{random.randint(10000,99999)}",
        "usernames": _username_variants(given_name, surname),
        "platforms_present": random.sample(SOCIAL_PLATFORMS, k=random.randint(1, 4)),
    }
    return persona


def generate_dataset(n_base_personas=40, n_hard_cases=6, out_path="synthetic_personas.json"):
    """
    Generate a full demo dataset: base personas + deliberately ambiguous
    'hard case' duplicates for the entity-resolution demo to shine on.
    """
    personas = []
    for i in range(n_base_personas):
        personas.append(generate_persona(i))

    # add hard cases: same real person appearing with noisy variants
    hard_case_pairs = []
    for j in range(n_hard_cases):
        base = random.choice(personas)
        twin = generate_persona(n_base_personas + j, twin_of=base)
        personas.append(twin)
        hard_case_pairs.append((base["persona_id"], twin["persona_id"]))

    dataset = {
        "generated_at": datetime.now().isoformat(),
        "personas": personas,
        "known_duplicate_pairs": hard_case_pairs,  # ground truth for demo validation
    }

    with open(out_path, "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"Generated {len(personas)} personas ({n_hard_cases} deliberate identity-match hard cases)")
    print(f"Saved to {out_path}")
    return dataset


if __name__ == "__main__":
    generate_dataset()
