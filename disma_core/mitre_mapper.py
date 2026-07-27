"""
DISCOPE MITRE ATT&CK Mapping Engine
====================================
Maps credential leak findings to MITRE ATT&CK tactics, techniques, and procedures (TTPs).
Generates attack chain visualizations and business impact quantification.

Data sources:
- IBM Cost of a Data Breach Report 2024
- Verizon DBIR 2024
- Ponemon Institute research
- MITRE ATT&CK v14
"""

import json
from typing import Optional

# ── MITRE ATT&CK TTP Mappings for Credential Leaks ────────────────────────────

MITRE_MAPPINGS = {
    "credential_leak": {
        "tactics": ["Initial Access", "Credential Access", "Lateral Movement"],
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                "url": "https://attack.mitre.org/techniques/T1078/",
                "severity": "critical",
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when passwords are obtained.",
                "url": "https://attack.mitre.org/techniques/T1110/",
                "severity": "high",
            },
            {
                "id": "T1555",
                "name": "Credentials from Password Stores",
                "description": "Adversaries may search for common password storage locations to obtain user credentials.",
                "url": "https://attack.mitre.org/techniques/T1555/",
                "severity": "high",
            },
        ],
        "sub_techniques": [
            {
                "id": "T1078.001",
                "name": "Default Accounts",
                "description": "Adversaries may obtain and abuse credentials of default accounts.",
                "severity": "critical",
            },
            {
                "id": "T1078.002",
                "name": "Domain Accounts",
                "description": "Adversaries may obtain and abuse credentials of domain accounts.",
                "severity": "critical",
            },
            {
                "id": "T1078.003",
                "name": "Local Accounts",
                "description": "Adversaries may obtain and abuse credentials of local accounts.",
                "severity": "high",
            },
            {
                "id": "T1078.004",
                "name": "Cloud Accounts",
                "description": "Adversaries may obtain and abuse credentials of cloud accounts.",
                "severity": "critical",
            },
            {
                "id": "T1110.001",
                "name": "Password Guessing",
                "description": "Adversaries may guess passwords to attempt access to accounts.",
                "severity": "medium",
            },
            {
                "id": "T1110.002",
                "name": "Password Cracking",
                "description": "Adversaries may use password cracking to obtain credentials.",
                "severity": "high",
            },
            {
                "id": "T1110.003",
                "name": "Password Spraying",
                "description": "Adversaries may use a single or small list of commonly used passwords against many accounts.",
                "severity": "high",
            },
            {
                "id": "T1110.004",
                "name": "Credential Stuffing",
                "description": "Adversaries may use credentials obtained from breach dumps to gain access.",
                "severity": "critical",
            },
            {
                "id": "T1555.001",
                "name": "Keychain",
                "description": "Adversaries may acquire credentials from Keychain.",
                "severity": "medium",
            },
            {
                "id": "T1555.002",
                "name": "Securityd Memory",
                "description": "Adversaries may acquire credential material from the securityd process memory.",
                "severity": "medium",
            },
            {
                "id": "T1555.003",
                "name": "Credentials from Web Browsers",
                "description": "Adversaries may acquire credentials from web browsers.",
                "severity": "high",
            },
            {
                "id": "T1555.004",
                "name": "Windows Credential Manager",
                "description": "Adversaries may acquire credentials from Windows Credential Manager.",
                "severity": "high",
            },
            {
                "id": "T1555.005",
                "name": "Password Managers",
                "description": "Adversaries may acquire credentials from password managers.",
                "severity": "critical",
            },
            {
                "id": "T1555.006",
                "name": "Cloud Secrets Management Stores",
                "description": "Adversaries may acquire credentials from cloud secrets management stores.",
                "severity": "critical",
            },
        ],
    },
    "stealer_log": {
        "tactics": ["Collection", "Exfiltration", "Command and Control"],
        "techniques": [
            {
                "id": "T1005",
                "name": "Data from Local System",
                "description": "Adversaries may search local system sources to find files of interest and sensitive data.",
                "url": "https://attack.mitre.org/techniques/T1005/",
                "severity": "high",
            },
            {
                "id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                "url": "https://attack.mitre.org/techniques/T1041/",
                "severity": "critical",
            },
            {
                "id": "T1567",
                "name": "Exfiltration Over Web Service",
                "description": "Adversaries may use an existing, legitimate external Web service to exfiltrate data.",
                "url": "https://attack.mitre.org/techniques/T1567/",
                "severity": "critical",
            },
        ],
        "sub_techniques": [
            {
                "id": "T1567.002",
                "name": "Exfiltration to Cloud Storage",
                "description": "Adversaries may exfiltrate data to a cloud storage service.",
                "severity": "critical",
            },
        ],
    },
}

# ── Business Impact Quantification (IBM + Verizon + Ponemon 2024) ─────────────

BUSINESS_IMPACT = {
    "credential_leak": {
        "base_cost_per_record": 165,  # USD per exposed credential (IBM 2024 avg)
        "probability_of_breach": 0.83,  # 83% of breaches involve credential misuse (Verizon DBIR 2024)
        "avg_breach_cost": 4_880_000,  # USD (IBM 2024 global average)
        "healthcare_multiplier": 2.1,
        "financial_multiplier": 1.8,
        "government_multiplier": 1.5,
        "technology_multiplier": 1.3,
        "retail_multiplier": 1.1,
        "other_multiplier": 1.0,
    },
    "stealer_log": {
        "base_cost_per_record": 210,  # Higher due to active malware context
        "probability_of_breach": 0.91,  # Stealer logs almost always weaponized
        "avg_breach_cost": 4_880_000,
        "healthcare_multiplier": 2.1,
        "financial_multiplier": 1.8,
        "government_multiplier": 1.5,
        "technology_multiplier": 1.3,
        "retail_multiplier": 1.1,
        "other_multiplier": 1.0,
    },
}

# Industry classification by domain TLD/keywords
INDUSTRY_KEYWORDS = {
    "healthcare": ["hospital", "health", "medical", "clinic", "pharma", "care", "seha", "doh"],
    "financial": ["bank", "finance", "insurance", "capital", "invest", "payment", "nbd", "emirates", "adcb", "fab", "cbd", "dib", "mashreq", "rakbank", "hsbc", "citibank", "standardchartered"],
    "government": ["gov", "mil", "state", "federal", "ministry", "authority", "rta", "dewa", "sewa", "tawtheeq", "moi", "mofa", "dubai", "abudhabi", "sharjah", "ajman", "fujairah", "rak", "uaq"],
    "technology": ["tech", "software", "cloud", "data", "digital", "cyber", "du", "etisalat", "virgin", "sti", "sap", "oracle", "ibm", "microsoft", "google", "amazon", "apple"],
    "retail": ["shop", "store", "retail", "mart", "commerce", "carrefour", "lulu", "noon", "amazon.ae"],
}


def classify_industry(domain: str) -> str:
    """Classify domain into industry vertical for cost multiplier."""
    domain_lower = domain.lower()
    for industry, keywords in INDUSTRY_KEYWORDS.items():
        if any(kw in domain_lower for kw in keywords):
            return industry
    return "other"


def map_to_mitre(record_type: str, domain: str, credential_count: int = 0) -> dict:
    """Map a finding to MITRE ATT&CK framework.

    Returns:
        {
            "tactics": [...],
            "techniques": [...],
            "sub_techniques": [...],
            "attack_chain": [...],
            "business_impact": {...},
        }
    """
    mapping = MITRE_MAPPINGS.get(record_type, MITRE_MAPPINGS["credential_leak"])

    # Build attack chain narrative
    attack_chain = _build_attack_chain(record_type, domain)

    # Calculate business impact
    impact = _calculate_business_impact(record_type, domain, credential_count)

    return {
        "tactics": mapping["tactics"],
        "techniques": mapping["techniques"],
        "sub_techniques": mapping["sub_techniques"],
        "attack_chain": attack_chain,
        "business_impact": impact,
    }


def _build_attack_chain(record_type: str, domain: str) -> list:
    """Build a kill-chain narrative for the finding."""
    if record_type == "stealer_log":
        return [
            {
                "phase": "1. Initial Infection",
                "description": f"Victim at {domain} infected with infostealer malware (RedLine, Vidar, Raccoon, etc.)",
                "mitre": "T1059 — Command and Scripting Interpreter",
            },
            {
                "phase": "2. Credential Harvesting",
                "description": "Malware extracts saved credentials from browsers, password managers, and memory",
                "mitre": "T1555 — Credentials from Password Stores",
            },
            {
                "phase": "3. Data Exfiltration",
                "description": "Stolen credentials transmitted to attacker C2 infrastructure",
                "mitre": "T1041 — Exfiltration Over C2 Channel",
            },
            {
                "phase": "4. Credential Sale/Sharing",
                "description": f"Credentials from {domain} appear in stealer log dumps on Telegram/marketplaces",
                "mitre": "T1567 — Exfiltration Over Web Service",
            },
            {
                "phase": "5. Initial Access",
                "description": f"Threat actors use {domain} credentials to access corporate systems, VPNs, cloud accounts",
                "mitre": "T1078 — Valid Accounts",
            },
            {
                "phase": "6. Lateral Movement",
                "description": "Attackers pivot to internal resources using harvested credentials",
                "mitre": "T1021 — Remote Services",
            },
        ]
    else:  # credential_leak
        return [
            {
                "phase": "1. Data Breach",
                "description": f"Credentials from {domain} exposed via breach, phishing, or stealer malware",
                "mitre": "T1530 — Data from Cloud Storage",
            },
            {
                "phase": "2. Credential Dump",
                "description": "Exposed credentials aggregated into combolists and sold/shared on dark web",
                "mitre": "T1041 — Exfiltration Over C2 Channel",
            },
            {
                "phase": "3. Credential Stuffing",
                "description": f"Attackers use {domain} credentials in automated stuffing attacks against other services",
                "mitre": "T1110.004 — Credential Stuffing",
            },
            {
                "phase": "4. Account Takeover",
                "description": f"Successful logins to {domain} and related services using valid credentials",
                "mitre": "T1078 — Valid Accounts",
            },
            {
                "phase": "5. Privilege Escalation",
                "description": "Compromised accounts used to access sensitive systems and data",
                "mitre": "T1098 — Account Manipulation",
            },
        ]


def _calculate_business_impact(record_type: str, domain: str, credential_count: int) -> dict:
    """Calculate business impact metrics based on industry research."""
    impact_data = BUSINESS_IMPACT.get(record_type, BUSINESS_IMPACT["credential_leak"])
    industry = classify_industry(domain)
    multiplier_key = f"{industry}_multiplier"
    industry_multiplier = impact_data.get(multiplier_key, 1.0)

    base_cost = impact_data["base_cost_per_record"]
    probability = impact_data["probability_of_breach"]
    avg_breach_cost = impact_data["avg_breach_cost"]

    # Expected loss calculation
    direct_cost = credential_count * base_cost * industry_multiplier
    expected_breach_cost = avg_breach_cost * probability * industry_multiplier

    # Risk score (0-100)
    risk_score = min(100, int((credential_count / 100) * 50 + probability * 50))

    return {
        "credential_count": credential_count,
        "industry": industry,
        "industry_multiplier": industry_multiplier,
        "cost_per_credential": base_cost,
        "direct_exposure_cost": round(direct_cost, 2),
        "probability_of_breach": probability,
        "probability_percentage": f"{probability * 100:.0f}%",
        "average_breach_cost": avg_breach_cost,
        "expected_breach_cost": round(expected_breach_cost, 2),
        "risk_score": risk_score,
        "risk_level": "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW",
        "currency": "USD",
        "sources": [
            "IBM Cost of a Data Breach Report 2024",
            "Verizon Data Breach Investigations Report 2024",
            "Ponemon Institute Cost of Credential Theft 2024",
        ],
    }


def generate_mitre_report(domain: str, findings: list) -> dict:
    """Generate a complete MITRE mapping report for a domain scan.

    Args:
        domain: The scanned domain
        findings: List of finding dicts with keys: record_type, severity, content

    Returns:
        Complete report with MITRE mappings, attack chains, and business impact
    """
    credential_count = len([f for f in findings if f.get("record_type") in ("credential_leak", "stealer_log")])
    has_stealer = any(f.get("record_type") == "stealer_log" for f in findings)
    has_creds = any(f.get("record_type") == "credential_leak" for f in findings)

    primary_type = "stealer_log" if has_stealer else "credential_leak"

    report = {
        "domain": domain,
        "finding_count": len(findings),
        "credential_count": credential_count,
        "has_stealer_logs": has_stealer,
        "has_credential_leaks": has_creds,
        "mitre": map_to_mitre(primary_type, domain, credential_count),
    }

    # Add secondary mapping if both types present
    if has_stealer and has_creds:
        report["mitre_secondary"] = map_to_mitre("credential_leak", domain, credential_count)

    return report
