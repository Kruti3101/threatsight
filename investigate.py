"""
ThreatSight — Module 3: Investigate & Correlate
=================================================
Enriches findings with:
  - IP reputation (offline lookup + threat intel feeds)
  - Event correlation (kill chain chaining, IP clustering)
  - Attack campaign detection
  - Timeline reconstruction

Author: Krutika Jagdale
"""

import re
from collections import defaultdict
from datetime import datetime

# ── Known malicious IP ranges (offline, no API needed) ──────────────────────
# In production: integrate with AbuseIPDB, VirusTotal, Shodan APIs
KNOWN_MALICIOUS_RANGES = [
    "203.0.113.",   # TEST-NET-3 (RFC 5737) - used in samples as attacker IPs
    "198.51.100.",  # TEST-NET-2
]

KNOWN_TOR_EXIT_PATTERN = re.compile(r"^(185\.220\.|199\.249\.|176\.10\.)")
KNOWN_CLOUD_PROVIDERS  = ["amazonaws.com", "azure.com", "googlecloud.com"]

def check_ip_reputation(ip: str) -> dict:
    """
    Offline IP reputation check.
    Returns a reputation dict. In production, extend with API calls.
    """
    rep = {
        "ip": ip,
        "is_malicious": False,
        "is_tor": False,
        "is_internal": False,
        "threat_category": None,
        "confidence": "low",
        "source": "offline_heuristic",
    }
    if not ip or ip == "0.0.0.0":
        return rep

    # Internal RFC 1918
    if re.match(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", ip):
        rep["is_internal"] = True
        return rep

    # TOR exit nodes (heuristic)
    if KNOWN_TOR_EXIT_PATTERN.match(ip):
        rep["is_tor"] = True
        rep["is_malicious"] = True
        rep["threat_category"] = "TOR Exit Node"
        rep["confidence"] = "medium"

    # Known malicious ranges
    for rng in KNOWN_MALICIOUS_RANGES:
        if ip.startswith(rng):
            rep["is_malicious"] = True
            rep["threat_category"] = "Known Threat Range (Sample)"
            rep["confidence"] = "high"

    return rep


def correlate_findings(findings: list) -> dict:
    """
    Correlate individual findings into:
    - IP clusters (same IP attacking multiple targets)
    - User compromises (same user, multiple attack types)
    - Kill chain sequences (ordered ATT&CK progression)
    - Campaign detection (coordinated multi-source attacks)
    """
    anomalous = [f for f in findings if f.get("is_anomalous")]

    # ── IP clustering ────────────────────────────────────────────────────────
    ip_activity = defaultdict(list)
    for f in anomalous:
        ip = f.get("source_ip","0.0.0.0")
        ip_activity[ip].append(f)

    ip_clusters = []
    for ip, events in ip_activity.items():
        if len(events) >= 2:
            attack_types = list({e["attack_type"] for e in events})
            ip_clusters.append({
                "source_ip": ip,
                "event_count": len(events),
                "attack_types": attack_types,
                "risk": "critical" if len(attack_types) >= 3 else "high",
                "assessment": f"IP {ip} triggered {len(events)} alerts across {len(attack_types)} attack type(s). Likely automated threat actor.",
            })

    # ── User compromise indicators ───────────────────────────────────────────
    user_activity = defaultdict(list)
    for f in anomalous:
        user = f.get("user","unknown")
        if user not in ("unknown","anonymous","root"):
            user_activity[user].append(f)

    user_risks = []
    for user, events in user_activity.items():
        cats = list({e.get("category","") for e in events})
        if len(cats) >= 2:
            user_risks.append({
                "user": user,
                "event_count": len(events),
                "categories": cats,
                "assessment": f"User '{user}' appears in {len(events)} alerts across categories: {', '.join(cats)}. Possible account compromise.",
            })

    # ── Kill chain reconstruction ─────────────────────────────────────────────
    # MITRE ATT&CK tactic ordering
    TACTIC_ORDER = {
        "Reconnaissance":       1,
        "Discovery":            2,
        "Initial Access":       3,
        "Execution":            4,
        "Persistence":          5,
        "Privilege Escalation": 6,
        "Defense Evasion":      7,
        "Credential Access":    8,
        "Lateral Movement":     9,
        "Collection":          10,
        "Exfiltration":        11,
        "Command and Control": 12,
    }
    CATEGORY_TO_TACTIC = {
        "Discovery":    "Discovery",
        "Web Security": "Initial Access",
        "AI Security":  "Execution",
        "Malware":      "Execution",
        "Persistence":  "Persistence",
        "System Security": "Privilege Escalation",
        "Evasion":      "Defense Evasion",
        "Network Security": "Lateral Movement",
    }
    kill_chain = []
    seen_tactics = set()
    for f in sorted(anomalous, key=lambda x: x.get("timestamp","")):
        cat = f.get("category","")
        tactic = CATEGORY_TO_TACTIC.get(cat)
        if tactic and tactic not in seen_tactics:
            seen_tactics.add(tactic)
            kill_chain.append({
                "step": TACTIC_ORDER.get(tactic, 99),
                "tactic": tactic,
                "event_id": f.get("query_id"),
                "attack_type": f.get("attack_type"),
                "timestamp": f.get("timestamp",""),
            })
    kill_chain.sort(key=lambda x: x["step"])

    # ── Campaign assessment ──────────────────────────────────────────────────
    unique_ips = len({f.get("source_ip") for f in anomalous})
    unique_attacks = len({f.get("attack_type") for f in anomalous})
    campaign = None
    if unique_ips >= 3 and unique_attacks >= 3:
        campaign = {
            "detected": True,
            "confidence": "high",
            "description": f"Coordinated attack campaign detected: {unique_ips} source IPs, {unique_attacks} distinct attack types.",
            "recommendation": "Activate IR playbook. Isolate affected systems. Notify CISO.",
        }
    elif unique_ips >= 2 or unique_attacks >= 4:
        campaign = {
            "detected": True,
            "confidence": "medium",
            "description": f"Possible coordinated activity: {unique_ips} source IPs, {unique_attacks} attack types.",
            "recommendation": "Increase monitoring. Correlate with threat intel feeds.",
        }

    return {
        "ip_clusters": ip_clusters,
        "user_risks": user_risks,
        "kill_chain": kill_chain,
        "campaign": campaign,
        "summary": {
            "unique_attacker_ips": unique_ips,
            "unique_attack_types": unique_attacks,
            "kill_chain_steps_observed": len(kill_chain),
            "compromised_users": len(user_risks),
        }
    }


def enrich_findings(findings: list) -> list:
    """Add IP reputation and correlation data to each finding."""
    enriched = []
    for f in findings:
        f["ip_reputation"] = check_ip_reputation(f.get("source_ip",""))
        enriched.append(f)
    return enriched
