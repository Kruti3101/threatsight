"""
ThreatSight — Module 5: Terminal Dashboard
===========================================
Live terminal dashboard using only stdlib.
Shows real-time stats, threat feed, and kill chain.

Author: Krutika Jagdale
"""

import os, time
from datetime import datetime, timezone

RISK_ICONS = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","none":"⚪"}
CATEGORY_ICONS = {
    "AI Security":"🤖","Network Security":"🌐","System Security":"🖥️",
    "Web Security":"🕸️","Malware":"🦠","Persistence":"🪤",
    "Evasion":"🥷","Discovery":"🔍","None":"✅",
}

def _clear():
    os.system("cls" if os.name == "nt" else "clear")

def _bar(value, total, width=20, fill="█", empty="░"):
    if total == 0:
        return empty * width
    filled = int(width * value / total)
    return fill * filled + empty * (width - filled)

def _center(text, width=72):
    return text.center(width)

def print_dashboard(findings, correlation, stats, mode="static"):
    """
    Print a terminal dashboard.
    mode='static'  → print once and return
    mode='live'    → clear and reprint (for use in loops)
    """
    if mode == "live":
        _clear()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    anomalous = [f for f in findings if f.get("is_anomalous")]
    total = stats["total"]
    n_bad = stats["anomalous"]

    W = 72
    print("=" * W)
    print(_center("🛡️  ThreatSight v2.0 — Security Operations Dashboard", W))
    print(_center(f"Author: Krutika Jagdale  |  {now}", W))
    print("=" * W)

    # ── Summary bar ──────────────────────────────────────────────────────────
    pct = (n_bad / total * 100) if total else 0
    print(f"\n  EVENTS ANALYZED   : {total}")
    print(f"  THREATS DETECTED  : {n_bad}  ({pct:.0f}%)")
    print(f"  THREAT BAR        : [{_bar(n_bad, total)}] {pct:.0f}%")
    print(f"  CLEAN EVENTS      : {stats['clean']}")

    # ── Risk breakdown ────────────────────────────────────────────────────────
    print(f"\n  {'─'*66}")
    print(f"  RISK BREAKDOWN")
    print(f"  {'─'*66}")
    for lvl in ["critical","high","medium","low"]:
        count = stats.get("by_risk",{}).get(lvl,0)
        bar = _bar(count, n_bad if n_bad else 1, width=15)
        icon = RISK_ICONS.get(lvl,"•")
        print(f"  {icon} {lvl.upper():<10} [{bar}] {count}")

    # ── Category breakdown ────────────────────────────────────────────────────
    print(f"\n  {'─'*66}")
    print(f"  ATTACK CATEGORIES")
    print(f"  {'─'*66}")
    for cat, count in sorted(stats.get("by_category",{}).items(), key=lambda x: x[1], reverse=True):
        icon = CATEGORY_ICONS.get(cat,"•")
        bar = _bar(count, n_bad if n_bad else 1, width=12)
        print(f"  {icon} {cat:<25} [{bar}] {count}")

    # ── Top MITRE techniques ──────────────────────────────────────────────────
    print(f"\n  {'─'*66}")
    print(f"  TOP MITRE ATT&CK TECHNIQUES")
    print(f"  {'─'*66}")
    top = stats.get("top_techniques",{})
    if top:
        for tech, count in list(top.items())[:5]:
            print(f"  ⚡ {tech:<12} — {count} event(s)")
    else:
        print("  No techniques detected.")

    # ── Kill chain ────────────────────────────────────────────────────────────
    kc = correlation.get("kill_chain",[])
    if kc:
        print(f"\n  {'─'*66}")
        print(f"  🔗 KILL CHAIN RECONSTRUCTION")
        print(f"  {'─'*66}")
        chain_str = " → ".join(f"[{s['step']}]{s['tactic']}" for s in kc)
        # Word-wrap the chain
        words = chain_str.split(" ")
        line = "  "
        for w in words:
            if len(line) + len(w) > W - 2:
                print(line)
                line = "  " + w + " "
            else:
                line += w + " "
        if line.strip():
            print(line)

    # ── Campaign alert ────────────────────────────────────────────────────────
    campaign = correlation.get("campaign")
    if campaign and campaign.get("detected"):
        print(f"\n  {'─'*66}")
        conf = campaign.get('confidence','').upper()
        print(f"  ⚠️  CAMPAIGN DETECTED ({conf} CONFIDENCE)")
        print(f"  {campaign.get('description','')}")
        print(f"  ➜  {campaign.get('recommendation','')}")

    # ── Recent threats ────────────────────────────────────────────────────────
    print(f"\n  {'─'*66}")
    print(f"  RECENT THREATS (latest 5)")
    print(f"  {'─'*66}")
    for f in anomalous[-5:]:
        icon = RISK_ICONS.get(f.get("risk_level","none"),"•")
        print(f"  {icon} [{f.get('risk_level','?').upper():<8}] {f.get('attack_type','?'):<30} {f.get('source_ip','')}")

    # ── IP clusters ───────────────────────────────────────────────────────────
    clusters = correlation.get("ip_clusters",[])
    if clusters:
        print(f"\n  {'─'*66}")
        print(f"  🎯 IP THREAT CLUSTERS")
        print(f"  {'─'*66}")
        for c in clusters[:3]:
            print(f"  IP: {c['source_ip']:<18} Events: {c['event_count']}  Risk: {c['risk'].upper()}")

    print("\n" + "=" * W)
    print(_center("ThreatSight | End-to-End Cybersecurity Detection Platform", W))
    print("=" * W + "\n")


def print_progress(current, total, label="Analyzing"):
    """Simple progress indicator for batch processing."""
    pct = int(current / total * 100) if total else 0
    bar = _bar(current, total, width=30)
    print(f"\r  {label}: [{bar}] {pct}% ({current}/{total})", end="", flush=True)
    if current == total:
        print()
