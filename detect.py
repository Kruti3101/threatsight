"""
ThreatSight — Module 2: Detection Engine
=========================================
Expanded from original threatsight.py.
Adds: Network attack detection, credential attacks,
lateral movement, web attacks, malware patterns.

Author: Krutika Jagdale
"""

import re

MITRE_TECHNIQUES = {
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1071": "Application Layer Protocol Abuse",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1566": "Phishing / Prompt Injection",
    "T1078": "Valid Accounts / Credential Abuse",
    "T1110": "Brute Force",
    "T1110.003": "Password Spraying",
    "T1530": "Data from Cloud Storage",
    "T1552": "Unsecured Credentials",
    "T1602": "Data from Configuration Repository",
    "T1650": "Acquire Access (AI Model Abuse)",
    "T1055": "Process Injection / Jailbreak Escalation",
    "T1021": "Remote Services",
    "T1021.004": "SSH",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task",
    "T1068": "Exploitation for Privilege Escalation",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1136": "Create Account",
    "T1543": "Create or Modify System Process",
    "T1562": "Impair Defenses",
}

DETECTION_CHECKS = [
    # ── AI / LLM attacks ────────────────────────────────────────────────────
    {
        "attack_type": "Prompt Injection",
        "risk_level": "high",
        "mitre_techniques": ["T1566", "T1190"],
        "category": "AI Security",
        "patterns": [
            r"\bignore (all )?(previous|prior|system) instructions\b",
            r"\bdisregard\b.*\binstructions\b",
            r"\boutput\b.*\bsystem prompt\b",
            r"\breveal\b.*\bsystem prompt\b",
            r"\bforget (all )?previous (instructions|context)\b",
        ],
        "rule": "Alert when query text contains instruction override phrases targeting LLM system prompts.",
        "response": "Block the prompt and alert SOC for prompt-injection review.",
        "sigma_title": "LLM Prompt Injection Attempt",
    },
    {
        "attack_type": "Jailbreak Attempt",
        "risk_level": "high",
        "mitre_techniques": ["T1055", "T1650"],
        "category": "AI Security",
        "patterns": [
            r"\bact as DAN\b",
            r"\bdeveloper mode\b",
            r"\bjailbreak\b",
            r"\broleplay\b.*\bno restrictions\b",
            r"\byou are now\b.*\bunrestricted\b",
            r"\bDAN mode\b",
        ],
        "rule": "Alert when query attempts to switch model into unrestricted persona.",
        "response": "Deny request and increase monitoring on source identity.",
        "sigma_title": "LLM Jailbreak Attempt",
    },
    {
        "attack_type": "Data Exfiltration via AI",
        "risk_level": "critical",
        "mitre_techniques": ["T1048", "T1552", "T1602"],
        "category": "AI Security",
        "patterns": [
            r"\b/etc/(passwd|shadow|hosts|sudoers)\b",
            r"\b(api[_-]?key|secret|token|credential|password)\b",
            r"\b(send|upload|exfiltrate|export)\b.*\b(external|http|server|domain)\b",
            r"\btraining data\b|\binternal configuration",
            r"\b\.aws/credentials\b|\b\.ssh/id_rsa\b",
        ],
        "rule": "Alert when AI queries request sensitive files, credentials, or external data transfer.",
        "response": "Block request, preserve prompt log, review session permissions.",
        "sigma_title": "AI-Assisted Data Exfiltration Attempt",
    },
    {
        "attack_type": "Resource Abuse",
        "risk_level": "medium",
        "mitre_techniques": ["T1650"],
        "category": "AI Security",
        "patterns": [
            r"\brepeat\b.*\b([5-9]\d{2,}|\d{4,})\b",
            r"\bloop forever\b",
            r"\bunlimited tokens\b",
            r"\binfinite\b.*\b(loop|repeat|generate)\b",
        ],
        "rule": "Alert when prompts request excessive repetition or unbounded output.",
        "response": "Rate-limit request and review account for automated abuse.",
        "sigma_title": "LLM Resource Exhaustion Attempt",
    },
    # ── Network / Infrastructure attacks ────────────────────────────────────
    {
        "attack_type": "Brute Force / Credential Attack",
        "risk_level": "high",
        "mitre_techniques": ["T1110", "T1110.003", "T1078"],
        "category": "Network Security",
        "patterns": [
            r"\bfailed password\b",
            r"\binvalid (user|password|credential)\b",
            r"\bauthentication (failed|failure|error)\b",
            r"\bunauthorized\b.*\b(login|access|attempt)\b",
            r"\bpassword (spray|spraying)\b",
            r"\bbrute.?force\b",
        ],
        "rule": "Alert on repeated authentication failures indicating brute force or credential stuffing.",
        "response": "Block source IP after threshold exceeded. Review account lockout policies.",
        "sigma_title": "Brute Force Authentication Attempt",
    },
    {
        "attack_type": "Privilege Escalation",
        "risk_level": "critical",
        "mitre_techniques": ["T1068", "T1078"],
        "category": "System Security",
        "patterns": [
            r"\bsudo\b.*\b(su|bash|sh|root)\b",
            r"\bsuper\s*user\b",
            r"\bgetsystem\b|\bbypassuac\b",
            r"\bTTY=.+USER=root\b",
            r"\bchmod\s+(777|4755|u\+s)\b",
            r"\bchown\s+root\b",
        ],
        "rule": "Alert when commands indicate privilege escalation to root or system level.",
        "response": "Terminate session, alert IR team, review sudo/RBAC configuration.",
        "sigma_title": "Linux Privilege Escalation via Sudo",
    },
    {
        "attack_type": "Lateral Movement / Remote Execution",
        "risk_level": "high",
        "mitre_techniques": ["T1021", "T1021.004"],
        "category": "Network Security",
        "patterns": [
            r"\bAccepted (password|publickey)\b.*\broot\b",
            r"\bpsexec\b|\bwmiexec\b|\bwinrm\b",
            r"\bssh\b.*\b(root|admin|system)\b",
            r"\brdp\b.*\b(lateral|pivot|hop)\b",
            r"\bnew (ssh|rdp|smb) connection\b",
        ],
        "rule": "Alert when remote service connections use privileged accounts or pivot patterns.",
        "response": "Investigate source account for signs of compromise. Review remote access logs.",
        "sigma_title": "Suspicious Remote Service Authentication",
    },
    {
        "attack_type": "Malware / C2 Download",
        "risk_level": "critical",
        "mitre_techniques": ["T1105", "T1059"],
        "category": "Malware",
        "patterns": [
            r"\b(wget|curl|invoke-webrequest|iwr)\b.*\b(http|https|ftp)\b",
            r"\b/tmp/\w+\.(sh|py|pl|exe|bin)\b",
            r"\bbash\s+/tmp/\b",
            r"\bdownload.*\bpayload\b",
            r"\bInvoke-Expression\b.*\bDownloadString\b",
            r"\bpowershell\b.*\b-EncodedCommand\b",
        ],
        "rule": "Alert when commands download and execute files from external sources.",
        "response": "Quarantine host immediately. Initiate IR playbook for malware response.",
        "sigma_title": "Suspicious Remote File Download and Execution",
    },
    {
        "attack_type": "Scheduled Task Persistence",
        "risk_level": "high",
        "mitre_techniques": ["T1053", "T1053.005", "T1543"],
        "category": "Persistence",
        "patterns": [
            r"\bschtasks\b|\bat\b.*\b/create\b",
            r"\bcrontab\b.*(-e|-l)\b",
            r"\b(MaliciousTask|BackdoorTask)\b",
            r"\bScheduled Task Created\b",
            r"\bRegister-ScheduledTask\b",
        ],
        "rule": "Alert when scheduled tasks or cron jobs are created unexpectedly.",
        "response": "Review task content and creator. Remove if unauthorized.",
        "sigma_title": "Suspicious Scheduled Task Creation",
    },
    {
        "attack_type": "Web Application Attack",
        "risk_level": "high",
        "mitre_techniques": ["T1190"],
        "category": "Web Security",
        "patterns": [
            r"\bSELECT\b.+\bFROM\b.+\bWHERE\b",
            r"(?:--|;)\s*(?:DROP|INSERT|UPDATE|DELETE)\b",
            r"\bUNION\b.+\bSELECT\b",
            r"<script\b[^>]*>",
            r"\.\./\.\./|\.\.%2f",
            r"\bOR\s+['\"]?1['\"]?\s*=\s*['\"]?1",
        ],
        "rule": "Alert on SQL injection, XSS, or directory traversal patterns in HTTP requests.",
        "response": "Block source IP. Review WAF rules. Patch vulnerable endpoint.",
        "sigma_title": "Web Application Attack Detected",
    },
    {
        "attack_type": "Defense Evasion",
        "risk_level": "high",
        "mitre_techniques": ["T1562"],
        "category": "Evasion",
        "patterns": [
            r"\b(disable|stop|kill)\b.*(firewall|iptables|ufw|defender|antivirus|av)\b",
            r"\bsetenforce\s+0\b",
            r"\bsystemctl\s+(stop|disable)\b.*(ufw|firewalld|iptables)\b",
            r"\bSet-MpPreference\b.*\bDisable\b",
            r"\bnetsh\s+advfirewall\s+set\b.*\boff\b",
        ],
        "rule": "Alert when security tools or firewall rules are disabled.",
        "response": "Alert IR immediately. Re-enable controls. Investigate source.",
        "sigma_title": "Security Tool Disabled",
    },
    {
        "attack_type": "Discovery / Reconnaissance",
        "risk_level": "medium",
        "mitre_techniques": ["T1082", "T1083"],
        "category": "Discovery",
        "patterns": [
            r"\b(nmap|masscan|netdiscover)\b",
            r"\bifconfig\b|\bip\s+addr\b|\bipconfig\b",
            r"\bcat\b.*/etc/(passwd|shadow|group|hosts)\b",
            r"\bls\s+-la\s+/\b|\bfind\s+/\b.*(-name|-perm)\b",
            r"\bwhoami\b.*&&.*\bhostname\b",
            r"\bnet\s+(user|group|localgroup)\b",
        ],
        "rule": "Alert when discovery commands enumerate users, network, or sensitive system files.",
        "response": "Investigate context. Escalate if combined with other suspicious activity.",
        "sigma_title": "System and Network Discovery Commands",
    },
]


class DetectionEngine:
    """Offline, rule-based detection engine. No external API or API key is used."""

    def __init__(self):
        self.mode = "local"
        self.findings = []

    def _match(self, text, patterns):
        return any(re.search(p, text, re.IGNORECASE) for p in patterns)

    def analyze(self, record):
        text = record.get("query","") + " " + record.get("context","")
        matches = [c for c in DETECTION_CHECKS if self._match(text, c["patterns"])]

        if not matches:
            return {
                "query_id": record["id"],
                "timestamp": record.get("timestamp",""),
                "user": record.get("user",""),
                "source_ip": record.get("source_ip",""),
                "is_anomalous": False,
                "risk_level": "none",
                "attack_type": "Benign",
                "category": "None",
                "mitre_techniques": [],
                "reasoning": "Query matches normal operational patterns.",
                "detection_rule": "No rule triggered.",
                "recommended_response": "Allow and continue normal logging.",
                "sigma_title": "",
            }

        # Take highest severity match
        priority = {"critical":4,"high":3,"medium":2,"low":1}
        best = max(matches, key=lambda c: priority.get(c["risk_level"],0))

        return {
            "query_id": record["id"],
            "timestamp": record.get("timestamp",""),
            "user": record.get("user",""),
            "source_ip": record.get("source_ip",""),
            "is_anomalous": True,
            "risk_level": best["risk_level"],
            "attack_type": best["attack_type"],
            "category": best["category"],
            "mitre_techniques": best["mitre_techniques"],
            "reasoning": f"Matched pattern for {best['attack_type']}. Text: '{text[:120]}...'",
            "detection_rule": best["rule"],
            "recommended_response": best["response"],
            "sigma_title": best["sigma_title"],
            "all_matches": [c["attack_type"] for c in matches],
        }

    def run_batch(self, records):
        self.findings = []
        for r in records:
            self.findings.append(self.analyze(r))
        return self.findings

    def get_stats(self):
        total = len(self.findings)
        anomalous = [f for f in self.findings if f.get("is_anomalous")]
        by_risk = {}
        by_category = {}
        by_technique = {}
        for f in anomalous:
            lvl = f.get("risk_level","unknown")
            by_risk[lvl] = by_risk.get(lvl,0) + 1
            cat = f.get("category","unknown")
            by_category[cat] = by_category.get(cat,0) + 1
            for t in f.get("mitre_techniques",[]):
                by_technique[t] = by_technique.get(t,0) + 1
        return {
            "total": total,
            "anomalous": len(anomalous),
            "clean": total - len(anomalous),
            "by_risk": by_risk,
            "by_category": by_category,
            "top_techniques": dict(sorted(by_technique.items(), key=lambda x: x[1], reverse=True)[:5]),
        }
