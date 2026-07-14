"""
ThreatSight — Module 6: SIEM Export
=====================================
Exports findings in formats ready to ingest into:
  - IBM QRadar (Custom Log Format / LEEF)
  - Splunk (JSON HEC format)
  - Microsoft Sentinel (CEF / JSON)
  - Generic SIEM (CEF)

Author: Krutika Jagdale
"""

import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_MAP_QRADAR = {"critical": 10, "high": 7, "medium": 5, "low": 2, "none": 0}
SEVERITY_MAP_CEF    = {"critical": 10, "high": 8, "medium": 5, "low": 3, "none": 0}

def _now_epoch():
    return int(datetime.now(timezone.utc).timestamp() * 1000)

def _ts_to_epoch(ts_str):
    try:
        formats = [
            "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y %b %d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str.strip(), fmt)
                return int(dt.timestamp() * 1000)
            except ValueError:
                continue
    except Exception:
        pass
    return _now_epoch()


# ── IBM QRadar LEEF ──────────────────────────────────────────────────────────
def export_qradar_leef(findings, output_path):
    """
    Log Event Extended Format (LEEF) for QRadar.
    Format: LEEF:2.0|Vendor|Product|Version|EventID|<tab-delimited key=value pairs>
    """
    lines = []
    for f in findings:
        if not f.get("is_anomalous"):
            continue
        sev = SEVERITY_MAP_QRADAR.get(f.get("risk_level","none"), 0)
        evt_id = f.get("attack_type","Unknown").replace(" ","_").upper()
        techniques = ",".join(f.get("mitre_techniques",[]))
        ts = _ts_to_epoch(f.get("timestamp",""))
        fields = "\t".join([
            f"devTime={f.get('timestamp','')}",
            f"devTimeFormat=yyyy-MM-dd'T'HH:mm:ss'Z'",
            f"src={f.get('source_ip','0.0.0.0')}",
            f"usrName={f.get('user','unknown')}",
            f"severity={sev}",
            f"cat={f.get('category','Security')}",
            f"msg={f.get('reasoning','').replace(chr(9),' ')}",
            f"mitreTechniques={techniques}",
            f"detectionRule={f.get('detection_rule','').replace(chr(9),' ')}",
            f"attackType={f.get('attack_type','')}",
            f"responseAction={f.get('recommended_response','').replace(chr(9),' ')}",
        ])
        leef_line = f"LEEF:2.0|ThreatSight|SecurityDetection|2.0|{evt_id}|{fields}"
        lines.append(leef_line)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    return output_path


# ── Splunk HEC JSON ──────────────────────────────────────────────────────────
def export_splunk_hec(findings, output_path):
    """
    Splunk HTTP Event Collector (HEC) JSON format.
    Each line is an independent JSON event (newline-delimited).
    """
    events = []
    for f in findings:
        if not f.get("is_anomalous"):
            continue
        event = {
            "time": _ts_to_epoch(f.get("timestamp","")) / 1000,
            "host": f.get("source_ip","0.0.0.0"),
            "source": "threatsight:detection",
            "sourcetype": "threatsight:json",
            "index": "security",
            "event": {
                "query_id": f.get("query_id",""),
                "timestamp": f.get("timestamp",""),
                "source_ip": f.get("source_ip",""),
                "user": f.get("user",""),
                "is_anomalous": True,
                "risk_level": f.get("risk_level",""),
                "attack_type": f.get("attack_type",""),
                "category": f.get("category",""),
                "mitre_techniques": f.get("mitre_techniques",[]),
                "reasoning": f.get("reasoning",""),
                "detection_rule": f.get("detection_rule",""),
                "recommended_response": f.get("recommended_response",""),
                "sigma_title": f.get("sigma_title",""),
                "severity_score": SEVERITY_MAP_CEF.get(f.get("risk_level","none"),0),
                "tool": "ThreatSight",
                "author": "Krutika Jagdale",
            }
        }
        events.append(json.dumps(event))

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text("\n".join(events), encoding="utf-8")
    return output_path


# ── CEF (Common Event Format) ─────────────────────────────────────────────────
def export_cef(findings, output_path):
    """
    ArcSight / Sentinel compatible CEF format.
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    lines = []
    for f in findings:
        if not f.get("is_anomalous"):
            continue
        sev = SEVERITY_MAP_CEF.get(f.get("risk_level","none"), 0)
        sig_id = f.get("query_id","0").replace("Q","")
        name = f.get("attack_type","Unknown").replace("|","_")
        ts = _ts_to_epoch(f.get("timestamp",""))
        ext_parts = [
            f"rt={ts}",
            f"src={f.get('source_ip','0.0.0.0')}",
            f"suser={f.get('user','unknown')}",
            f"cat={f.get('category','Security')}",
            f"msg={f.get('reasoning','').replace('=','_').replace('|','_')[:255]}",
            f"cs1={','.join(f.get('mitre_techniques',[]))}",
            f"cs1Label=MITRE_Techniques",
            f"cs2={f.get('sigma_title','').replace('=','_').replace('|','_')}",
            f"cs2Label=Sigma_Title",
        ]
        cef_line = f"CEF:0|ThreatSight|SecurityDetection|2.0|{sig_id}|{name}|{sev}|{' '.join(ext_parts)}"
        lines.append(cef_line)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    return output_path


# ── QRadar AQL Reference ──────────────────────────────────────────────────────
def generate_aql_queries(findings):
    """
    Generate QRadar AQL queries for each detected attack type.
    These can be pasted directly into QRadar Log Activity > Advanced Search.
    """
    anomalous = [f for f in findings if f.get("is_anomalous")]
    seen = set()
    queries = []

    for f in anomalous:
        attack = f.get("attack_type","")
        if attack in seen:
            continue
        seen.add(attack)

        # Generic AQL template — customize per your QRadar log source names
        techs = f.get("mitre_techniques",[])
        ip = f.get("source_ip","")

        queries.append({
            "attack_type": attack,
            "aql": (
                f"SELECT DATEFORMAT(devicetime,'dd-MM-yyyy HH:mm:ss') AS 'Time', "
                f"sourceip, username, QIDNAME(qid) AS 'Event Name', "
                f"\"Category\" AS severity, UTF8(payload) AS 'Payload' "
                f"FROM events "
                f"WHERE INCIDR('{ip}/24', sourceip) "
                f"AND LOGSOURCETYPENAME(devicetype) = 'LinuxServer' "
                f"LAST 24 HOURS"
            ),
            "mitre": techs,
            "description": f"Find events related to {attack} from similar source range.",
        })

    return queries


def export_all(findings, output_dir="output"):
    """Export to all SIEM formats in one call."""
    d = Path(output_dir)
    d.mkdir(exist_ok=True)
    results = {
        "qradar_leef": export_qradar_leef(findings, d / "threatsight_qradar.leef"),
        "splunk_hec":  export_splunk_hec(findings,  d / "threatsight_splunk.json"),
        "cef":         export_cef(findings,          d / "threatsight_sentinel.cef"),
    }
    aql = generate_aql_queries(findings)
    aql_path = d / "threatsight_qradar_aql.json"
    aql_path.write_text(json.dumps(aql, indent=2), encoding="utf-8")
    results["aql_queries"] = str(aql_path)
    return results
