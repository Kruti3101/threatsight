# ThreatSight v2.0 — Offline Cybersecurity Detection Platform

ThreatSight is a local, rule-based cybersecurity detection platform for AI prompts and security logs. It normalizes logs, detects suspicious activity, maps findings to MITRE ATT&CK techniques, correlates related events, and produces investigation-ready reports.

It runs entirely with Python's standard library: no API key, cloud account, paid service, or third-party Python package is required.

## Features

- Ingests JSON, CSV, Syslog, Windows Event XML, and Apache logs
- Detects prompt injection, jailbreaks, data exfiltration, brute-force attempts, privilege escalation, malware downloads, web attacks, and more
- Maps detections to MITRE ATT&CK techniques and assigns severity levels
- Enriches findings with offline IP-reputation heuristics
- Reconstructs kill chains and identifies related IP clusters and possible campaigns
- Generates text, HTML, JSON, and Sigma reports
- Exports findings in QRadar LEEF, Splunk HEC JSON, Sentinel/CEF, and QRadar AQL formats
- Displays a terminal security dashboard

## Requirements

- Python 3.9 or later
- No external dependencies

## Run

Clone the repository and enter its directory:

```bash
git clone https://github.com/Kruti3101/threatsight.git
cd threatsight
```

Run all built-in demos:

```bash
python3 threatsight_v2.py
```

Run one demo:

```bash
python3 threatsight_v2.py --demo syslog
```

Available demos are `native`, `syslog`, `windows`, and `apache`.

## Analyze Your Own Log File

```bash
python3 threatsight_v2.py --source /path/to/logfile.log
```

ThreatSight detects the format automatically when possible. To select it yourself:

```bash
python3 threatsight_v2.py --source /path/to/log.json --format json
```

Supported formats are `json`, `csv`, `syslog`, `windows_xml`, and `apache`.

Choose a different output directory or skip the HTML report:

```bash
python3 threatsight_v2.py --output-dir results
python3 threatsight_v2.py --no-html
```

## Architecture

```text
Log Files / Built-in Demos
          |
          v
Ingest and Normalize
(JSON, CSV, Syslog, Windows XML, Apache)
          |
          v
Local Rule-Based Detection
(severity scoring and MITRE ATT&CK mapping)
          |
          v
Investigation and Correlation
(IP reputation, kill chain, IP clusters, campaigns)
          |
          v
Reports and SIEM Export
(HTML, text, JSON, Sigma, LEEF, HEC, CEF, AQL)
```

## Output

By default, results are written to `output/`:

- Text and HTML investigation reports
- JSON findings export
- Sigma detection rules
- QRadar LEEF events and AQL queries
- Splunk HEC JSON events
- Sentinel-compatible CEF events

## Project Structure

```text
threatsight/
├── threatsight_v2.py   # Main command-line interface
├── ingest.py           # Multi-format log normalization
├── detect.py           # Local detection rules and MITRE mapping
├── investigate.py      # Enrichment and event correlation
├── respond.py          # Reports, Sigma rules, and response playbooks
├── dashboard.py        # Terminal dashboard
├── siem_export.py      # SIEM format exports
├── README.md
└── .gitignore
```

## MITRE ATT&CK Coverage

ThreatSight maps findings to relevant techniques, including prompt injection, command and scripting activity, credential abuse, brute force, data exfiltration, remote services, scheduled-task persistence, privilege escalation, defense evasion, and discovery.

## Author

Krutika Jagdale  
M.S. Cybersecurity — University of Colorado Denver

## License

MIT License — free to use, modify, and distribute.
