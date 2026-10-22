# Enterprise SIEM Lab — Lightweight Prototype

## Overview
A beginner-friendly Python prototype that reads **synthetic, offline authentication events**, counts failed logins, and raises a JSON alert when one source IP has at least three failed login events.

## Important scope note
This is a small learning prototype, **not a production SIEM** and not a Wazuh installation. It does not monitor a live machine, collect Windows Event Logs, block IP addresses, or prove malicious intent. Use only authorized logs and systems.

## Requirements
- Windows 10 or another OS with Python 3.10 or newer
- No third-party Python packages required
- A few MB of disk space for the code and sample log

Check Python:
```powershell
py --version
```
If Python is not installed, install a supported Python 3 version from the official Python website and enable the Python launcher during setup.

## Run on Windows 10
1. Extract `enterprise_siem_lab.zip`.
2. Open the extracted `Enterprise-SIEM-Lab` folder.
3. In File Explorer, click the address bar, type `powershell`, and press Enter.
4. Run:
```powershell
py main.py --input data/sample_auth.log --output output/alerts.json
```
If `py` is unavailable but `python` works, use:
```powershell
python main.py --input data/sample_auth.log --output output/alerts.json
```

Expected summary for the included sample:
- Events processed: 7
- Invalid lines skipped: 1
- Alerts generated: 1
- JSON report saved to: `output/alerts.json`

The single alert should identify repeated failed login events from the reserved documentation IP `203.0.113.10`. These are synthetic training records, not real network activity.

## Change the threshold
For example, require at least four failed attempts:
```powershell
py main.py --input data/sample_auth.log --output output/alerts.json --threshold 4
```

## Event format
Each event is a single line with `key=value` fields. Required fields:
- `timestamp` — ISO 8601 date/time
- `host` — source endpoint name
- `event` — for example, `login_failed` or `login_success`

Failed-login records should also include `src_ip` and may include `user`.

## Rule
**AUTH-001 — Repeated failed login attempts:** generate a medium-severity alert when the number of `login_failed` events from one source IP reaches the configured threshold (default: 3). This prototype counts the entire input file; it does not use a rolling time window.

## Files
- `main.py` — parser, detection rule, JSON output
- `data/sample_auth.log` — synthetic training events
- `output/` — generated JSON output appears here
- `requirements.txt` — dependency note

## Limitations and future work
- No live log ingestion or Wazuh integration
- No rolling time-window detection, authentication context, or allowlists
- No automatic response or account/IP blocking
- Future extensions could include Windows Event Log ingestion, unit tests, time-window correlation, a dashboard, and integration with a dedicated SIEM after resource and compatibility checks.
