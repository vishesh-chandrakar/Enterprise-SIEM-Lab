"""
Lightweight Enterprise SIEM Lab prototype.
Reads structured sample authentication events, detects repeated failed logins,
and writes a JSON summary. This is a learning prototype, not a production SIEM.
Python 3.10+ recommended; no third-party packages required.
"""
import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


def parse_line(line):
    """Parse one key=value event line. Returns None for comments/blank/invalid lines."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    fields = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key.strip()] = value.strip()
    required = {"timestamp", "host", "event"}
    if not required.issubset(fields):
        return None
    try:
        datetime.fromisoformat(fields["timestamp"].replace("Z", "+00:00"))
    except ValueError:
        return None
    return fields


def analyze_events(lines, threshold=3):
    """Return a deterministic analysis of events and repeated failed logins."""
    events = []
    invalid_lines = 0
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        event = parse_line(line)
        if event is None:
            invalid_lines += 1
        else:
            events.append(event)

    failed_by_ip = defaultdict(list)
    event_counts = Counter()
    for event in events:
        event_name = event.get("event", "unknown")
        event_counts[event_name] += 1
        if event_name == "login_failed":
            ip = event.get("src_ip", "unknown")
            failed_by_ip[ip].append({
                "timestamp": event["timestamp"],
                "host": event["host"],
                "user": event.get("user", "unknown")
            })

    alerts = []
    for ip, attempts in sorted(failed_by_ip.items()):
        if len(attempts) >= threshold:
            alerts.append({
                "severity": "medium",
                "rule_id": "AUTH-001",
                "title": "Repeated failed login attempts",
                "source_ip": ip,
                "failed_attempts": len(attempts),
                "threshold": threshold,
                "affected_hosts": sorted({attempt["host"] for attempt in attempts}),
                "first_seen": min(a["timestamp"] for a in attempts),
                "last_seen": max(a["timestamp"] for a in attempts),
                "note": "Investigate in an authorized lab; this alert alone does not prove an attack."
            })

    return {
        "project": "Enterprise SIEM Lab - Lightweight Prototype",
        "analysis_mode": "offline_sample_log_analysis",
        "events_processed": len(events),
        "invalid_lines_skipped": invalid_lines,
        "event_counts": dict(sorted(event_counts.items())),
        "alert_count": len(alerts),
        "alerts": alerts,
        "limitations": [
            "Does not collect live endpoint logs or connect to Wazuh.",
            "Uses a simple threshold rule and does not correlate time windows.",
            "Sample data is synthetic and must not be treated as real incident evidence."
        ]
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze sample authentication logs for repeated failed logins.")
    parser.add_argument("--input", default="data/sample_auth.log", help="Path to a structured log file")
    parser.add_argument("--output", default="output/alerts.json", help="Path for JSON analysis output")
    parser.add_argument("--threshold", type=int, default=3, help="Failed login count required to alert (minimum 2)")
    args = parser.parse_args()

    if args.threshold < 2:
        parser.error("--threshold must be at least 2")

    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_file():
        parser.error(f"Input file not found: {input_path}. Run the command from the project folder or pass a valid path.")

    result = analyze_events(input_path.read_text(encoding="utf-8").splitlines(), threshold=args.threshold)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Events processed: {result['events_processed']}")
    print(f"Invalid lines skipped: {result['invalid_lines_skipped']}")
    print(f"Alerts generated: {result['alert_count']}")
    print(f"JSON report saved to: {output_path}")


if __name__ == "__main__":
    main()
