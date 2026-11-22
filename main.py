from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path


def emit(value, output=None):
    rendered = json.dumps(value, indent=2, default=str)
    if output:
        Path(output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


def analyze(text: str):
    events = []
    sources = collections.Counter()
    users = collections.Counter()
    event_counts = collections.Counter()
    commands = collections.Counter()
    sessions = set()

    for line in text.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        event_id = str(obj.get("eventid") or obj.get("event_type") or "unknown")
        event_counts[event_id] += 1

        source_ip = obj.get("src_ip") or obj.get("remote_ip") or obj.get("client_ip")
        if source_ip:
            sources[str(source_ip)] += 1

        username = obj.get("username")
        if username and ("login" in event_id or "auth" in event_id):
            users[str(username)] += 1

        session_id = obj.get("session") or obj.get("session_id")
        if session_id:
            sessions.add(str(session_id))

        if "command.input" in event_id:
            command = str(obj.get("input") or obj.get("command") or "(empty)")[:120]
            commands[command] += 1

        if len(events) < 100:
            events.append({
                "timestamp": obj.get("timestamp"),
                "eventid": event_id,
                "src_ip": source_ip,
                "username": username,
                "session": session_id,
            })

    failed = sum(
        count for event, count in event_counts.items()
        if "login.failed" in event or "login.failure" in event
    )
    successful = sum(
        count for event, count in event_counts.items()
        if "login.success" in event
    )

    return {
        "events_parsed": sum(event_counts.values()),
        "unique_sessions": len(sessions),
        "failed_logins": failed,
        "successful_logins": successful,
        "top_source_ips": sources.most_common(20),
        "top_usernames": users.most_common(20),
        "event_counts": dict(event_counts),
        "top_commands": commands.most_common(20),
        "recent_events": events,
        "note": "Cowrie data is untrusted telemetry. Commands are counted only; never execute log content.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Cowrie honeypot JSON/JSONL exports for source-IP activity, "
                    "login attempts, session counts, and command patterns."
    )
    parser.add_argument("target", nargs="?", default="-", help="Local input file; use - for stdin")
    parser.add_argument("--output", help="Optional JSON report output path")
    args = parser.parse_args()

    raw = sys.stdin.read() if args.target == "-" else Path(args.target).read_text(errors="replace")
    report = analyze(raw)

    rendered = json.dumps(report, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
