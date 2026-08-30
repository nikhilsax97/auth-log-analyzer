from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze_events
from .parser import parse_lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze SSH authentication logs for suspicious activity.")
    parser.add_argument("logfile", type=Path)
    parser.add_argument("--brute-force-threshold", type=int, default=5)
    parser.add_argument("--spray-user-threshold", type=int, default=4)
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        with args.logfile.open("r", encoding="utf-8") as handle:
            events = parse_lines(handle)
        findings = analyze_events(
            events,
            brute_force_threshold=args.brute_force_threshold,
            spray_user_threshold=args.spray_user_threshold,
            window_minutes=args.window_minutes,
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    if args.json:
        print(json.dumps([finding.to_dict() for finding in findings], indent=2))
        return 1 if findings else 0

    print(f"Parsed events: {len(events)}")
    print(f"Findings: {len(findings)}")
    for finding in findings:
        print(
            f"[{finding.severity.upper()}] {finding.rule_id} {finding.source_ip} - "
            f"{finding.summary}"
        )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
