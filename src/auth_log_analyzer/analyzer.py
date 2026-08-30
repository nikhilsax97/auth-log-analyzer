from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from .models import AuthEvent, Finding


def _windowed_failures(
    failures: list[AuthEvent], threshold: int, window: timedelta
) -> list[Finding]:
    findings: list[Finding] = []
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in failures:
        by_ip[event.source_ip].append(event)

    for ip, events in by_ip.items():
        queue: deque[AuthEvent] = deque()
        best_window: list[AuthEvent] = []
        for event in events:
            queue.append(event)
            while queue and event.timestamp - queue[0].timestamp > window:
                queue.popleft()
            if len(queue) > len(best_window):
                best_window = list(queue)

        if len(best_window) >= threshold:
            findings.append(
                Finding(
                    rule_id="SSH-BRUTE-FORCE",
                    severity="high",
                    source_ip=ip,
                    summary=(
                        f"{len(best_window)} failed SSH logins occurred within "
                        f"{int(window.total_seconds() // 60)} minutes."
                    ),
                    evidence_count=len(best_window),
                    first_seen=best_window[0].timestamp,
                    last_seen=best_window[-1].timestamp,
                )
            )
    return findings


def _username_spray_findings(
    failures: list[AuthEvent], user_threshold: int, window: timedelta
) -> list[Finding]:
    findings: list[Finding] = []
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in failures:
        by_ip[event.source_ip].append(event)

    for ip, events in by_ip.items():
        for start_index, start in enumerate(events):
            window_events = [
                event
                for event in events[start_index:]
                if event.timestamp - start.timestamp <= window
            ]
            users = {event.username for event in window_events}
            if len(users) >= user_threshold:
                findings.append(
                    Finding(
                        rule_id="SSH-USERNAME-SPRAY",
                        severity="medium",
                        source_ip=ip,
                        summary=(
                            f"Failed SSH attempts targeted {len(users)} distinct usernames "
                            f"within {int(window.total_seconds() // 60)} minutes."
                        ),
                        evidence_count=len(window_events),
                        first_seen=window_events[0].timestamp,
                        last_seen=window_events[-1].timestamp,
                    )
                )
                break
    return findings


def _suspicious_success_findings(
    events: list[AuthEvent], preceding_failure_threshold: int, window: timedelta
) -> list[Finding]:
    findings: list[Finding] = []
    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)

    for event in events:
        if event.status == "failed":
            failures_by_ip[event.source_ip].append(event)
            continue

        recent_failures = [
            failure
            for failure in failures_by_ip[event.source_ip]
            if timedelta(0) <= event.timestamp - failure.timestamp <= window
        ]
        if len(recent_failures) >= preceding_failure_threshold:
            findings.append(
                Finding(
                    rule_id="SSH-SUCCESS-AFTER-FAILURES",
                    severity="critical",
                    source_ip=event.source_ip,
                    summary=(
                        f"Successful SSH login for '{event.username}' followed "
                        f"{len(recent_failures)} recent failures from the same source."
                    ),
                    evidence_count=len(recent_failures) + 1,
                    first_seen=recent_failures[0].timestamp,
                    last_seen=event.timestamp,
                )
            )
    return findings


def analyze_events(
    events: list[AuthEvent],
    brute_force_threshold: int = 5,
    spray_user_threshold: int = 4,
    window_minutes: int = 10,
) -> list[Finding]:
    """Run simple SSH authentication detections over parsed events."""

    if brute_force_threshold < 1 or spray_user_threshold < 1 or window_minutes < 1:
        raise ValueError("Thresholds and window_minutes must be positive integers.")

    events = sorted(events, key=lambda event: event.timestamp)
    failures = [event for event in events if event.status == "failed"]
    window = timedelta(minutes=window_minutes)

    findings = []
    findings.extend(_windowed_failures(failures, brute_force_threshold, window))
    findings.extend(_username_spray_findings(failures, spray_user_threshold, window))
    findings.extend(
        _suspicious_success_findings(
            events, preceding_failure_threshold=brute_force_threshold, window=window
        )
    )
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda finding: (severity_order[finding.severity], finding.first_seen))
