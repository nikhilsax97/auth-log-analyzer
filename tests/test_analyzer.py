from auth_log_analyzer.analyzer import analyze_events
from auth_log_analyzer.parser import parse_lines


def make_failure(minute: int, user: str = "root", ip: str = "203.0.113.10") -> str:
    return (
        f"2026-08-29T14:{minute:02d}:00Z web01 sshd[{100+minute}]: "
        f"Failed password for {user} from {ip} port 50100 ssh2"
    )


def test_detects_brute_force():
    events = parse_lines([make_failure(i) for i in range(5)])
    findings = analyze_events(events)
    assert any(f.rule_id == "SSH-BRUTE-FORCE" for f in findings)


def test_detects_username_spray():
    lines = [make_failure(i, user=f"user{i}") for i in range(4)]
    findings = analyze_events(parse_lines(lines), brute_force_threshold=10)
    assert any(f.rule_id == "SSH-USERNAME-SPRAY" for f in findings)


def test_detects_success_after_failures():
    lines = [make_failure(i, user="admin") for i in range(5)]
    lines.append(
        "2026-08-29T14:05:30Z web01 sshd[999]: Accepted password for admin from 203.0.113.10 port 50200 ssh2"
    )
    findings = analyze_events(parse_lines(lines))
    suspicious = [f for f in findings if f.rule_id == "SSH-SUCCESS-AFTER-FAILURES"]
    assert len(suspicious) == 1
    assert suspicious[0].severity == "critical"


def test_does_not_flag_sparse_failures_outside_window():
    lines = [make_failure(i * 15) for i in range(4)]
    findings = analyze_events(parse_lines(lines), brute_force_threshold=4, window_minutes=10)
    assert not any(f.rule_id == "SSH-BRUTE-FORCE" for f in findings)


def test_rejects_invalid_thresholds():
    try:
        analyze_events([], brute_force_threshold=0)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")
