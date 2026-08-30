from auth_log_analyzer.parser import parse_line, parse_lines


def test_parses_failed_password_event():
    line = "2026-08-29T14:00:00Z web01 sshd[101]: Failed password for invalid user admin from 203.0.113.10 port 50100 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.status == "failed"
    assert event.username == "admin"
    assert event.source_ip == "203.0.113.10"


def test_parses_success_event():
    line = "2026-08-29T14:05:00Z web01 sshd[102]: Accepted publickey for alex from 198.51.100.5 port 50101 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.status == "accepted"
    assert event.username == "alex"


def test_ignores_unrelated_and_malformed_lines():
    lines = [
        "not a valid log line",
        "2026-08-29T14:05:00Z web01 sudo[22]: session opened",
    ]
    assert parse_lines(lines) == []
