from __future__ import annotations

from datetime import datetime
import re
from typing import Iterable

from .models import AuthEvent

LINE_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<message>.+)$"
)
FAILED_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F:.]+) port \d+ ssh2$"
)
SUCCESS_RE = re.compile(
    r"^Accepted (?:password|publickey) for (?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F:.]+) port \d+ ssh2$"
)


def parse_line(line: str) -> AuthEvent | None:
    """Parse one ISO-8601 SSH authentication log line.

    Unsupported or malformed lines return ``None`` instead of raising so a
    mixed log file can still be analyzed.
    """

    match = LINE_RE.match(line.strip())
    if not match:
        return None

    try:
        timestamp = datetime.fromisoformat(match.group("timestamp").replace("Z", "+00:00"))
    except ValueError:
        return None

    message = match.group("message")
    status_match = FAILED_RE.match(message)
    status = "failed"
    if status_match is None:
        status_match = SUCCESS_RE.match(message)
        status = "accepted"
    if status_match is None:
        return None

    return AuthEvent(
        timestamp=timestamp,
        host=match.group("host"),
        status=status,
        username=status_match.group("user"),
        source_ip=status_match.group("ip"),
        raw_line=line.rstrip("\n"),
    )


def parse_lines(lines: Iterable[str]) -> list[AuthEvent]:
    events = [event for line in lines if (event := parse_line(line)) is not None]
    return sorted(events, key=lambda event: event.timestamp)
