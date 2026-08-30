from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    status: str
    username: str
    source_ip: str
    raw_line: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    source_ip: str
    summary: str
    evidence_count: int
    first_seen: datetime
    last_seen: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "summary": self.summary,
            "evidence_count": self.evidence_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }
