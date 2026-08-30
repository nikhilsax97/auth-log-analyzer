# Authentication Log Analyzer

A small defensive-security tool that parses SSH authentication logs and identifies patterns associated with brute-force attempts, username spraying, and a successful login that follows repeated failures from the same source.

## Detection Rules

| Rule | Purpose |
| --- | --- |
| `SSH-BRUTE-FORCE` | Finds a high number of failed SSH logins from one source within a time window |
| `SSH-USERNAME-SPRAY` | Finds one source attempting several different usernames |
| `SSH-SUCCESS-AFTER-FAILURES` | Highlights a successful SSH login after repeated failures from the same source |

The rules are intentionally transparent and testable. They are heuristics, not proof that an IP address is malicious.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Run the Example

```bash
auth-log-analyzer examples/sample_auth.log
```

JSON output:

```bash
auth-log-analyzer examples/sample_auth.log --json
```

The command returns exit code `1` when findings are present and `0` when no findings are present, which makes it usable in simple automation pipelines.

## Expected Input

The parser accepts ISO-8601 SSH lines such as:

```text
2026-08-29T14:00:00Z web01 sshd[101]: Failed password for invalid user admin from 203.0.113.10 port 50100 ssh2
```

Unsupported lines are ignored instead of stopping analysis of the entire file.

## Tests

```bash
pytest -q
```

The test suite covers parsing, malformed input, brute-force detection, username spraying, suspicious successful authentication, time-window behavior, and configuration validation.

## Scope

This project is designed for learning and defensive analysis. Production environments should combine authentication telemetry with asset context, threat intelligence, rate limiting, MFA, centralized logging, and a SIEM or detection platform.
