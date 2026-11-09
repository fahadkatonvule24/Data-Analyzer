from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from loganalyzer import analyze_logs

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
DAY = datetime(2026, 3, 14)


@pytest.fixture(scope="session")
def samples() -> Path:
    return SAMPLES


@pytest.fixture(scope="session")
def auth_analysis():
    return analyze_logs([SAMPLES / "auth.log"], year=2026)


@pytest.fixture(scope="session")
def web_analysis():
    return analyze_logs([SAMPLES / "access.log"])


def syslog(when: datetime, message: str, process: str = "sshd[4242]", host: str = "web01") -> str:
    return f"{when:%b} {when.day:>2} {when:%H:%M:%S} {host} {process}: {message}"


def failed(when: datetime, ip: str, user: str = "root", invalid: bool = False) -> str:
    prefix = "invalid user " if invalid else ""
    return syslog(when, f"Failed password for {prefix}{user} from {ip} port 50000 ssh2")


def accepted(when: datetime, ip: str, user: str, method: str = "password") -> str:
    return syslog(when, f"Accepted {method} for {user} from {ip} port 50001 ssh2")


def access(
    ip: str,
    path: str,
    status: int = 200,
    when: datetime = DAY,
    method: str = "GET",
    ua: str = "Mozilla/5.0",
    size: int = 512,
) -> str:
    stamp = f"{when:%d}/{when:%b}/{when:%Y:%H:%M:%S} +0000"
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def every(start: datetime, count: int, seconds: float) -> list[datetime]:
    return [start + timedelta(seconds=i * seconds) for i in range(count)]
