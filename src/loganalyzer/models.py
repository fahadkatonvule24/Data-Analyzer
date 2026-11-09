"""Core data types shared by detectors, reports and the CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Finding severity. Ordered so that comparisons (``>=``) work naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from: {choices})") from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """A single security observation produced by a detector.

    ``rule`` is a stable identifier (e.g. ``ssh.bruteforce``) that downstream
    tooling can key on; ``title`` and ``description`` are for humans.
    """

    rule: str
    title: str
    severity: Severity
    description: str
    event_count: int
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    source_ip: str | None = None
    user: str | None = None
    mitre: str | None = None
    evidence: tuple[str, ...] = field(default_factory=tuple)

    @property
    def mitre_url(self) -> str | None:
        if not self.mitre:
            return None
        return "https://attack.mitre.org/techniques/" + self.mitre.replace(".", "/") + "/"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "source_ip": self.source_ip,
            "user": self.user,
            "mitre_attack": self.mitre,
            "evidence": list(self.evidence),
        }
