from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

import pandas as pd

MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


class LogFormat(str, Enum):
    AUTH = "auth"
    ACCESS = "access"

    @property
    def description(self) -> str:
        return {
            LogFormat.AUTH: "Linux auth log (sshd / sudo / useradd)",
            LogFormat.ACCESS: "Web access log (Apache / Nginx combined)",
        }[self]


class UnsupportedFormatError(ValueError):
    """Raised when a file does not look like any supported log format."""


@dataclass
class ParseResult:
    events: pd.DataFrame
    total_lines: int
    unparsed_lines: int

    @property
    def parsed_lines(self) -> int:
        return self.total_lines - self.unparsed_lines


def to_naive_utc(value: datetime) -> datetime:
    """Normalise aware datetimes to naive UTC so events from different offsets compare correctly."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def frame(records: list[dict], columns: list[str]) -> pd.DataFrame:
    df = pd.DataFrame.from_records(records, columns=columns)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df
