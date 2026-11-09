"""Log parsers. Each turns raw lines into a pandas DataFrame with a fixed schema."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from loganalyzer.parsers.access import ACCESS_LINE, parse_access_lines
from loganalyzer.parsers.auth import SYSLOG_LINE, AuthEvent, parse_auth_lines
from loganalyzer.parsers.base import LogFormat, ParseResult, UnsupportedFormatError

PARSERS: dict[LogFormat, Callable[..., ParseResult]] = {
    LogFormat.AUTH: parse_auth_lines,
    LogFormat.ACCESS: parse_access_lines,
}

_SIGNATURES = {LogFormat.AUTH: SYSLOG_LINE, LogFormat.ACCESS: ACCESS_LINE}


def detect_format(sample: Sequence[str], min_match_ratio: float = 0.5) -> LogFormat:
    """Pick the format whose line pattern matches most of the sample."""
    lines = [line for line in sample if line.strip()]
    if not lines:
        raise UnsupportedFormatError("file is empty")
    scores = {fmt: sum(bool(rx.match(line)) for line in lines) for fmt, rx in _SIGNATURES.items()}
    best = max(scores, key=scores.__getitem__)
    if scores[best] / len(lines) < min_match_ratio:
        supported = "; ".join(f.description for f in LogFormat)
        raise UnsupportedFormatError(f"unrecognised log format (supported: {supported})")
    return best


__all__ = [
    "PARSERS",
    "AuthEvent",
    "LogFormat",
    "ParseResult",
    "UnsupportedFormatError",
    "detect_format",
    "parse_access_lines",
    "parse_auth_lines",
]
