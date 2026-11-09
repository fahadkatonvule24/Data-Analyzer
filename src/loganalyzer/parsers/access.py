"""Parser for Apache / Nginx access logs in Common or Combined Log Format."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from loganalyzer.parsers.base import MONTHS, ParseResult, frame, to_naive_utc

ACCESS_COLUMNS = [
    "timestamp",
    "source_ip",
    "user",
    "method",
    "path",
    "protocol",
    "status",
    "bytes",
    "referrer",
    "user_agent",
    "raw",
    "line_no",
]

_QUOTED = r'(?:[^"\\]|\\.)*'
ACCESS_LINE = re.compile(
    rf'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<request>{_QUOTED})" '
    rf'(?P<status>\d{{3}}) (?P<bytes>\d+|-)(?: "(?P<referrer>{_QUOTED})" "(?P<ua>{_QUOTED})")?'
)
_CLF_TIME = re.compile(
    r"^(?P<d>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<y>\d{4}):(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})"
    r"(?: (?P<sign>[+-])(?P<oh>\d{2})(?P<om>\d{2}))?$"
)


def parse_clf_time(value: str) -> datetime:
    """Parse ``10/Oct/2000:13:55:36 -0700``. Done by hand because ``%b`` is locale-dependent."""
    m = _CLF_TIME.match(value)
    if not m or m["mon"] not in MONTHS:
        raise ValueError(f"bad CLF timestamp: {value!r}")
    tz = None
    if m["sign"]:
        offset = timedelta(hours=int(m["oh"]), minutes=int(m["om"]))
        tz = timezone(offset if m["sign"] == "+" else -offset)
    parsed = datetime(
        int(m["y"]), MONTHS[m["mon"]], int(m["d"]), int(m["H"]), int(m["M"]), int(m["S"]), tzinfo=tz
    )
    return to_naive_utc(parsed)


def _split_request(request: str) -> tuple[str | None, str, str | None]:
    """Split ``GET /path HTTP/1.1``. Malformed requests (raw TLS bytes, probes) keep the raw text."""
    parts = request.split(" ")
    if len(parts) >= 2 and parts[0].isalpha() and parts[0].isupper():
        protocol = parts[-1] if len(parts) >= 3 and parts[-1].startswith("HTTP/") else None
        path_parts = parts[1:-1] if protocol else parts[1:]
        return parts[0], " ".join(path_parts), protocol
    return None, request, None


def _dash_to_none(value: str | None) -> str | None:
    return None if value in (None, "-", "") else value


def parse_access_lines(lines: Iterable[str], **_: object) -> ParseResult:
    records: list[dict] = []
    total = unparsed = 0
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        total += 1
        match = ACCESS_LINE.match(line)
        if not match:
            unparsed += 1
            continue
        try:
            timestamp = parse_clf_time(match["ts"])
        except ValueError:
            unparsed += 1
            continue
        method, path, protocol = _split_request(match["request"])
        records.append(
            {
                "timestamp": timestamp,
                "source_ip": match["ip"],
                "user": _dash_to_none(match["user"]),
                "method": method,
                "path": path,
                "protocol": protocol,
                "status": int(match["status"]),
                "bytes": 0 if match["bytes"] == "-" else int(match["bytes"]),
                "referrer": _dash_to_none(match["referrer"]),
                "user_agent": _dash_to_none(match["ua"]),
                "raw": line,
                "line_no": line_no,
            }
        )
    events = frame(records, ACCESS_COLUMNS)
    events["status"] = events["status"].astype("int64")
    events["bytes"] = events["bytes"].astype("int64")
    return ParseResult(events=events, total_lines=total, unparsed_lines=unparsed)
