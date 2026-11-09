"""Parser for Linux authentication logs (``/var/log/auth.log``, ``/var/log/secure``).

Handles both the classic BSD syslog prefix (``Mar 14 02:13:07 host sshd[812]: ...``)
and the RFC 3339 prefix used by default on Ubuntu 24.04+
(``2026-03-14T02:13:07.123456+00:00 host sshd[812]: ...``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime

import pandas as pd

from loganalyzer.parsers.base import MONTHS, ParseResult, frame, to_naive_utc


class AuthEvent:
    FAILURE = "auth_failure"
    SUCCESS = "auth_success"
    INVALID_USER = "invalid_user"
    SUDO_COMMAND = "sudo_command"
    SUDO_FAILURE = "sudo_failure"
    USER_CREATED = "user_created"
    OTHER = "other"


AUTH_COLUMNS = [
    "timestamp",
    "host",
    "process",
    "event",
    "user",
    "source_ip",
    "port",
    "auth_method",
    "invalid_user",
    "command",
    "raw",
    "line_no",
]

SYSLOG_LINE = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"|(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2}))"
    r"\s(?P<host>\S+)\s(?P<process>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<message>.*)$"
)

_REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]$")
_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_SUDO = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<fails>\d+) incorrect password attempts? ; )?"
    r"(?:TTY=\S+ ; )?PWD=\S+ ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$"
)
_USERADD = re.compile(r"^new user: name=(?P<user>[^,\s]+)")
_OFFSET_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def _timestamp(match: re.Match[str], year: int) -> datetime:
    if match["iso"]:
        # Python 3.10's fromisoformat needs "+00:00", not "Z" or "+0000".
        iso = _OFFSET_NO_COLON.sub(r"\1:\2", match["iso"].replace("Z", "+00:00"))
        return to_naive_utc(datetime.fromisoformat(iso))
    hh, mm, ss = (int(x) for x in match["time"].split(":"))
    return datetime(year, MONTHS[match["month"]], int(match["day"]), hh, mm, ss)


def _classify(process: str, message: str) -> tuple[str, dict, int]:
    """Return (event_type, extracted_fields, occurrences) for one syslog message."""
    occurrences = 1
    if repeated := _REPEATED.match(message):
        occurrences = int(repeated["n"])
        message = repeated["msg"]

    if m := _FAILED.match(message):
        fields = {
            "user": m["user"] or None,
            "source_ip": m["ip"],
            "port": int(m["port"]),
            "auth_method": m["method"],
            "invalid_user": bool(m["invalid"]),
        }
        return AuthEvent.FAILURE, fields, occurrences
    if m := _ACCEPTED.match(message):
        fields = {
            "user": m["user"],
            "source_ip": m["ip"],
            "port": int(m["port"]),
            "auth_method": m["method"],
        }
        return AuthEvent.SUCCESS, fields, occurrences
    if m := _INVALID.match(message):
        fields = {
            "user": m["user"] or None,
            "source_ip": m["ip"],
            "port": int(m["port"]) if m["port"] else None,
            "invalid_user": True,
        }
        return AuthEvent.INVALID_USER, fields, occurrences
    if process == "sudo" and (m := _SUDO.match(message)):
        fields = {"user": m["user"], "command": m["cmd"].strip()}
        if m["fails"]:
            # "alice : 3 incorrect password attempts ; ..." means three failed attempts.
            return AuthEvent.SUDO_FAILURE, fields, occurrences * int(m["fails"])
        return AuthEvent.SUDO_COMMAND, fields, occurrences
    if process == "useradd" and (m := _USERADD.match(message)):
        return AuthEvent.USER_CREATED, {"user": m["user"]}, occurrences
    return AuthEvent.OTHER, {}, occurrences


def parse_auth_lines(
    lines: Iterable[str], year: int | None = None, now: datetime | None = None
) -> ParseResult:
    """Parse auth.log lines into a normalised event table.

    BSD syslog timestamps carry no year. ``year`` defaults to the current year,
    a December -> January wrap inside the file advances the year, and if the
    inferred timestamps land in the future (e.g. analysing December logs in
    January) everything is shifted back one year.
    """
    now = now or datetime.now()
    explicit_year = year is not None
    current_year = year if explicit_year else now.year
    previous_month: int | None = None

    records: list[dict] = []
    total = unparsed = 0
    for line_no, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        total += 1
        match = SYSLOG_LINE.match(line)
        if not match:
            unparsed += 1
            continue

        if match["month"]:
            month = MONTHS[match["month"]]
            if previous_month is not None and month < previous_month - 6:
                current_year += 1
            previous_month = month
        try:
            timestamp = _timestamp(match, current_year)
        except ValueError:  # e.g. "Feb 30"
            unparsed += 1
            continue

        process = match["process"]
        event, fields, occurrences = _classify(process, match["message"])
        record = {
            "timestamp": timestamp,
            "host": match["host"],
            "process": process,
            "event": event,
            "raw": line,
            "line_no": line_no,
            **fields,
        }
        records.extend([record] * occurrences)

    events = frame(records, AUTH_COLUMNS)
    events["invalid_user"] = events["invalid_user"].astype("boolean").fillna(False).astype(bool)
    events["port"] = events["port"].astype("Int64")

    if not explicit_year and not events.empty:
        has_bsd_dates = events["raw"].str.match(r"^[A-Z][a-z]{2}\s").any()
        if has_bsd_dates and events["timestamp"].max() > pd.Timestamp(now) + pd.Timedelta(days=1):
            events["timestamp"] = events["timestamp"] - pd.DateOffset(years=1)

    return ParseResult(events=events, total_lines=total, unparsed_lines=unparsed)
