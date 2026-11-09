from datetime import datetime

import pytest
from conftest import DAY, accepted, access, failed, syslog

from loganalyzer.parsers import (
    AuthEvent,
    LogFormat,
    UnsupportedFormatError,
    detect_format,
    parse_access_lines,
    parse_auth_lines,
)
from loganalyzer.parsers.access import parse_clf_time

# --- auth.log ---------------------------------------------------------------------------------


def test_failed_password_for_invalid_user():
    events = parse_auth_lines([failed(DAY, "203.0.113.5", "admin", invalid=True)], year=2026).events
    row = events.iloc[0]
    assert row["event"] == AuthEvent.FAILURE
    assert row["user"] == "admin"
    assert row["source_ip"] == "203.0.113.5"
    assert row["port"] == 50000
    assert row["auth_method"] == "password"
    assert bool(row["invalid_user"]) is True
    assert row["timestamp"] == DAY


def test_accepted_publickey():
    line = syslog(
        DAY, "Accepted publickey for alice from 10.0.0.5 port 50022 ssh2: ED25519 SHA256:abc"
    )
    row = parse_auth_lines([line], year=2026).events.iloc[0]
    assert (row["event"], row["user"], row["auth_method"]) == (
        AuthEvent.SUCCESS,
        "alice",
        "publickey",
    )


def test_message_repeated_expands_to_individual_events():
    line = syslog(
        DAY, "message repeated 3 times: [ Failed password for root from 203.0.113.9 port 22 ssh2]"
    )
    events = parse_auth_lines([line], year=2026).events
    assert len(events) == 3
    assert set(events["event"]) == {AuthEvent.FAILURE}


def test_sudo_command_and_failed_attempts():
    ok = syslog(
        DAY,
        "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
        "sudo",
    )
    bad = syslog(
        DAY,
        "   bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls",
        "sudo",
    )
    events = parse_auth_lines([ok, bad], year=2026).events
    assert events.iloc[0]["event"] == AuthEvent.SUDO_COMMAND
    assert events.iloc[0]["command"] == "/usr/bin/apt update"
    assert (events["event"] == AuthEvent.SUDO_FAILURE).sum() == 3


def test_useradd():
    line = syslog(
        DAY, "new user: name=backdoor, UID=1005, GID=1005, home=/home/backdoor", "useradd[77]"
    )
    row = parse_auth_lines([line], year=2026).events.iloc[0]
    assert (row["event"], row["user"]) == (AuthEvent.USER_CREATED, "backdoor")


def test_rfc3339_timestamps_are_normalised_to_utc():
    line = "2026-03-14T05:00:00.123456+03:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    row = parse_auth_lines([line]).events.iloc[0]
    assert row["timestamp"] == datetime(2026, 3, 14, 2, 0, 0, 123456)


@pytest.mark.parametrize("offset", ["Z", "+00:00", "+0000"])
def test_rfc3339_offset_variants(offset):
    line = f"2026-03-14T02:00:00{offset} web01 sshd[1]: Invalid user x from 1.2.3.4 port 22"
    assert parse_auth_lines([line]).events.iloc[0]["timestamp"] == datetime(2026, 3, 14, 2, 0)


def test_unparseable_lines_are_counted_not_fatal():
    result = parse_auth_lines(["garbage", "", failed(DAY, "1.2.3.4")], year=2026)
    assert (result.total_lines, result.unparsed_lines, len(result.events)) == (2, 1, 1)


def test_year_rolls_over_from_december_to_january():
    lines = [
        failed(datetime(2025, 12, 31, 23, 59), "1.2.3.4"),
        failed(datetime(2026, 1, 1, 0, 1), "1.2.3.4"),
    ]
    ts = parse_auth_lines(lines, year=2025).events["timestamp"]
    assert [t.year for t in ts] == [2025, 2026]


def test_inferred_year_never_lands_in_the_future():
    # Analysing December logs in early January: they belong to last year.
    lines = [failed(datetime(2000, 12, 30, 10, 0), "1.2.3.4")]
    ts = parse_auth_lines(lines, now=datetime(2026, 1, 5)).events["timestamp"].iloc[0]
    assert ts.year == 2025


# --- access.log -------------------------------------------------------------------------------


def test_combined_log_line():
    line = (
        '203.0.113.7 - frank [14/Mar/2026:10:00:00 +0200] "POST /login?next=%2F HTTP/1.1" 401 532 '
        '"https://shop.example.com/login" "Mozilla/5.0 (X11; Linux x86_64)"'
    )
    row = parse_access_lines([line]).events.iloc[0]
    assert row["timestamp"] == datetime(2026, 3, 14, 8, 0, 0)  # +0200 -> UTC
    assert (row["method"], row["path"], row["protocol"]) == ("POST", "/login?next=%2F", "HTTP/1.1")
    assert (row["status"], row["bytes"], row["user"]) == (401, 532, "frank")
    assert row["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64)"


def test_common_log_format_without_referrer_and_dash_bytes():
    line = '10.0.0.1 - - [14/Mar/2026:10:00:00 +0000] "GET / HTTP/1.0" 304 -'
    row = parse_access_lines([line]).events.iloc[0]
    assert row["bytes"] == 0
    assert row["user_agent"] is None or row["user_agent"] != row["user_agent"]  # None / NaN


def test_malformed_request_keeps_raw_target():
    line = r'198.51.100.9 - - [14/Mar/2026:10:00:00 +0000] "\x16\x03\x01\x02\x00" 400 157 "-" "-"'
    row = parse_access_lines([line]).events.iloc[0]
    assert row["method"] is None
    assert row["path"].startswith("\\x16")


def test_escaped_quotes_inside_user_agent():
    line = (
        '1.2.3.4 - - [14/Mar/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "evil \\"agent\\" 1.0"'
    )
    assert parse_access_lines([line]).unparsed_lines == 0


def test_clf_time_parsing_is_locale_independent():
    assert parse_clf_time("01/Dec/2025:23:59:59 -0500") == datetime(2025, 12, 2, 4, 59, 59)
    with pytest.raises(ValueError):
        parse_clf_time("01/Foo/2025:23:59:59 +0000")


# --- format detection -------------------------------------------------------------------------


def test_detect_format():
    assert detect_format([failed(DAY, "1.2.3.4")] * 3) is LogFormat.AUTH
    assert detect_format([access("1.2.3.4", "/")] * 3) is LogFormat.ACCESS


@pytest.mark.parametrize("sample", [[], ["", "  "], ["a,b,c", "1,2,3", "4,5,6"]])
def test_detect_format_rejects_unknown_input(sample):
    with pytest.raises(UnsupportedFormatError):
        detect_format(sample)


def test_accepted_helper_round_trips():
    row = parse_auth_lines([accepted(DAY, "1.2.3.4", "carol")], year=2026).events.iloc[0]
    assert row["user"] == "carol"
