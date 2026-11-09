"""Detections for Linux authentication logs."""

from __future__ import annotations

import re

import pandas as pd

from loganalyzer.config import DetectionConfig
from loganalyzer.detectors.base import (
    evidence,
    humanize,
    peak_in_window,
    plural,
    time_bounds,
    top_values,
)
from loganalyzer.models import Finding, Severity
from loganalyzer.parsers import AuthEvent

# Sudo commands worth a second look, with the reason shown to the analyst.
SENSITIVE_SUDO: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:^|/)(?:ba|z|da|k|c)?sh(?:\s+-i)?\s*$"), "interactive root shell"),
    (re.compile(r"(?:^|/)su(?:\s|$)"), "switch user"),
    (re.compile(r"/etc/(?:shadow|sudoers|passwd)\b"), "credential / privilege file access"),
    (re.compile(r"\b(?:useradd|usermod|adduser|passwd)\b"), "account manipulation"),
    (re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:ba)?sh\b"), "remote script piped to shell"),
    (
        re.compile(r"\b(?:iptables\s+-F|ufw\s+disable|setenforce\s+0)\b"),
        "security control disabled",
    ),
    (
        re.compile(r"\bhistory\s+-c\b|\b(?:rm|shred|truncate)\b.*?/var/log/"),
        "possible log tampering",
    ),
    (
        re.compile(r"\bchmod\s+(?:-R\s+)?[0-7]?777\b|\bchmod\s+[ug]?\+s\b"),
        "dangerous permission change",
    ),
]


def detect_bruteforce(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    failures = events[events["event"] == AuthEvent.FAILURE]
    findings = []
    for ip, group in failures.groupby("source_ip", sort=False):
        peak = peak_in_window(group["timestamp"], cfg.bruteforce_window)
        if peak < cfg.bruteforce_threshold:
            continue
        first, last = time_bounds(group)
        findings.append(
            Finding(
                rule="ssh.bruteforce",
                title="SSH brute-force attack",
                severity=Severity.HIGH,
                description=(
                    f"{len(group)} failed SSH logins from {ip}, peaking at {peak} within "
                    f"{humanize(cfg.bruteforce_window)}. Accounts targeted: {top_values(group['user'])}."
                ),
                event_count=len(group),
                first_seen=first,
                last_seen=last,
                source_ip=str(ip),
                mitre="T1110.001",
                evidence=evidence(group, cfg.evidence_lines),
            )
        )
    return findings


def detect_password_spraying(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    attempts = events[events["event"].isin([AuthEvent.FAILURE, AuthEvent.INVALID_USER])]
    findings = []
    for ip, group in attempts.groupby("source_ip", sort=False):
        users = group["user"].dropna().unique()
        if len(users) < cfg.spraying_min_users:
            continue
        # sshd logs "Invalid user x" *and* "Failed password for invalid user x" for one attempt.
        attempt_count = max(
            int((group["event"] == AuthEvent.FAILURE).sum()),
            int((group["event"] == AuthEvent.INVALID_USER).sum()),
        )
        invalid = group.loc[group["invalid_user"], "user"].dropna().nunique()
        failed_rows = group[group["event"] == AuthEvent.FAILURE]
        tried = (failed_rows if not failed_rows.empty else group)["user"]
        first, last = time_bounds(group)
        findings.append(
            Finding(
                rule="ssh.password_spraying",
                title="Password spraying / username enumeration",
                severity=Severity.HIGH,
                description=(
                    f"{ip} tried {len(users)} different usernames ({invalid} do not exist on the "
                    f"host) over {attempt_count} attempts: {top_values(tried, 8)}."
                ),
                event_count=attempt_count,
                first_seen=first,
                last_seen=last,
                source_ip=str(ip),
                mitre="T1110.003",
                evidence=evidence(group, cfg.evidence_lines),
            )
        )
    return findings


def detect_success_after_failures(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    """A login that succeeds after a run of failures from the same IP is the classic
    'brute force worked' signal and the most urgent thing in an auth log."""
    failures = events[events["event"] == AuthEvent.FAILURE]
    successes = events[events["event"] == AuthEvent.SUCCESS].sort_values("timestamp")
    findings = []
    for (ip, user), group in successes.groupby(["source_ip", "user"], sort=False):
        login = group.iloc[0]
        prior = failures[
            (failures["source_ip"] == ip) & (failures["timestamp"] <= login["timestamp"])
        ]
        if len(prior) < cfg.compromise_min_failures:
            continue
        rows = pd.concat([prior.tail(cfg.evidence_lines - 1), group.head(1)])
        findings.append(
            Finding(
                rule="ssh.success_after_failures",
                title="Successful login after repeated failures",
                severity=Severity.CRITICAL,
                description=(
                    f"'{user}' logged in from {ip} at {login['timestamp']:%Y-%m-%d %H:%M:%S} "
                    f"via {login['auth_method']} after {len(prior)} failed attempts from the same "
                    "address. Treat the account as compromised until proven otherwise."
                ),
                event_count=len(prior) + 1,
                first_seen=prior["timestamp"].min().to_pydatetime(),
                last_seen=login["timestamp"].to_pydatetime(),
                source_ip=str(ip),
                user=str(user),
                mitre="T1078",
                evidence=evidence(rows, cfg.evidence_lines),
            )
        )
    return findings


def detect_root_login(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    root = events[(events["event"] == AuthEvent.SUCCESS) & (events["user"] == "root")]
    findings = []
    for ip, group in root.groupby("source_ip", sort=False):
        first, last = time_bounds(group)
        findings.append(
            Finding(
                rule="ssh.root_login",
                title="Direct root login over SSH",
                severity=Severity.MEDIUM,
                description=(
                    f"root logged in directly from {ip} ({len(group)}x). Direct root login removes "
                    "per-user accountability; set 'PermitRootLogin no' and use sudo."
                ),
                event_count=len(group),
                first_seen=first,
                last_seen=last,
                source_ip=str(ip),
                user="root",
                mitre="T1078.003",
                evidence=evidence(group, cfg.evidence_lines),
            )
        )
    return findings


def detect_user_created(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    created = events[events["event"] == AuthEvent.USER_CREATED]
    return [
        Finding(
            rule="account.created",
            title="New local account created",
            severity=Severity.MEDIUM,
            description=(
                f"Account '{row['user']}' was created on {row['host']}. Confirm it matches an "
                "approved change; attackers add accounts for persistence."
            ),
            event_count=1,
            first_seen=row["timestamp"].to_pydatetime(),
            last_seen=row["timestamp"].to_pydatetime(),
            user=str(row["user"]),
            mitre="T1136.001",
            evidence=(str(row["raw"]),),
        )
        for row in created.to_dict("records")
    ]


def detect_sensitive_sudo(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    sudo = events[events["event"] == AuthEvent.SUDO_COMMAND]
    findings = []
    for user, group in sudo.groupby("user", sort=False):
        reasons: dict[str, list[str]] = {}
        matched_index = []
        for idx, command in group["command"].items():
            for pattern, reason in SENSITIVE_SUDO:
                if pattern.search(command):
                    reasons.setdefault(reason, []).append(command)
                    matched_index.append(idx)
                    break
        if not reasons:
            continue
        rows = group.loc[matched_index]
        first, last = time_bounds(rows)
        summary = "; ".join(f"{reason}: {cmds[0]}" for reason, cmds in reasons.items())
        findings.append(
            Finding(
                rule="sudo.sensitive_command",
                title="Sensitive command run with sudo",
                severity=Severity.MEDIUM,
                description=(
                    f"{user} ran {plural(len(rows), 'sensitive command')} as root — {summary}."
                ),
                event_count=len(rows),
                first_seen=first,
                last_seen=last,
                user=str(user),
                mitre="T1548.003",
                evidence=evidence(rows, cfg.evidence_lines),
            )
        )
    return findings


def detect_sudo_failures(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    failures = events[events["event"] == AuthEvent.SUDO_FAILURE]
    findings = []
    for user, group in failures.groupby("user", sort=False):
        if len(group) < cfg.sudo_failure_threshold:
            continue
        first, last = time_bounds(group)
        findings.append(
            Finding(
                rule="sudo.auth_failure",
                title="Repeated sudo password failures",
                severity=Severity.LOW,
                description=(
                    f"{user} entered a wrong sudo password {len(group)} times. Usually a typo; "
                    "worth checking if the account was also involved in other findings."
                ),
                event_count=len(group),
                first_seen=first,
                last_seen=last,
                user=str(user),
                mitre="T1548.003",
                evidence=evidence(group, cfg.evidence_lines),
            )
        )
    return findings


AUTH_DETECTORS = (
    detect_success_after_failures,
    detect_bruteforce,
    detect_password_spraying,
    detect_root_login,
    detect_user_created,
    detect_sensitive_sudo,
    detect_sudo_failures,
)
