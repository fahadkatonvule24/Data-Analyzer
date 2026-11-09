"""Detections for web server access logs."""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

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

# Payload signatures, matched against the URL-decoded request target (and user agent / referrer
# for header-borne attacks such as Log4Shell). Each is tuned to avoid matching normal URLs.
ATTACK_SIGNATURES: dict[str, re.Pattern[str]] = {
    "SQL injection": re.compile(
        r"\bunion\b[\s/*+]+(?:all[\s/*+]+)?select\b|'\s*(?:or|and)\s+'?\w*'?\s*=\s*'?\w*"
        r"|\b(?:and|or)\s+\d+\s*=\s*\d+\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\("
        r"|\b(?:extractvalue|updatexml)\s*\(|information_schema|;\s*drop\s+table\b"
        r"|'\s*(?:--|#)|\bxp_cmdshell\b",
        re.IGNORECASE,
    ),
    "Cross-site scripting": re.compile(
        r"<\s*script\b|javascript\s*:|\bon(?:error|load|mouseover|focus)\s*=|<\s*(?:svg|iframe|img)\b"
        r"|\balert\s*\(|document\.cookie",
        re.IGNORECASE,
    ),
    "Path traversal": re.compile(
        r"(?:\.\.[/\\]){2,}|/etc/(?:passwd|shadow|hosts)\b|\b(?:win|boot|system)\.ini\b",
        re.IGNORECASE,
    ),
    "Command injection": re.compile(
        r"[;|`&]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping)\b|\$\([^)]*\)",
        re.IGNORECASE,
    ),
    "Log4Shell (JNDI lookup)": re.compile(r"\$\{\s*(?:jndi|\$\{[^}]*\})", re.IGNORECASE),
}

SENSITIVE_PATHS = re.compile(
    r"/\.(?:env|git|svn|hg|htpasswd|htaccess|aws|ssh|DS_Store|bash_history)(?:/|$|\?)"
    r"|wp-config\.php|/phpmyadmin|/server-status|/actuator(?:/|$)|/config\.(?:php|json|ya?ml)\b"
    r"|\.(?:sql|bak|old|swp|tar\.gz|zip)(?:$|\?)|/backup\b|/id_rsa\b",
    re.IGNORECASE,
)

SCANNER_AGENTS = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|feroxbuster|ffuf|wfuzz|wpscan|nuclei"
    r"|hydra|acunetix|nessus|openvas|whatweb|commix",
    re.IGNORECASE,
)

LOGIN_PATH = re.compile(
    r"^/(?:login|signin|sign-in|wp-login\.php|xmlrpc\.php|user/login|admin/login"
    r"|api/(?:v\d+/)?(?:auth|login|token|session))(?:/|$|\?)",
    re.IGNORECASE,
)


def _decode(value: object) -> str:
    """Decode twice so double-encoded payloads (%252e%252e%252f) are caught too."""
    if not isinstance(value, str) or not value:
        return ""
    return unquote_plus(unquote_plus(value))


def detect_attack_payloads(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    if events.empty:
        return []
    target = events["path"].map(_decode)
    headers = events["user_agent"].map(_decode) + " " + events["referrer"].map(_decode)
    findings = []
    for category, pattern in ATTACK_SIGNATURES.items():
        in_target = target.str.contains(pattern)
        in_headers = headers.str.contains(pattern)
        hits = in_target | in_headers
        if not hits.any():
            continue
        for ip, group in events[hits].groupby("source_ip", sort=False):
            ok = int(group["status"].between(200, 299).sum())
            first, last = time_bounds(group)
            index = group.index[0]
            example = target[index] if in_target[index] else headers[index].strip()
            note = (
                f" {plural(ok, 'response')} returned HTTP 2xx — verify whether it succeeded."
                if ok
                else " None succeeded (all non-2xx)."
            )
            findings.append(
                Finding(
                    rule="web.attack_payload",
                    title=f"{category} attempt",
                    severity=Severity.HIGH,
                    description=(
                        f"{plural(len(group), 'request')} from {ip} carried {category} "
                        f"payloads, e.g. {example[:120]!r}.{note}"
                    ),
                    event_count=len(group),
                    first_seen=first,
                    last_seen=last,
                    source_ip=str(ip),
                    mitre="T1190",
                    evidence=evidence(group, cfg.evidence_lines),
                )
            )
    return findings


def detect_sensitive_file_probes(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    probes = events[events["path"].map(_decode).str.contains(SENSITIVE_PATHS)]
    findings = []
    for ip, group in probes.groupby("source_ip", sort=False):
        served = group[group["status"].between(200, 299)]
        first, last = time_bounds(group)
        severity = Severity.HIGH if not served.empty else Severity.MEDIUM
        exposure = (
            f" {plural(len(served), 'path')} served with HTTP 2xx: "
            f"{top_values(served['path'], 3)} — check for exposed secrets."
            if not served.empty
            else " All were blocked or missing."
        )
        findings.append(
            Finding(
                rule="web.sensitive_file_probe",
                title="Probing for sensitive files",
                severity=severity,
                description=(
                    f"{ip} requested {plural(group['path'].nunique(), 'sensitive path')} such as "
                    f"{top_values(group['path'], 3)}.{exposure}"
                ),
                event_count=len(group),
                first_seen=first,
                last_seen=last,
                source_ip=str(ip),
                mitre="T1595.003",
                evidence=evidence(served if not served.empty else group, cfg.evidence_lines),
            )
        )
    return findings


def detect_scanner_agents(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    agents = events["user_agent"].fillna("")
    tools = agents.str.extract(f"({SCANNER_AGENTS.pattern})", flags=re.IGNORECASE)[0].str.lower()
    flagged = events.assign(tool=tools).dropna(subset=["tool"])
    findings = []
    for (ip, tool), group in flagged.groupby(["source_ip", "tool"], sort=False):
        first, last = time_bounds(group)
        findings.append(
            Finding(
                rule="web.scanner_user_agent",
                title=f"Vulnerability scanner detected ({tool})",
                severity=Severity.MEDIUM,
                description=(
                    f"{ip} sent {len(group)} requests identifying as {tool}. Automated scanning "
                    "usually precedes exploitation attempts."
                ),
                event_count=len(group),
                first_seen=first,
                last_seen=last,
                source_ip=str(ip),
                mitre="T1595.002",
                evidence=evidence(group, cfg.evidence_lines),
            )
        )
    return findings


def detect_forced_browsing(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    findings = []
    for ip, group in events.groupby("source_ip", sort=False):
        client_errors = group[group["status"].between(400, 499)]
        ratio = len(client_errors) / len(group)
        distinct = client_errors["path"].nunique()
        if (
            len(client_errors) < cfg.web_scan_min_4xx
            or ratio < cfg.web_scan_min_ratio
            or distinct < cfg.web_scan_min_paths
        ):
            continue
        first, last = time_bounds(group)
        findings.append(
            Finding(
                rule="web.forced_browsing",
                title="Directory / content discovery",
                severity=Severity.MEDIUM,
                description=(
                    f"{ip} made {len(group)} requests, {ratio:.0%} of them failing with 4xx "
                    f"across {distinct} distinct paths — typical of "
                    "wordlist-driven forced browsing."
                ),
                event_count=len(group),
                first_seen=first,
                last_seen=last,
                source_ip=str(ip),
                mitre="T1595.003",
                evidence=evidence(client_errors, cfg.evidence_lines),
            )
        )
    return findings


def detect_login_bruteforce(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    path_only = events["path"].str.split("?", n=1).str[0]
    posts = events[(events["method"] == "POST") & path_only.str.contains(LOGIN_PATH)]
    findings = []
    for ip, group in posts.groupby("source_ip", sort=False):
        peak = peak_in_window(group["timestamp"], cfg.web_login_window)
        if peak < cfg.web_login_threshold:
            continue
        failed = int(group["status"].isin([401, 403, 429]).sum())
        first, last = time_bounds(group)
        findings.append(
            Finding(
                rule="web.login_bruteforce",
                title="Web login brute force / credential stuffing",
                severity=Severity.HIGH,
                description=(
                    f"{ip} sent {len(group)} login POSTs to {top_values(group['path'], 2)} "
                    f"(peak {peak} in {humanize(cfg.web_login_window)}); {failed} were rejected "
                    f"(401/403/429) and {len(group) - failed} were not."
                ),
                event_count=len(group),
                first_seen=first,
                last_seen=last,
                source_ip=str(ip),
                mitre="T1110",
                evidence=evidence(group, cfg.evidence_lines),
            )
        )
    return findings


def detect_request_flood(events: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    findings = []
    for ip, group in events.groupby("source_ip", sort=False):
        if len(group) < cfg.web_rate_per_minute:
            continue
        peak = peak_in_window(group["timestamp"], "1min")
        if peak < cfg.web_rate_per_minute:
            continue
        first, last = time_bounds(group)
        findings.append(
            Finding(
                rule="web.request_flood",
                title="Abnormally high request rate",
                severity=Severity.LOW,
                description=(
                    f"{ip} peaked at {peak} requests/minute ({len(group)} total). Could be an "
                    "aggressive crawler, scraping, or an application-layer DoS attempt."
                ),
                event_count=len(group),
                first_seen=first,
                last_seen=last,
                source_ip=str(ip),
                mitre="T1499.002",
                evidence=evidence(group, cfg.evidence_lines),
            )
        )
    return findings


WEB_DETECTORS = (
    detect_attack_payloads,
    detect_login_bruteforce,
    detect_sensitive_file_probes,
    detect_scanner_agents,
    detect_forced_browsing,
    detect_request_flood,
)


def web_features(events: pd.DataFrame) -> pd.DataFrame:
    """Per-IP behaviour profile used by the Isolation Forest."""
    if events.empty:
        return pd.DataFrame()
    grouped = events.groupby("source_ip")
    span_min = (grouped["timestamp"].max() - grouped["timestamp"].min()).dt.total_seconds() / 60
    features = pd.DataFrame(
        {
            "requests": grouped.size(),
            "distinct_paths": grouped["path"].nunique(),
            "ratio_4xx": grouped["status"].apply(lambda s: s.between(400, 499).mean()),
            "ratio_5xx": grouped["status"].apply(lambda s: s.between(500, 599).mean()),
            "bytes_per_request": grouped["bytes"].mean(),
            "post_ratio": grouped["method"].apply(lambda s: (s == "POST").mean()),
            "distinct_user_agents": grouped["user_agent"].nunique(),
        }
    )
    features["requests_per_minute"] = features["requests"] / span_min.clip(lower=1)
    return features.astype(float)
