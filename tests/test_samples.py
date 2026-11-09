"""Ground truth: samples/ is generated with known attacks (scripts/generate_samples.py).
Every planted attack must be found, and benign traffic must not be flagged."""

from loganalyzer.models import Severity

ATTACKER_NET = "203.0.113."


def rules_by_ip(analysis):
    return {(f.rule, f.source_ip) for f in analysis.findings}


def test_auth_sample_is_fully_parsed(auth_analysis):
    assert auth_analysis.unparsed_lines == 0
    assert auth_analysis.events["timestamp"].dt.year.unique().tolist() == [2026]


def test_auth_sample_planted_attacks_are_detected(auth_analysis):
    found = rules_by_ip(auth_analysis)
    assert ("ssh.bruteforce", "203.0.113.45") in found
    assert ("ssh.password_spraying", "203.0.113.23") in found
    assert ("ssh.success_after_failures", "203.0.113.77") in found
    assert ("ssh.root_login", "10.0.1.15") in found
    rules = {f.rule for f in auth_analysis.findings}
    assert {
        "account.created",
        "sudo.sensitive_command",
        "sudo.auth_failure",
        "volume.spike",
    } <= rules


def test_auth_sample_compromise_is_the_top_finding(auth_analysis):
    top = auth_analysis.findings[0]
    assert top.severity is Severity.CRITICAL
    assert top.user == "deploy"


def test_auth_sample_background_noise_is_not_high_severity(auth_analysis):
    for finding in auth_analysis.findings_at_or_above(Severity.HIGH):
        assert finding.source_ip.startswith(ATTACKER_NET), finding


def test_web_sample_planted_attacks_are_detected(web_analysis):
    titles = {(f.title.split(" (")[0], f.source_ip) for f in web_analysis.findings}
    assert ("SQL injection attempt", "203.0.113.66") in titles
    assert ("Cross-site scripting attempt", "203.0.113.75") in titles
    assert ("Path traversal attempt", "203.0.113.150") in titles
    assert ("Command injection attempt", "203.0.113.150") in titles
    assert ("Log4Shell", "203.0.113.150") in titles
    found = rules_by_ip(web_analysis)
    assert ("web.login_bruteforce", "203.0.113.99") in found
    assert ("web.forced_browsing", "203.0.113.10") in found
    assert ("web.scanner_user_agent", "203.0.113.10") in found
    assert ("web.request_flood", "203.0.113.180") in found


def test_web_sample_exposed_env_file_is_high(web_analysis):
    (probe,) = [f for f in web_analysis.findings if f.rule == "web.sensitive_file_probe"]
    assert probe.severity is Severity.HIGH
    assert "/.env" in probe.description


def test_web_sample_ml_surfaces_the_quiet_exfiltration(web_analysis):
    ml = [f for f in web_analysis.findings if f.rule == "ml.behavior_outlier"]
    assert [f.source_ip for f in ml] == ["203.0.113.200"]
    assert "bytes per request" in ml[0].description


def test_web_sample_sqli_catches_every_payload(web_analysis):
    (sqli,) = [f for f in web_analysis.findings if f.title == "SQL injection attempt"]
    assert sqli.event_count == 120


def test_web_sample_no_background_client_is_flagged(web_analysis):
    flagged = {f.source_ip for f in web_analysis.findings if f.source_ip}
    assert all(ip.startswith(ATTACKER_NET) for ip in flagged), flagged
