import gzip
import json

import pandas as pd
import pytest
from conftest import DAY, access, failed

from loganalyzer import analyze_logs
from loganalyzer.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from loganalyzer.models import Severity
from loganalyzer.report import render_log_report
from loganalyzer.tabular import analyze_table, clean_table, feature_columns


def test_logs_command_writes_all_outputs(samples, tmp_path):
    code = main(["logs", str(samples / "auth.log"), "-o", str(tmp_path), "--year", "2026"])
    assert code == EXIT_OK
    assert {p.name for p in tmp_path.iterdir()} == {"report.html", "findings.json", "events.csv"}
    payload = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert payload["summary"]["findings_by_severity"]["critical"] == 1
    assert payload["findings"][0]["mitre_attack"] == "T1078"


def test_fail_on_sets_exit_code(samples, tmp_path):
    args = ["logs", str(samples / "access.log"), "-o", str(tmp_path), "--no-html"]
    assert main([*args, "--fail-on", "high"]) == EXIT_FINDINGS
    assert main([*args, "--fail-on", "critical"]) == EXIT_OK


def test_json_flag_prints_machine_readable_output(samples, tmp_path, capsys):
    main(["logs", str(samples / "access.log"), "-o", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "access"
    assert len(payload["findings"]) == sum(payload["summary"]["findings_by_severity"].values())


def test_bruteforce_threshold_flag(samples, tmp_path):
    main(
        [
            "logs",
            str(samples / "auth.log"),
            "-o",
            str(tmp_path),
            "--year",
            "2026",
            "--bruteforce-threshold",
            "100",
            "--no-html",
        ]
    )
    rules = [f["rule"] for f in json.loads((tmp_path / "findings.json").read_text())["findings"]]
    assert "ssh.bruteforce" not in rules


def test_gzip_and_multiple_files(tmp_path):
    part1 = tmp_path / "auth.log.1"
    part1.write_text("\n".join(failed(DAY, "203.0.113.1") for _ in range(6)) + "\n")
    part2 = tmp_path / "auth.log.2.gz"
    with gzip.open(part2, "wt") as fh:
        fh.write("\n".join(failed(DAY, "203.0.113.1") for _ in range(6)) + "\n")
    analysis = analyze_logs([part1, part2], year=2026)
    assert len(analysis.events) == 12
    assert any(f.rule == "ssh.bruteforce" for f in analysis.findings)


@pytest.mark.parametrize(
    ("files", "message"),
    [
        (["missing.log"], "file not found"),
        (["mixed"], "analyse them separately"),
        (["empty"], "file is empty"),
    ],
)
def test_input_errors_exit_2(tmp_path, capsys, files, message):
    (tmp_path / "a.log").write_text(failed(DAY, "1.2.3.4") + "\n")
    (tmp_path / "b.log").write_text(access("1.2.3.4", "/") + "\n")
    (tmp_path / "empty.log").write_text("")
    paths = {
        "missing.log": [str(tmp_path / "missing.log")],
        "mixed": [str(tmp_path / "a.log"), str(tmp_path / "b.log")],
        "empty": [str(tmp_path / "empty.log")],
    }[files[0]]
    assert main(["logs", *paths, "-o", str(tmp_path / "out")]) == EXIT_ERROR
    assert message in capsys.readouterr().err


def test_report_escapes_attacker_controlled_log_content(tmp_path):
    """Log lines are attacker-controlled. The HTML report must never execute them."""
    payload = "<script>alert('pwned')</script>"
    lines = [access("203.0.113.5", f"/search?q={payload}", 200, ua=payload)]
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n")
    html = render_log_report(analyze_logs([log]))
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_report_renders_with_no_findings(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(access("198.51.100.1", "/") + "\n")
    analysis = analyze_logs([log])
    assert analysis.findings_at_or_above(Severity.LOW) == []
    assert "No findings" in render_log_report(analysis)


# --- data subcommand --------------------------------------------------------------------------


def test_clean_table_conversions_are_logged():
    raw = pd.DataFrame(
        {
            "amount": ["1,200", "300", "45", "45"],
            "when": ["2026-01-01", "2026-01-02", "2026-01-03", "2026-01-03"],
            "exercise": ["None", "Daily", "Weekly", "Weekly"],
        }
    )
    cleaned, notes = clean_table(raw)
    assert cleaned["amount"].tolist() == [1200, 300, 45]
    assert pd.api.types.is_datetime64_any_dtype(cleaned["when"])
    assert any("duplicate" in n for n in notes)


def test_none_is_a_category_not_missing(tmp_path):
    csv = tmp_path / "survey.csv"
    csv.write_text("exercise,score\nNone,1\nDaily,2\nNA,3\n")
    result = analyze_table(csv)
    assert result.data["exercise"].tolist()[:2] == ["None", "Daily"]
    assert result.data["exercise"].isna().sum() == 1


def test_feature_columns_skip_identifiers():
    df = pd.DataFrame(
        {"ID": range(50), "user_id": range(50), "x": [1.0, 2.0] * 25, "const": [1] * 50}
    )
    assert feature_columns(df) == ["x"]


def test_data_command(samples, tmp_path):
    assert main(["data", str(samples / "workouts.csv"), "-o", str(tmp_path)]) == EXIT_OK
    html = (tmp_path / "data_report.html").read_text(encoding="utf-8")
    assert "Anomalous rows" in html and "<svg" in html
    assert len(pd.read_csv(tmp_path / "cleaned_data.csv")) == 162


def test_output_never_crashes_on_legacy_windows_encodings(monkeypatch):
    """Regression (found by Windows CI): cp1252 output cannot encode '→' or '●'."""
    import io
    import sys

    from loganalyzer.cli import safe_streams

    raw = io.BytesIO()
    legacy = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", legacy)
    safe_streams()
    legacy.write("09:00  →  10:00 · ● 3 high · ✓")
    legacy.flush()
    # Known symbols become readable ASCII; cp1252 keeps '·'; anything else degrades to '?'.
    assert raw.getvalue() == b"09:00  ->  10:00 \xb7 * 3 high \xb7 ?"


def test_logs_command_survives_a_cp1252_pipe(samples, tmp_path):
    """End to end: the real CLI, stdout encoded as cp1252 (what Windows uses for redirected output)."""
    import os
    import subprocess
    import sys

    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    result = subprocess.run(
        [sys.executable, "-m", "loganalyzer.cli", "logs", str(samples / "auth.log"),
         "--year", "2026", "-o", str(tmp_path)],
        capture_output=True,
        env=env,
    )  # fmt: skip
    output = result.stdout.decode("cp1252")
    assert result.returncode == EXIT_OK, result.stderr.decode("cp1252", errors="replace")
    assert "  ->  " in output
    assert "* " in output
