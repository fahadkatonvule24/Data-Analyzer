"""Command-line interface.

loganalyzer logs /var/log/auth.log                 # analyse, print findings, write reports
loganalyzer logs access.log* --fail-on high        # non-zero exit if anything high or worse
loganalyzer logs auth.log --json | jq '.findings'  # machine-readable output
loganalyzer data measurements.csv                  # general dataset profiling / anomalies
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from loganalyzer import __version__
from loganalyzer.config import DetectionConfig
from loganalyzer.models import Severity
from loganalyzer.parsers import LogFormat
from loganalyzer.pipeline import AnalysisError, LogAnalysis, analyze_logs

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red3",
    Severity.HIGH: "bold red3",
    Severity.MEDIUM: "bold dark_orange",
    Severity.LOW: "grey50",
    Severity.INFO: "grey50",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loganalyzer",
        description="Security log analysis for SSH auth logs and web access logs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{logs,data}")

    logs = sub.add_parser("logs", help="analyse auth.log / access.log files for attacks")
    logs.add_argument("paths", nargs="+", type=Path, help="log files (same format; .gz supported)")
    logs.add_argument(
        "-f",
        "--format",
        choices=["auto", *(f.value for f in LogFormat)],
        default="auto",
        help="log format (default: detect from content)",
    )
    logs.add_argument(
        "-o",
        "--out",
        type=Path,
        default=Path("loganalyzer-report"),
        help="output directory (default: %(default)s)",
    )
    logs.add_argument(
        "--year", type=int, help="year for syslog timestamps that omit it (default: infer)"
    )
    logs.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        type=Severity.parse,
        help="exit with status 1 if any finding is at or above this severity "
        "(info, low, medium, high, critical)",
    )
    logs.add_argument("--json", action="store_true", help="print findings as JSON to stdout")
    logs.add_argument("--no-html", action="store_true", help="skip the HTML report")
    logs.add_argument(
        "--brief", action="store_true", help="omit finding descriptions in the terminal"
    )
    tuning = logs.add_argument_group("detection tuning")
    tuning.add_argument(
        "--bruteforce-threshold",
        type=int,
        metavar="N",
        default=DetectionConfig.bruteforce_threshold,
        help="failed logins per window that count as brute force (default: %(default)s)",
    )
    tuning.add_argument(
        "--window",
        type=int,
        metavar="MINUTES",
        default=int(DetectionConfig.bruteforce_window.total_seconds() // 60),
        help="brute-force sliding window in minutes (default: %(default)s)",
    )

    data = sub.add_parser(
        "data", help="profile a CSV/Excel/JSON/Parquet dataset and flag anomalies"
    )
    data.add_argument("path", type=Path)
    data.add_argument(
        "-o",
        "--out",
        type=Path,
        default=Path("loganalyzer-report"),
        help="output directory (default: %(default)s)",
    )
    data.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="expected share of anomalous rows (default: %(default)s)",
    )
    return parser


def safe_streams() -> None:
    """Never crash on output: legacy Windows consoles (cp1252) cannot encode characters like '→'."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if encoding and encoding != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def main(argv: Sequence[str] | None = None) -> int:
    safe_streams()
    args = build_parser().parse_args(argv)
    console = Console(highlight=False)
    errors = Console(stderr=True, highlight=False, soft_wrap=True)
    try:
        if args.command == "logs":
            return run_logs(args, console)
        return run_data(args, console)
    except AnalysisError as exc:
        errors.print(f"[bold red]error:[/] {escape(str(exc))}")
        return EXIT_ERROR
    except ValueError as exc:  # DataError and friends
        errors.print(f"[bold red]error:[/] {escape(str(exc))}")
        return EXIT_ERROR


def run_logs(args: argparse.Namespace, console: Console) -> int:
    from loganalyzer.report import write_log_outputs
    from loganalyzer.report.html import findings_payload

    config = DetectionConfig(
        bruteforce_threshold=args.bruteforce_threshold,
        bruteforce_window=timedelta(minutes=args.window),
    )
    log_format = None if args.format == "auto" else LogFormat(args.format)
    analysis = analyze_logs(args.paths, log_format=log_format, config=config, year=args.year)
    written = write_log_outputs(analysis, args.out, html=not args.no_html)

    if args.json:
        sys.stdout.write(json.dumps(findings_payload(analysis), indent=2) + "\n")
    else:
        print_summary(analysis, console, brief=args.brief)
        print_outputs(written, console)

    if args.fail_on is not None and analysis.findings_at_or_above(args.fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


def print_summary(analysis: LogAnalysis, console: Console, brief: bool = False) -> None:
    time_range = analysis.time_range
    header = Text.assemble(
        (", ".join(p.name for p in analysis.sources), "bold"),
        ("  ·  " + analysis.log_format.description, "grey50"),
        "\n",
        f"{analysis.total_lines:,} lines  ·  {analysis.parse_rate:.1%} parsed  ·  "
        f"{len(analysis.events):,} events  ·  {analysis.unique_ips:,} source IPs",
    )
    if time_range:
        header.append(
            f"\n{time_range[0]:%d %b %Y %H:%M}  →  {time_range[1]:%d %b %Y %H:%M}", "grey50"
        )
    console.print(
        Panel(
            header,
            title=f"[bold]Log Analyzer[/] {__version__}",
            title_align="left",
            border_style="grey50",
            padding=(0, 1),
        )
    )

    counts = Text("Findings  ", style="bold")
    shown = [(s, n) for s, n in analysis.severity_counts().items() if n]
    for severity, n in shown:
        counts.append(
            "● ", style=SEVERITY_STYLE[severity].replace("on red3", "").replace("white", "red3")
        )
        counts.append(f"{n} {severity.label}   ")
    if not shown:
        counts.append("none — no detector crossed its threshold", style="green")
    console.print(counts)
    if not analysis.findings:
        return

    table = Table(
        show_edge=False,
        header_style="bold grey50",
        pad_edge=False,
        expand=True,
        box=None,
        padding=(0, 1),
        show_lines=not brief,
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Finding", ratio=1)
    table.add_column("Source", no_wrap=True)
    table.add_column("Events", justify="right", no_wrap=True)
    table.add_column("ATT&CK", no_wrap=True)
    for f in analysis.findings:
        finding = Text(f.title, style="bold")
        if not brief:
            finding.append("\n" + f.description, style="grey62")
        table.add_row(
            Text(f" {f.severity.name} ", style=SEVERITY_STYLE[f.severity]),
            finding,
            f.source_ip or (f"user {f.user}" if f.user else "—"),
            f"{f.event_count:,}",
            f.mitre or "—",
        )
    console.print()
    console.print(table)


def print_outputs(written: dict[str, Path], console: Console) -> None:
    console.print()
    labels = {"html": "HTML report", "json": "Findings (JSON)", "events": "Parsed events (CSV)"}
    for key in ("html", "json", "events"):
        if key in written:
            console.print(f"[grey50]{labels[key]:<20}[/] {escape(str(written[key]))}")


def run_data(args: argparse.Namespace, console: Console) -> int:
    from loganalyzer.report import render_data_report
    from loganalyzer.tabular import analyze_table

    result = analyze_table(args.path, contamination=args.contamination)
    args.out.mkdir(parents=True, exist_ok=True)
    report = args.out / "data_report.html"
    report.write_text(render_data_report(result), encoding="utf-8")
    cleaned = args.out / "cleaned_data.csv"
    result.data.to_csv(cleaned, index=False)

    rows, cols = result.data.shape
    body = Text.assemble(
        (result.source.name, "bold"),
        f"\n{rows:,} rows × {cols} columns after cleaning  ·  {result.missing_pct:.1f}% cells missing",
        f"\n{result.anomaly_count} anomalous rows (Isolation Forest)",
        f"  ·  {result.k} clusters (silhouette {result.silhouette:.2f})" if result.k else "",
    )
    console.print(
        Panel(
            body,
            title=f"[bold]Data Analyzer[/] {__version__}",
            title_align="left",
            border_style="grey50",
            padding=(0, 1),
        )
    )
    for note in result.notes:
        console.print(f"  [grey50]•[/] {escape(note)}")
    console.print()
    console.print(f"[grey50]{'HTML report':<20}[/] {escape(str(report))}")
    console.print(f"[grey50]{'Cleaned data (CSV)':<20}[/] {escape(str(cleaned))}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
