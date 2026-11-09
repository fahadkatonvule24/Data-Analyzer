from __future__ import annotations

import json
from dataclasses import fields
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pandas as pd
from jinja2 import Environment, PackageLoader, select_autoescape

from loganalyzer.detectors.anomaly import bucket_counts, spike_buckets
from loganalyzer.models import Severity
from loganalyzer.parsers import AuthEvent, LogFormat
from loganalyzer.report import svg

if TYPE_CHECKING:
    from loganalyzer.pipeline import LogAnalysis
    from loganalyzer.tabular import TabularAnalysis

_CHART_BUCKETS_MIN = (1, 5, 15, 30, 60, 180, 360, 720, 1440)
_MAX_BARS = 120


def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("loganalyzer", "report/templates"),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["dt"] = lambda v, fmt="%Y-%m-%d %H:%M:%S": v.strftime(fmt) if v else "—"
    env.filters["num"] = lambda v: f"{v:,}" if isinstance(v, int) else f"{v:,.2f}"
    return env


def _version() -> str:
    from loganalyzer import __version__

    return __version__


def _chart_bucket(events: pd.DataFrame, minimum: str) -> int:
    span_min = (events["timestamp"].max() - events["timestamp"].min()).total_seconds() / 60
    floor = pd.Timedelta(minimum).total_seconds() / 60
    for minutes in _CHART_BUCKETS_MIN:
        if minutes >= floor and span_min / minutes <= _MAX_BARS:
            return minutes
    return _CHART_BUCKETS_MIN[-1]


def _timeline(analysis: LogAnalysis) -> dict[str, Any]:
    events, cfg = analysis.events, analysis.config
    if analysis.log_format is LogFormat.AUTH:
        stamps, unit = (
            events.loc[events["event"] == AuthEvent.FAILURE, "timestamp"],
            "failed logins",
        )
    else:
        stamps, unit = events["timestamp"], "requests"
    if stamps.empty:
        return {"svg": "", "unit": unit, "bucket": 0, "spikes": 0}

    spikes = spike_buckets(bucket_counts(stamps, cfg.spike_bucket), cfg)
    minutes = _chart_bucket(events, cfg.spike_bucket)
    counts = bucket_counts(stamps, f"{minutes}min")
    flagged = set(spikes.index.floor(f"{minutes}min"))
    buckets = [(ts.to_pydatetime(), int(n), ts in flagged) for ts, n in counts.items()]
    chart = svg.timeline(buckets, unit, minutes, f"{unit.capitalize()} per {minutes} minutes")
    bursts = sum(f.rule == "volume.spike" for f in analysis.findings)
    return {"svg": chart, "unit": unit, "bucket": minutes, "spikes": bursts}


def _top_ips(analysis: LogAnalysis, limit: int = 10) -> dict[str, Any]:
    per_finding: dict[str, int] = {}
    for f in analysis.findings:
        if f.source_ip:
            per_finding[f.source_ip] = per_finding.get(f.source_ip, 0) + 1
    events = analysis.events.dropna(subset=["source_ip"])
    if analysis.log_format is LogFormat.AUTH:
        events = events[events["event"] != AuthEvent.OTHER]
    counts = events["source_ip"].value_counts().head(limit)
    bars = [
        svg.Bar(
            label=str(ip),
            value=int(n),
            highlight=ip in per_finding,
            tooltip=f"{ip}: {n:,} events · {per_finding.get(str(ip), 0)} finding(s)",
        )
        for ip, n in counts.items()
    ]
    rows = [
        {"ip": b.label, "events": int(b.value), "findings": per_finding.get(b.label, 0)}
        for b in bars
    ]
    return {"svg": svg.hbars(bars, "Top source IPs by event count", mono=True), "rows": rows}


def _breakdown(analysis: LogAnalysis) -> dict[str, Any]:
    events = analysis.events
    if analysis.log_format is LogFormat.AUTH:
        failures = events[events["event"] == AuthEvent.FAILURE]
        counts = failures["user"].fillna("(empty)").value_counts().head(10)
        title, unit = "Most-targeted accounts", "failed logins"
    else:
        classes = (events["status"] // 100).map(lambda c: f"{c}xx")
        counts = classes.value_counts().sort_index()
        title, unit = "Responses by status class", "responses"
    bars = [svg.Bar(str(k), int(v), tooltip=f"{k}: {v:,} {unit}") for k, v in counts.items()]
    rows = [{"label": b.label, "count": int(b.value)} for b in bars]
    return {"svg": svg.hbars(bars, title), "title": title, "unit": unit, "rows": rows}


def _config_rows(analysis: LogAnalysis) -> list[tuple[str, str]]:
    rows = []
    for f in fields(analysis.config):
        value = getattr(analysis.config, f.name)
        if isinstance(value, timedelta):
            value = f"{int(value.total_seconds() // 60)} min"
        rows.append((f.name, str(value)))
    return rows


def render_log_report(analysis: LogAnalysis) -> str:
    template = _env().get_template("logs.html")
    severity_counts = analysis.severity_counts()
    return template.render(
        a=analysis,
        version=_version(),
        source_names=", ".join(p.name for p in analysis.sources),
        severity_counts=[(s, n) for s, n in severity_counts.items() if s is not Severity.INFO],
        total_findings=len(analysis.findings),
        timeline=_timeline(analysis),
        top_ips=_top_ips(analysis),
        breakdown=_breakdown(analysis),
        config_rows=_config_rows(analysis),
    )


def findings_payload(analysis: LogAnalysis) -> dict[str, Any]:
    time_range = analysis.time_range
    return {
        "tool": "loganalyzer",
        "version": _version(),
        "generated_at": analysis.generated_at.isoformat(timespec="seconds"),
        "sources": [str(p) for p in analysis.sources],
        "format": analysis.log_format.value,
        "summary": {
            "lines": analysis.total_lines,
            "unparsed_lines": analysis.unparsed_lines,
            "events": len(analysis.events),
            "unique_source_ips": analysis.unique_ips,
            "time_range": [t.isoformat() for t in time_range] if time_range else None,
            "findings_by_severity": {s.label: n for s, n in analysis.severity_counts().items()},
        },
        "findings": [f.to_dict() for f in analysis.findings],
    }


def write_log_outputs(analysis: LogAnalysis, out_dir: Path, html: bool = True) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    json_path = out_dir / "findings.json"
    json_path.write_text(json.dumps(findings_payload(analysis), indent=2), encoding="utf-8")
    written["json"] = json_path

    csv_path = out_dir / "events.csv"
    analysis.events.to_csv(csv_path, index=False)
    written["events"] = csv_path

    if html:
        html_path = out_dir / "report.html"
        html_path.write_text(render_log_report(analysis), encoding="utf-8")
        written["html"] = html_path
    return written


def render_data_report(result: TabularAnalysis) -> str:
    template = _env().get_template("data.html")
    return template.render(r=result, version=_version(), generated_at=datetime.now())
