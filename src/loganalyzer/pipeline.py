"""High-level entry point: files in, parsed events + findings out."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from itertools import chain, islice
from pathlib import Path

import pandas as pd

from loganalyzer.config import DetectionConfig
from loganalyzer.detectors import run_detectors
from loganalyzer.io import iter_lines
from loganalyzer.models import Finding, Severity
from loganalyzer.parsers import PARSERS, LogFormat, UnsupportedFormatError, detect_format

SNIFF_LINES = 200


class AnalysisError(Exception):
    """User-facing error: bad input, unreadable file, mixed formats, nothing parsed."""


@dataclass
class LogAnalysis:
    sources: list[Path]
    log_format: LogFormat
    events: pd.DataFrame
    findings: list[Finding]
    total_lines: int
    unparsed_lines: int
    config: DetectionConfig = field(default_factory=DetectionConfig)
    generated_at: datetime = field(default_factory=datetime.now)

    @property
    def parse_rate(self) -> float:
        return 0.0 if not self.total_lines else 1 - self.unparsed_lines / self.total_lines

    @property
    def time_range(self) -> tuple[datetime, datetime] | None:
        if self.events.empty:
            return None
        ts = self.events["timestamp"]
        return ts.min().to_pydatetime(), ts.max().to_pydatetime()

    @property
    def unique_ips(self) -> int:
        return int(self.events["source_ip"].nunique())

    def severity_counts(self) -> dict[Severity, int]:
        counts = Counter(f.severity for f in self.findings)
        return {s: counts.get(s, 0) for s in sorted(Severity, reverse=True)}

    def findings_at_or_above(self, minimum: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= minimum]


def analyze_logs(
    paths: Sequence[str | Path],
    log_format: LogFormat | None = None,
    config: DetectionConfig | None = None,
    year: int | None = None,
) -> LogAnalysis:
    """Parse one or more log files of the same format and run every detector over them."""
    if not paths:
        raise AnalysisError("no input files given")
    cfg = config or DetectionConfig()
    sources = [Path(p) for p in paths]
    chosen = log_format
    frames: list[pd.DataFrame] = []
    total = unparsed = 0

    for path in sources:
        if not path.is_file():
            raise AnalysisError(f"{path}: file not found")
        try:
            lines = iter_lines(path)
            head = list(islice(lines, SNIFF_LINES))
            detected = log_format or detect_format(head)
            if chosen is None:
                chosen = detected
            elif detected is not chosen:
                raise AnalysisError(
                    f"{path.name} looks like a {detected.value} log but earlier files are "
                    f"{chosen.value} logs; analyse them separately"
                )
            result = PARSERS[chosen](chain(head, lines), year=year)
        except UnsupportedFormatError as exc:
            raise AnalysisError(f"{path}: {exc}") from exc
        except OSError as exc:
            raise AnalysisError(f"{path}: {exc.strerror or exc}") from exc

        result.events.insert(len(result.events.columns), "source_file", path.name)
        frames.append(result.events)
        total += result.total_lines
        unparsed += result.unparsed_lines

    assert chosen is not None
    events = pd.concat(frames, ignore_index=True)
    if events.empty:
        raise AnalysisError(f"no {chosen.value} log lines could be parsed")
    events = events.sort_values("timestamp", kind="stable").reset_index(drop=True)

    return LogAnalysis(
        sources=sources,
        log_format=chosen,
        events=events,
        findings=run_detectors(chosen, events, cfg),
        total_lines=total,
        unparsed_lines=unparsed,
        config=cfg,
    )
