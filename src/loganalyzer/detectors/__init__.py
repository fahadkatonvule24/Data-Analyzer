"""Detection engine: rule-based detectors per log format, plus format-agnostic anomaly checks."""

from __future__ import annotations

import pandas as pd

from loganalyzer.config import DetectionConfig
from loganalyzer.detectors.anomaly import detect_behavioral_outliers, detect_volume_spikes
from loganalyzer.detectors.auth import AUTH_DETECTORS
from loganalyzer.detectors.web import WEB_DETECTORS, web_features
from loganalyzer.models import Finding
from loganalyzer.parsers import AuthEvent, LogFormat


def run_detectors(
    log_format: LogFormat, events: pd.DataFrame, cfg: DetectionConfig
) -> list[Finding]:
    findings: list[Finding] = []

    if log_format is LogFormat.AUTH:
        for detector in AUTH_DETECTORS:
            findings.extend(detector(events, cfg))
        failures = events.loc[events["event"] == AuthEvent.FAILURE, "timestamp"]
        findings.extend(detect_volume_spikes(failures, cfg, "failed logins"))
        # No Isolation Forest here: the SSH client population is small and dominated by
        # internet background scanners, so "unusual" mostly means "legitimate staff member".
    else:
        for detector in WEB_DETECTORS:
            findings.extend(detector(events, cfg))
        findings.extend(detect_volume_spikes(events["timestamp"], cfg, "requests"))
        flagged = {f.source_ip for f in findings if f.source_ip}
        findings.extend(detect_behavioral_outliers(web_features(events), cfg, flagged))

    return sorted(
        findings,
        key=lambda f: (-f.severity, f.first_seen is None, f.first_seen or pd.Timestamp.min),
    )


__all__ = ["run_detectors"]
