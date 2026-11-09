"""Statistical and machine-learning detectors that apply to any log format."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from loganalyzer.config import DetectionConfig
from loganalyzer.models import Finding, Severity


def bucket_counts(timestamps: pd.Series, bucket: str) -> pd.Series:
    """Event counts per time bucket, including empty buckets (they matter for the baseline)."""
    ts = timestamps.dropna()
    if ts.empty:
        return pd.Series(dtype="int64")
    counts = ts.dt.floor(bucket).value_counts().sort_index()
    full_range = pd.date_range(counts.index.min(), counts.index.max(), freq=bucket)
    return counts.reindex(full_range, fill_value=0)


def robust_zscores(counts: pd.Series) -> pd.Series:
    """Modified z-score (Iglewicz & Hoaglin): median/MAD instead of mean/std, so the spikes we
    are trying to find do not inflate the baseline and hide themselves."""
    median = counts.median()
    mad = (counts - median).abs().median()
    scale = 1.4826 * mad
    if scale == 0:  # mostly-flat series: fall back to mean absolute deviation
        scale = 1.2533 * (counts - counts.mean()).abs().mean()
    if scale == 0:
        return pd.Series(0.0, index=counts.index)
    return (counts - median) / scale


def spike_buckets(counts: pd.Series, cfg: DetectionConfig) -> pd.Series:
    if len(counts) < 6:  # not enough history for a baseline
        return counts.iloc[0:0]
    z = robust_zscores(counts)
    return counts[(z > cfg.spike_z) & (counts >= cfg.spike_min_events)]


def detect_volume_spikes(timestamps: pd.Series, cfg: DetectionConfig, what: str) -> list[Finding]:
    counts = bucket_counts(timestamps, cfg.spike_bucket)
    spikes = spike_buckets(counts, cfg)
    if spikes.empty:
        return []
    z = robust_zscores(counts)
    step = pd.Timedelta(cfg.spike_bucket)
    baseline = counts.median()

    # Merge adjacent spike buckets into one finding per burst.
    runs: list[list[pd.Timestamp]] = []
    for ts in spikes.index:
        if runs and ts - runs[-1][-1] <= step:
            runs[-1].append(ts)
        else:
            runs.append([ts])

    findings = []
    for run in runs:
        total = int(spikes[run].sum())
        peak = int(spikes[run].max())
        start, end = run[0], run[-1] + step
        findings.append(
            Finding(
                rule="volume.spike",
                title=f"Spike in {what}",
                severity=Severity.MEDIUM,
                description=(
                    f"{total} {what} between {start:%H:%M} and {end:%H:%M} on {start:%Y-%m-%d}; "
                    f"peak {peak} per {cfg.spike_bucket} vs a typical {baseline:.0f} "
                    f"(robust z = {z[run].max():.1f})."
                ),
                event_count=total,
                first_seen=start.to_pydatetime(),
                last_seen=end.to_pydatetime(),
            )
        )
    return findings


def detect_behavioral_outliers(
    features: pd.DataFrame, cfg: DetectionConfig, already_flagged: set[str]
) -> list[Finding]:
    """Isolation Forest over per-IP behaviour profiles.

    Rules catch attacks we already know how to describe. The model ranks every client by how
    easy it is to isolate from the rest; we report outliers the rules did *not* already flag,
    which is where the model adds signal instead of duplicating alerts.
    """
    if len(features) < cfg.ml_min_entities:
        return []
    X = StandardScaler().fit_transform(np.log1p(features.clip(lower=0)))
    model = IsolationForest(n_estimators=300, random_state=cfg.random_state).fit(X)
    scores = -model.score_samples(X)  # the paper's anomaly score s: ~0.5 normal, ->1 anomalous

    median = features.median()
    spread = features.std(ddof=0).replace(0, 1)
    findings = []
    for position in np.flatnonzero(scores >= cfg.ml_min_score):
        ip = str(features.index[position])
        if ip in already_flagged:
            continue
        row = features.iloc[position]
        deviation = ((row - median).abs() / spread).sort_values(ascending=False)
        reasons = ", ".join(
            f"{name.replace('_', ' ')} {row[name]:,.2f} (median {median[name]:,.2f})"
            for name in deviation.index[:2]
        )
        findings.append(
            Finding(
                rule="ml.behavior_outlier",
                title="Anomalous client behaviour",
                severity=Severity.LOW,
                description=(
                    f"Isolation Forest ranks {ip} as an outlier (score {scores[position]:.2f}) "
                    f"though no rule fired. Most unusual: {reasons}."
                ),
                event_count=int(row.iloc[0]),
                source_ip=ip,
            )
        )
    return findings
