"""Detection thresholds. Defaults are deliberately conservative to limit alert fatigue."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class DetectionConfig:
    # SSH / auth.log
    bruteforce_threshold: int = 10
    """Failed logins from one IP inside ``bruteforce_window`` that count as brute force."""
    bruteforce_window: timedelta = timedelta(minutes=5)
    spraying_min_users: int = 5
    """Distinct usernames tried by one IP before it counts as password spraying."""
    compromise_min_failures: int = 5
    """Failures that must precede a successful login for it to be flagged as a likely compromise."""
    sudo_failure_threshold: int = 3

    # Web access logs
    web_scan_min_4xx: int = 30
    web_scan_min_ratio: float = 0.5
    web_scan_min_paths: int = 20
    web_login_threshold: int = 20
    web_login_window: timedelta = timedelta(minutes=10)
    web_rate_per_minute: int = 300

    # Volume spikes (robust z-score over time buckets)
    spike_bucket: str = "5min"
    spike_z: float = 3.5
    spike_min_events: int = 20

    # Isolation Forest behavioural outliers
    ml_min_entities: int = 20
    ml_min_score: float = 0.6
    """Anomaly score s in (0, 1] from Liu et al. (2008): s ~ 0.5 means 'nothing distinctive',
    s close to 1 means 'clearly isolated'. Only clients above this score are reported."""

    evidence_lines: int = 3
    random_state: int = 42
