"""Helpers shared by detectors."""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
import pandas as pd


def peak_in_window(timestamps: pd.Series, window: timedelta | str) -> int:
    """Largest number of events falling inside any sliding window of length ``window``.

    O(n log n): for each event, binary-search where its window ends.
    """
    ts = timestamps.dropna()
    if ts.empty:
        return 0
    t = np.sort(ts.to_numpy(dtype="datetime64[ns]").astype("int64"))
    width = pd.Timedelta(window).value
    window_ends = np.searchsorted(t, t + width, side="right")
    return int((window_ends - np.arange(t.size)).max())


def evidence(rows: pd.DataFrame, limit: int) -> tuple[str, ...]:
    """A few distinct raw log lines that back up a finding."""
    return tuple(rows["raw"].drop_duplicates().head(limit))


def time_bounds(rows: pd.DataFrame) -> tuple[datetime | None, datetime | None]:
    if rows.empty:
        return None, None
    return rows["timestamp"].min().to_pydatetime(), rows["timestamp"].max().to_pydatetime()


def top_values(series: pd.Series, limit: int = 5) -> str:
    """'root (30), admin (12), +3 more' — compact summary for descriptions.
    Counts are omitted when every value occurs once ('/.env, /.git/HEAD, +6 more')."""
    counts = series.dropna().value_counts()
    if counts.empty:
        return "n/a"
    head = counts.head(limit)
    if counts.max() == 1:
        shown = ", ".join(str(value) for value in head.index)
    else:
        shown = ", ".join(f"{value} ({count})" for value, count in head.items())
    remaining = len(counts) - limit
    return shown + (f", +{remaining} more" if remaining > 0 else "")


def plural(count: int, noun: str) -> str:
    return f"{count:,} {noun}" + ("" if count == 1 else "s")


def humanize(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    if seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds} s"
