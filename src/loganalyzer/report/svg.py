"""Small, dependency-free SVG chart builders for the HTML reports.

Charts are inline SVG so the report stays a single self-contained file, renders crisply at
any zoom, follows the page's light/dark theme through CSS custom properties, and shows a
native tooltip (``<title>``) on hover. Every chart has a table equivalent in the report.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from markupsafe import Markup, escape


@dataclass(frozen=True)
class Bar:
    label: str
    value: float
    highlight: bool = False
    tooltip: str | None = None


def _nice_step(raw: float) -> float:
    if raw <= 0:
        return 1
    exponent = 10 ** math.floor(math.log10(raw))
    for multiplier in (1, 2, 2.5, 5, 10):
        if raw <= multiplier * exponent:
            return multiplier * exponent
    return 10 * exponent


def _ticks(max_value: float, count: int = 4, integer: bool = True) -> list[float]:
    step = _nice_step(max_value / count) if max_value > 0 else 1
    if integer:
        step = max(1, math.ceil(step))
    top = step * max(1, math.ceil(max_value / step))
    return [step * i for i in range(round(top / step) + 1)]


def compact(value: float) -> str:
    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:.1f}M".replace(".0M", "M")
    if abs(value) >= 10_000:
        return f"{value / 1_000:.0f}K"
    if float(value).is_integer():
        return f"{int(value):,}"
    return f"{value:,.2f}"


def _column(x: float, y: float, w: float, h: float, r: float = 4) -> str:
    """Column path: rounded data-end on top, square at the baseline."""
    r = max(0.0, min(r, w / 2, h))
    return (
        f"M{x:.2f},{y + h:.2f}V{y + r:.2f}Q{x:.2f},{y:.2f} {x + r:.2f},{y:.2f}"
        f"H{x + w - r:.2f}Q{x + w:.2f},{y:.2f} {x + w:.2f},{y + r:.2f}V{y + h:.2f}Z"
    )


def _hbar(x: float, y: float, w: float, h: float, r: float = 4) -> str:
    """Horizontal bar path: square at the baseline (left), rounded data-end (right)."""
    r = max(0.0, min(r, h / 2, w))
    return (
        f"M{x:.2f},{y:.2f}H{x + w - r:.2f}Q{x + w:.2f},{y:.2f} {x + w:.2f},{y + r:.2f}"
        f"V{y + h - r:.2f}Q{x + w:.2f},{y + h:.2f} {x + w - r:.2f},{y + h:.2f}H{x:.2f}Z"
    )


def _svg(width: int, height: int, body: list[str], label: str) -> Markup:
    return Markup(
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{escape(label)}" xmlns="http://www.w3.org/2000/svg">'
        + "".join(body)
        + "</svg>"
    )


def timeline(
    buckets: Sequence[tuple[datetime, int, bool]],
    unit: str,
    bucket_minutes: int,
    label: str,
    width: int = 960,
    height: int = 230,
) -> Markup:
    """Column chart of event counts per time bucket; flagged buckets drawn in the alert color."""
    if not buckets:
        return Markup("")
    left, right, top, bottom = 48, 12, 14, 30
    plot_w, plot_h = width - left - right, height - top - bottom
    ticks = _ticks(max(count for _, count, _ in buckets))
    y_max = ticks[-1]
    slot = plot_w / len(buckets)
    gap = 2 if slot >= 8 else (1 if slot >= 3 else 0)
    bar_w = min(24.0, slot - gap)

    body = []
    for tick in ticks:
        y = top + plot_h - plot_h * tick / y_max
        body.append(
            f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>'
        )
        body.append(
            f'<text class="tick" x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{compact(tick)}</text>'
        )

    multi_day = buckets[0][0].date() != buckets[-1][0].date()
    label_every = max(1, math.ceil(len(buckets) / 8))
    for i, (start, count, flagged) in enumerate(buckets):
        x = left + i * slot + (slot - bar_w) / 2
        h = plot_h * count / y_max
        tip = f"{start:%d %b %H:%M} · {count:,} {unit} per {bucket_minutes} min"
        if flagged:
            tip += " · spike"
        bar = (
            f'<path class="{"bar alert" if flagged else "bar"}" d="{_column(x, top + plot_h - h, bar_w, h)}"/>'
            if count
            else ""
        )
        body.append(
            f'<g class="hit"><title>{escape(tip)}</title>'
            f'<rect x="{left + i * slot:.2f}" y="{top}" width="{slot:.2f}" height="{plot_h}" fill="transparent"/>'
            f"{bar}</g>"
        )
        if i % label_every == 0:
            fmt = "%d %b %H:%M" if multi_day else "%H:%M"
            body.append(
                f'<text class="tick" x="{left + i * slot + slot / 2:.1f}" y="{height - 8}" '
                f'text-anchor="middle">{start.strftime(fmt)}</text>'
            )
    body.append(
        f'<line class="axis" x1="{left}" x2="{width - right}" y1="{top + plot_h}" y2="{top + plot_h}"/>'
    )
    return _svg(width, height, body, label)


def hbars(
    bars: Sequence[Bar], label: str, width: int = 460, label_width: int = 128, mono: bool = False
) -> Markup:
    """Horizontal bar chart, value printed at each bar's tip."""
    if not bars:
        return Markup("")
    row, thickness, top = 28, 14, 4
    height = top + row * len(bars) + 4
    plot_w = width - label_width - 56
    max_value = max(b.value for b in bars) or 1
    body = []
    for i, bar in enumerate(bars):
        y = top + i * row
        w = max(2.0, plot_w * bar.value / max_value) if bar.value else 0
        cls = "bar alert" if bar.highlight else "bar"
        tip = bar.tooltip or f"{bar.label}: {compact(bar.value)}"
        text_cls = "label mono" if mono else "label"
        body.append(
            f'<g class="hit"><title>{escape(tip)}</title>'
            f'<rect x="0" y="{y}" width="{width}" height="{row}" fill="transparent"/>'
            f'<text class="{text_cls}" x="{label_width - 10}" y="{y + row / 2 + 4:.1f}" '
            f'text-anchor="end">{escape(_truncate(bar.label, 22))}</text>'
            + (
                f'<path class="{cls}" d="{_hbar(label_width, y + (row - thickness) / 2, w, thickness)}"/>'
                if w
                else ""
            )
            + f'<text class="value" x="{label_width + w + 6:.1f}" y="{y + row / 2 + 4:.1f}">'
            f"{compact(bar.value)}</text></g>"
        )
    body.append(
        f'<line class="axis" x1="{label_width}" x2="{label_width}" y1="{top - 2}" y2="{height - 2}"/>'
    )
    return _svg(width, height, body, label)


def histogram(
    values: Sequence[float], title: str, bins: int = 20, width: int = 300, height: int = 150
) -> Markup:
    clean = [v for v in values if v is not None and math.isfinite(v)]
    if not clean:
        return Markup("")
    lo, hi = min(clean), max(clean)
    span = (hi - lo) or 1
    counts = [0] * bins
    for v in clean:
        counts[min(bins - 1, int((v - lo) / span * bins))] += 1
    left, right, top, bottom = 34, 8, 8, 22
    plot_w, plot_h = width - left - right, height - top - bottom
    ticks = _ticks(max(counts), count=3)
    slot = plot_w / bins
    bar_w = min(24.0, slot - 2)
    body = []
    for tick in ticks:
        y = top + plot_h - plot_h * tick / ticks[-1]
        body.append(
            f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>'
        )
        body.append(
            f'<text class="tick" x="{left - 6}" y="{y + 4:.1f}" text-anchor="end">{compact(tick)}</text>'
        )
    for i, count in enumerate(counts):
        b_lo, b_hi = lo + span * i / bins, lo + span * (i + 1) / bins
        x = left + i * slot + (slot - bar_w) / 2
        h = plot_h * count / ticks[-1]
        tip = f"{compact(b_lo)} – {compact(b_hi)}: {count:,} rows"
        body.append(
            f'<g class="hit"><title>{escape(tip)}</title>'
            f'<rect x="{left + i * slot:.2f}" y="{top}" width="{slot:.2f}" height="{plot_h}" fill="transparent"/>'
            + (
                f'<path class="bar" d="{_column(x, top + plot_h - h, bar_w, h, 3)}"/>'
                if count
                else ""
            )
            + "</g>"
        )
    body.append(
        f'<line class="axis" x1="{left}" x2="{width - right}" y1="{top + plot_h}" y2="{top + plot_h}"/>'
    )
    body.append(f'<text class="tick" x="{left}" y="{height - 6}">{compact(lo)}</text>')
    body.append(
        f'<text class="tick" x="{width - right}" y="{height - 6}" text-anchor="end">{compact(hi)}</text>'
    )
    return _svg(width, height, body, f"Distribution of {title}")


def heatmap(columns: Sequence[str], matrix: Sequence[Sequence[float]], label: str) -> Markup:
    """Correlation heatmap on a diverging blue <-> red scale with a neutral midpoint at 0."""
    n = len(columns)
    if n < 2:
        return Markup("")
    cell, label_w, top = 46, 120, 96
    width, height = label_w + cell * n + 8, top + cell * n + 8
    body = []
    for j, name in enumerate(columns):
        x = label_w + j * cell + cell / 2
        body.append(
            f'<text class="tick" transform="translate({x:.1f},{top - 8}) rotate(-40)">{escape(_truncate(name, 14))}</text>'
        )
    for i, row_name in enumerate(columns):
        y = top + i * cell
        body.append(
            f'<text class="label" x="{label_w - 8}" y="{y + cell / 2 + 4:.1f}" text-anchor="end">{escape(_truncate(row_name, 16))}</text>'
        )
        for j, value in enumerate(matrix[i]):
            x = label_w + j * cell
            step = min(4, int(abs(value) * 5))  # 0..4 intensity steps per arm
            side = "pos" if value > 0 else "neg"
            cls = "cell mid" if step == 0 else f"cell {side}{step}"
            ink = "ink-light" if step >= 3 else "ink-dark"
            tip = f"{row_name} × {columns[j]}: r = {value:+.2f}"
            body.append(
                f'<g class="hit"><title>{escape(tip)}</title>'
                f'<rect class="{cls}" x="{x + 1}" y="{y + 1}" width="{cell - 2}" height="{cell - 2}" rx="4"/>'
                f'<text class="cellv {ink}" x="{x + cell / 2:.1f}" y="{y + cell / 2 + 4:.1f}" text-anchor="middle">{value:+.2f}</text></g>'
            )
    return _svg(width, height, body, label)


def scatter(
    points: Sequence[tuple[float, float, bool, str]],
    label: str,
    width: int = 560,
    height: int = 340,
) -> Markup:
    """2-D scatter (e.g. PCA projection); flagged points drawn in the alert color, on top."""
    if not points:
        return Markup("")
    left, right, top, bottom = 40, 12, 12, 30
    xs, ys = [p[0] for p in points], [p[1] for p in points]
    x_lo, x_hi, y_lo, y_hi = min(xs), max(xs), min(ys), max(ys)
    x_span, y_span = (x_hi - x_lo) or 1, (y_hi - y_lo) or 1
    plot_w, plot_h = width - left - right, height - top - bottom

    def sx(v: float) -> float:
        return left + plot_w * (v - x_lo) / x_span

    def sy(v: float) -> float:
        return top + plot_h - plot_h * (v - y_lo) / y_span

    body = [
        f'<rect class="frame" x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" rx="4"/>',
        f'<text class="tick" x="{left + plot_w / 2:.1f}" y="{height - 8}" text-anchor="middle">Principal component 1</text>',
        f'<text class="tick" transform="translate(14,{top + plot_h / 2:.1f}) rotate(-90)" text-anchor="middle">Component 2</text>',
    ]
    for x, y, flagged, tip in sorted(points, key=lambda p: p[2]):
        cls = "dot alert" if flagged else "dot"
        body.append(
            f'<g class="hit"><title>{escape(tip)}</title>'
            f'<circle class="{cls}" cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="{5 if flagged else 4}"/></g>'
        )
    return _svg(width, height, body, label)


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"
