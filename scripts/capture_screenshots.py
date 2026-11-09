"""Regenerate the README screenshots from the bundled samples.

    pip install playwright
    python scripts/capture_screenshots.py            # uses installed Edge or Chrome
    python scripts/capture_screenshots.py --browser chromium   # after `playwright install chromium`

Everything is produced by the real tool on the real sample files; nothing is mocked up.
"""

from __future__ import annotations

import argparse
import io
import tempfile
from pathlib import Path, PurePosixPath

from playwright.sync_api import Page, sync_playwright
from rich.console import Console

from loganalyzer import analyze_logs
from loganalyzer.cli import print_outputs, print_summary
from loganalyzer.report import render_data_report, render_log_report
from loganalyzer.tabular import analyze_table

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
OUT = ROOT / "docs" / "screenshots"


def terminal_svg(target: Path) -> None:
    analysis = analyze_logs([SAMPLES / "auth.log"], year=2026)
    console = Console(
        record=True, width=118, force_terminal=True, color_system="truecolor", file=io.StringIO()
    )
    console.print("[bold green]$[/] loganalyzer logs samples/auth.log\n")
    print_summary(analysis, console)
    out = PurePosixPath("loganalyzer-report")
    print_outputs(
        {"html": out / "report.html", "json": out / "findings.json", "events": out / "events.csv"},
        console,
    )
    svg = console.export_svg(title="loganalyzer")
    page = f'<!doctype html><body style="margin:0;background:#fff"><div id="term">{svg}</div>'
    target.write_text(page, encoding="utf-8")


def shoot(page: Page, selectors: list[str], path: Path, pad: int = 16) -> None:
    """Screenshot the union of the given elements' bounding boxes."""
    boxes = [page.locator(s).first.bounding_box() for s in selectors]
    left = min(b["x"] for b in boxes) - pad
    top = min(b["y"] for b in boxes) - pad
    right = max(b["x"] + b["width"] for b in boxes) + pad
    bottom = max(b["y"] + b["height"] for b in boxes) + pad
    page.screenshot(
        path=str(path),
        full_page=True,
        clip={"x": max(0, left), "y": max(0, top), "width": right - left, "height": bottom - top},
    )
    print(f"wrote {path.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", default="msedge", help="msedge, chrome or chromium")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        auth = work / "auth.html"
        web = work / "web.html"
        data = work / "data.html"
        term = work / "terminal.html"
        auth.write_text(render_log_report(analyze_logs([SAMPLES / "auth.log"], year=2026)), "utf-8")
        web.write_text(render_log_report(analyze_logs([SAMPLES / "access.log"])), "utf-8")
        data.write_text(
            render_data_report(analyze_table(SAMPLES / "health_lifestyle.csv")), "utf-8"
        )
        terminal_svg(term)

        with sync_playwright() as p:
            launch = {} if args.browser == "chromium" else {"channel": args.browser}
            browser = p.chromium.launch(**launch)
            page = browser.new_page(viewport={"width": 1180, "height": 900}, device_scale_factor=2)

            page.goto(term.as_uri())
            shoot(page, ["#term svg"], OUT / "terminal.png", pad=0)

            page.goto(auth.as_uri())
            shoot(page, ["header.top", ".kpis", "section.card >> nth=0"], OUT / "report-auth.png")

            page.goto(web.as_uri())
            shoot(page, ["section.card >> nth=1", "section.grid-2"], OUT / "report-charts.png")
            page.locator("details").nth(1).evaluate("el => el.open = true")  # SQLi evidence
            shoot(page, ["header.top", ".kpis", "section.card >> nth=0"], OUT / "report-web.png")

            page.goto(data.as_uri())
            shoot(page, ["header.top", ".kpis", "section.card >> nth=2"], OUT / "report-data.png")
            shoot(page, ["section.grid-2"], OUT / "report-data-charts.png")

            page.emulate_media(color_scheme="dark")
            page.goto(auth.as_uri())
            shoot(page, ["section.card >> nth=1", "section.grid-2"], OUT / "report-dark.png")
            browser.close()


if __name__ == "__main__":
    main()
