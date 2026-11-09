"""Report writers: self-contained HTML, machine-readable JSON, and the normalised event table."""

from loganalyzer.report.html import render_data_report, render_log_report, write_log_outputs

__all__ = ["render_data_report", "render_log_report", "write_log_outputs"]
