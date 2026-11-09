"""Security log analysis: parse logs, run detections, and report findings."""

from loganalyzer.config import DetectionConfig
from loganalyzer.models import Finding, Severity
from loganalyzer.parsers import LogFormat
from loganalyzer.pipeline import AnalysisError, LogAnalysis, analyze_logs

__version__ = "2.0.0"

__all__ = [
    "AnalysisError",
    "DetectionConfig",
    "Finding",
    "LogAnalysis",
    "LogFormat",
    "Severity",
    "__version__",
    "analyze_logs",
]
