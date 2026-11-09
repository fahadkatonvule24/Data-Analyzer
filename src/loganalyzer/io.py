"""File reading helpers. Rotated, gzip-compressed logs (``auth.log.2.gz``) are read transparently."""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from pathlib import Path


def iter_lines(path: Path) -> Iterator[str]:
    """Yield lines without trailing newlines. Undecodable bytes are replaced, never fatal."""
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as handle:
        for line in handle:
            yield line.rstrip("\r\n")
