"""General-purpose dataset analysis (the ``data`` subcommand).

Loads a CSV / TSV / Excel / JSON / Parquet file, cleans it, profiles every column, flags
anomalous rows with an Isolation Forest, segments rows with K-Means (k chosen by silhouette
score) and renders the result as a self-contained HTML report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from markupsafe import Markup
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

from loganalyzer.report import svg

# pandas treats "None" as missing by default, but in survey-style data "None" is usually a real
# answer ("Exercise: None"). Use an explicit list of markers that genuinely mean "no value".
NA_MARKERS = ["", "NA", "N/A", "n/a", "NaN", "nan", "NULL", "null", "#N/A", "-", "?"]
_CSV = {"keep_default_na": False, "na_values": NA_MARKERS, "encoding_errors": "replace"}
READERS = {
    ".csv": lambda p: pd.read_csv(p, sep=None, engine="python", **_CSV),
    ".tsv": lambda p: pd.read_csv(p, sep="\t", **_CSV),
    ".txt": lambda p: pd.read_csv(p, sep=None, engine="python", **_CSV),
    ".json": lambda p: pd.read_json(p),
    ".xlsx": lambda p: pd.read_excel(p),
    ".xls": lambda p: pd.read_excel(p),
    ".parquet": lambda p: pd.read_parquet(p),
}
_ID_NAME = re.compile(r"^(?:id|.*_id|index|unnamed: ?\d+)$", re.IGNORECASE)
MAX_SCATTER_POINTS = 1500


class DataError(ValueError):
    """Raised for unreadable or unusable datasets."""


@dataclass
class TabularAnalysis:
    source: Path
    raw_shape: tuple[int, int]
    data: pd.DataFrame
    notes: list[str]
    profile: list[dict]
    feature_columns: list[str]
    anomalies: pd.DataFrame = field(default_factory=pd.DataFrame)
    anomaly_count: int = 0
    clusters: pd.DataFrame | None = None
    k: int | None = None
    silhouette: float | None = None
    histograms: list[tuple[str, Markup]] = field(default_factory=list)
    heatmap: Markup = field(default_factory=Markup)
    scatter: Markup = field(default_factory=Markup)

    @property
    def missing_pct(self) -> float:
        cells = self.data.size
        return 0.0 if not cells else float(self.data.isna().sum().sum() / cells * 100)


def load_table(path: Path) -> pd.DataFrame:
    reader = READERS.get(path.suffix.lower())
    if reader is None:
        raise DataError(f"unsupported file type {path.suffix!r} (supported: {', '.join(READERS)})")
    try:
        return reader(path)
    except ImportError as exc:
        raise DataError(
            f"{exc}. Install the optional extra: pip install 'loganalyzer[excel,parquet]'"
        ) from exc
    except (ValueError, OSError, pd.errors.ParserError) as exc:
        raise DataError(f"could not read {path.name}: {exc}") from exc


def clean_table(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Light, explainable cleaning. Every change is recorded as a human-readable note."""
    notes: list[str] = []
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]

    before = df.shape
    df = df.dropna(how="all").dropna(axis=1, how="all")
    if df.shape != before:
        notes.append(
            f"Dropped {before[0] - df.shape[0]} empty row(s) and {before[1] - df.shape[1]} empty column(s)."
        )
    duplicates = int(df.duplicated().sum())
    if duplicates:
        df = df.drop_duplicates().reset_index(drop=True)
        notes.append(f"Removed {duplicates} duplicate row(s).")

    for column in df.columns:
        values = df[column]
        if not (pd.api.types.is_object_dtype(values) or pd.api.types.is_string_dtype(values)):
            continue  # pandas 2 stores text as object, pandas 3 as "str"
        present = int(values.notna().sum())
        if not present:
            continue
        as_number = pd.to_numeric(
            values.astype(str).str.replace(",", "", regex=False).str.strip(), errors="coerce"
        ).where(values.notna())
        if as_number.notna().sum() >= 0.9 * present:
            lost = present - int(as_number.notna().sum())
            df[column] = as_number
            notes.append(
                f"Converted '{column}' to numeric"
                + (f"; {lost} unparseable value(s) set to missing." if lost else ".")
            )
            continue
        as_date = pd.to_datetime(values, errors="coerce", format="mixed")
        if as_date.notna().sum() >= 0.9 * present:
            df[column] = as_date
            notes.append(f"Converted '{column}' to datetime.")
    return df, notes


def profile_table(df: pd.DataFrame) -> list[dict]:
    rows = []
    for column in df.columns:
        series = df[column]
        entry: dict = {
            "name": column,
            "dtype": str(series.dtype),
            "missing": int(series.isna().sum()),
            "missing_pct": float(series.isna().mean() * 100),
            "unique": int(series.nunique()),
        }
        if pd.api.types.is_numeric_dtype(series) and not pd.api.types.is_bool_dtype(series):
            entry.update(
                mean=series.mean(),
                std=series.std(),
                min=series.min(),
                median=series.median(),
                max=series.max(),
            )
        elif not series.dropna().empty:
            top = series.value_counts().head(1)
            entry["top"] = f"{top.index[0]} ({int(top.iloc[0]):,})"
        rows.append(entry)
    return rows


def feature_columns(df: pd.DataFrame) -> list[str]:
    """Numeric columns worth modelling: excludes identifiers and constant columns."""
    selected = []
    for column in df.select_dtypes(include="number").columns:
        series = df[column]
        if _ID_NAME.match(column) or series.nunique() <= 1:
            continue
        if (
            pd.api.types.is_integer_dtype(series)
            and series.is_monotonic_increasing
            and series.is_unique
        ):
            continue  # row counter
        selected.append(column)
    return selected


def analyze_table(
    path: str | Path, contamination: float = 0.05, random_state: int = 42
) -> TabularAnalysis:
    path = Path(path)
    if not path.is_file():
        raise DataError(f"{path}: file not found")
    raw = load_table(path)
    if raw.empty:
        raise DataError(f"{path.name} contains no rows")
    data, notes = clean_table(raw)
    features = feature_columns(data)
    result = TabularAnalysis(
        source=path,
        raw_shape=raw.shape,
        data=data,
        notes=notes,
        profile=profile_table(data),
        feature_columns=features,
    )
    result.histograms = [
        (column, svg.histogram(data[column].dropna().tolist(), column)) for column in features[:9]
    ]
    if len(features) >= 2:
        corr = data[features[:10]].corr().round(2).fillna(0)
        result.heatmap = svg.heatmap(
            list(corr.columns), corr.to_numpy().tolist(), "Correlation matrix"
        )

    if not features or len(data) < 20:
        notes.append(
            "Skipped anomaly detection and clustering: needs ≥ 20 rows and a numeric column."
        )
        return result

    X = data[features].fillna(data[features].median())
    scaled = StandardScaler().fit_transform(X)

    model = IsolationForest(
        n_estimators=300, contamination=contamination, random_state=random_state
    )
    labels = model.fit_predict(scaled)
    scores = -model.score_samples(scaled)
    is_anomaly = labels == -1
    result.anomaly_count = int(is_anomaly.sum())

    z = pd.DataFrame(scaled, columns=features, index=data.index)
    id_columns = [c for c in data.columns if _ID_NAME.match(c)][:1]
    anomalies = data.loc[is_anomaly, id_columns + features].copy()
    anomalies.insert(0, "anomaly_score", scores[is_anomaly].round(3))
    anomalies.insert(1, "why", [_explain(z.loc[i]) for i in anomalies.index])
    result.anomalies = anomalies.sort_values("anomaly_score", ascending=False).head(15)

    if len(features) >= 2 and len(data) >= 30:
        result.k, result.silhouette, cluster_labels = _best_kmeans(scaled, random_state)
        profile = X.assign(cluster=cluster_labels).groupby("cluster")
        clusters = profile.mean().round(2)
        clusters.insert(0, "rows", profile.size())
        result.clusters = clusters

        coords = PCA(n_components=2, random_state=random_state).fit_transform(scaled)
        rng = np.random.default_rng(random_state)
        keep = np.arange(len(coords))
        if len(keep) > MAX_SCATTER_POINTS:  # keep every anomaly, sample the rest
            normal = rng.choice(np.flatnonzero(~is_anomaly), MAX_SCATTER_POINTS, replace=False)
            keep = np.sort(np.concatenate([normal, np.flatnonzero(is_anomaly)]))
        points = [
            (
                float(coords[i, 0]),
                float(coords[i, 1]),
                bool(is_anomaly[i]),
                f"Row {data.index[i]} · cluster {cluster_labels[i]} · score {scores[i]:.2f}",
            )
            for i in keep
        ]
        result.scatter = svg.scatter(points, "Rows projected onto two principal components")
    return result


def _explain(z_row: pd.Series) -> str:
    top = z_row.abs().sort_values(ascending=False).head(2)
    return ", ".join(f"{name} {z_row[name]:+.1f}σ" for name in top.index)


def _best_kmeans(X: np.ndarray, random_state: int) -> tuple[int, float, np.ndarray]:
    best: tuple[int, float, np.ndarray] | None = None
    sample = min(len(X), 3000)
    for k in range(2, min(7, len(X))):
        labels = KMeans(n_clusters=k, n_init=10, random_state=random_state).fit_predict(X)
        score = silhouette_score(X, labels, sample_size=sample, random_state=random_state)
        if best is None or score > best[1]:
            best = (k, float(score), labels)
    assert best is not None
    return best
