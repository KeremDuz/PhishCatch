"""Group-disjoint temporal validation and provenance for private training exports."""

from __future__ import annotations

import hashlib
import math

import pandas as pd

PROVENANCE_COLUMNS = [
    "sample_id",
    "domain_group",
    "template_group",
    "observed_at",
    "label_source",
    "verified_label",
]


def grouped_temporal_indices(
    data: pd.DataFrame, features: list[str], test_size: float
) -> tuple[list[int], list[int]]:
    if not 0.1 <= test_size <= 0.5:
        raise ValueError("test_size must be between 0.1 and 0.5")
    if any(column not in data for column in PROVENANCE_COLUMNS):
        raise ValueError("Missing evaluation provenance")
    if not data["verified_label"].astype(str).str.lower().isin(["true", "1"]).all():
        raise ValueError("Only independently verified labels may be evaluated")
    if (
        data["label_source"]
        .astype(str)
        .str.contains("predict|model|auto", case=False, regex=True)
        .any()
    ):
        raise ValueError("Predictions are not verified labels")
    for column in ("sample_id", "domain_group", "label_source"):
        if (
            data[column].isna().any()
            or data[column].astype(str).str.strip().eq("").any()
        ):
            raise ValueError("Missing evaluation identity")
    observed = pd.to_datetime(data["observed_at"], utc=True, errors="coerce")
    if observed.isna().any():
        raise ValueError("Missing observation time; label time is not observation time")
    if data.groupby("sample_id")["result"].nunique().gt(1).any():
        raise ValueError("Conflicting labels for the same sample")
    # Repeated scans of one URL cannot inflate holdout sample counts.
    data = data.loc[observed.sort_values(kind="stable").index].drop_duplicates(
        "sample_id", keep="last"
    )
    observed = observed.loc[data.index]
    order = observed.sort_values(kind="stable")
    cutoff = order.iloc[max(1, int(len(data) * (1 - test_size)))]
    test = data.index[observed >= cutoff].tolist()
    train = data.index[observed < cutoff].tolist()
    if not test or not train:
        raise ValueError("No temporal holdout")
    # Domain, captured template and exact feature vectors cannot cross the split.
    # Numeric vector de-duplication is conservative: collisions reduce coverage.
    vectors = pd.util.hash_pandas_object(data[features], index=False).astype(str)
    for values in [
        data["sample_id"],
        data["domain_group"],
        data["template_group"].fillna(""),
        vectors,
    ]:
        blocked = {str(values.loc[index]) for index in test if str(values.loc[index])}
        train = [index for index in train if str(values.loc[index]) not in blocked]
    if (
        not train
        or set(data.loc[train, "result"].astype(int)) != {0, 1}
        or set(data.loc[test, "result"].astype(int)) != {0, 1}
    ):
        raise ValueError("Disjoint temporal cohorts need both classes")
    return train, test


def identity_digest(values: pd.Series) -> str:
    return hashlib.sha256("\n".join(sorted(values.astype(str))).encode()).hexdigest()


def wilson_upper(failures: int, count: int) -> float:
    if count <= 0 or not 0 <= failures <= count:
        return 1.0
    z = 1.96
    p = failures / count
    return (
        p
        + z * z / (2 * count)
        + z * math.sqrt(p * (1 - p) / count + z * z / (4 * count * count))
    ) / (1 + z * z / count)
