from __future__ import annotations

import argparse
from pathlib import Path
import re

import pandas as pd

from app.ml.feature_extractor import (
    MENDELEY_48_FEATURE_COLUMNS,
    URL_FEATURE_COLUMNS,
    extract_48_features,
    extract_url_features,
)


BALANCED_URLS_PATH_CANDIDATES = (Path("balanced_urls.csv"), Path("data/balanced_urls.csv"))
MENDELEY_INDEX_PATH = Path("Mendeley_dataset/index.sql")
URL_OUTPUT_PATH = "phishcatch_training_data_url.csv"
MENDELEY_48_OUTPUT_PATH = "phishcatch_training_data_48.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate PhishCatch training features.")
    parser.add_argument(
        "--schema",
        choices=["url", "mendeley48"],
        default="url",
        help="Feature schema to generate. Default: url",
    )
    parser.add_argument(
        "--balanced-urls",
        type=Path,
        default=None,
        help="Path to balanced_urls.csv. Defaults to balanced_urls.csv, then data/balanced_urls.csv.",
    )
    parser.add_argument(
        "--mendeley-index",
        type=Path,
        default=MENDELEY_INDEX_PATH,
        help="Path to Mendeley_dataset/index.sql.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output CSV path. Defaults to the schema-specific training CSV.",
    )
    return parser.parse_args()


def _load_mendeley_urls(index_sql_path: Path) -> pd.DataFrame:
    if not index_sql_path.exists():
        return pd.DataFrame(columns=["url", "result"])

    sql_text = index_sql_path.read_text(encoding="utf-8", errors="ignore")
    tuple_pattern = re.compile(
        r"\(\s*\d+\s*,\s*'((?:\\'|[^'])*)'\s*,\s*'((?:\\'|[^'])*)'\s*,\s*(\d+)\s*,\s*'((?:\\'|[^'])*)'\s*\)",
        re.DOTALL,
    )

    rows: list[dict[str, object]] = []
    for url_value, _website_value, result_value, _created_date in tuple_pattern.findall(sql_text):
        cleaned_url = url_value.replace("\\'", "'").strip()
        if cleaned_url:
            rows.append({"url": cleaned_url, "result": int(result_value)})

    if not rows:
        return pd.DataFrame(columns=["url", "result"])

    return pd.DataFrame(rows)


def _merge_and_deduplicate_url_sets(base_dataframe: pd.DataFrame, extra_dataframe: pd.DataFrame) -> pd.DataFrame:
    combined = pd.concat([base_dataframe[["url", "result"]], extra_dataframe[["url", "result"]]], ignore_index=True)
    combined = combined.dropna(subset=["url", "result"]).copy()
    combined["url"] = combined["url"].astype(str).str.strip()
    combined = combined[combined["url"] != ""]
    combined["result"] = combined["result"].astype(int)

    grouped = (
        combined.groupby("url", as_index=False)
        .agg(result_mean=("result", "mean"), vote_count=("result", "size"))
    )
    grouped["result"] = (grouped["result_mean"] >= 0.5).astype(int)

    return grouped[["url", "result"]]


def _resolve_balanced_urls_path(configured_path: Path | None) -> Path:
    if configured_path is not None:
        return configured_path

    for candidate in BALANCED_URLS_PATH_CANDIDATES:
        if candidate.exists():
            return candidate

    return BALANCED_URLS_PATH_CANDIDATES[0]


def _load_training_urls(balanced_urls_path: Path | None, mendeley_index_path: Path) -> pd.DataFrame:
    resolved_balanced_urls_path = _resolve_balanced_urls_path(balanced_urls_path)
    print(f"1. {resolved_balanced_urls_path} yukleniyor...")
    dataframe = pd.read_csv(resolved_balanced_urls_path)

    if "url" not in dataframe.columns or "result" not in dataframe.columns:
        raise ValueError(f"{resolved_balanced_urls_path} must contain 'url' and 'result' columns")

    print(f"2. {mendeley_index_path} kontrol ediliyor...")
    mendeley_dataframe = _load_mendeley_urls(mendeley_index_path)
    if len(mendeley_dataframe) > 0:
        print(f"Mendeley etiketli URL bulundu: {len(mendeley_dataframe)}")
        dataframe = _merge_and_deduplicate_url_sets(dataframe, mendeley_dataframe)
        print(f"Birlesik ve tekillestirilmis URL sayisi: {len(dataframe)}")
    else:
        dataframe = dataframe[["url", "result"]].dropna().copy()
        dataframe["result"] = dataframe["result"].astype(int)
        print("Mendeley verisi bulunamadi, yalnizca balanced_urls.csv kullanilacak.")

    return dataframe


def main() -> None:
    args = parse_args()
    dataframe = _load_training_urls(args.balanced_urls, args.mendeley_index)

    if args.schema == "mendeley48":
        print("3. Mendeley 48 approx feature cikariliyor...")
        extracted = dataframe["url"].apply(extract_48_features)
        output_path = args.output or Path(MENDELEY_48_OUTPUT_PATH)
        columns = MENDELEY_48_FEATURE_COLUMNS
    else:
        print("3. URL-only lexical feature cikariliyor...")
        extracted = dataframe["url"].apply(extract_url_features)
        output_path = args.output or Path(URL_OUTPUT_PATH)
        columns = URL_FEATURE_COLUMNS

    final_dataframe = pd.concat([dataframe["result"].astype(int), extracted], axis=1)
    final_dataframe.to_csv(output_path, index=False)

    print(f"4. Tamamlandi: '{output_path}' olusturuldu.")
    print(f"Satir sayisi: {len(final_dataframe)}")
    print(f"Kolon sayisi: {len(final_dataframe.columns)} (1 label + {len(columns)} feature)")


if __name__ == "__main__":
    main()
