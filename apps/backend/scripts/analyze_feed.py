from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import warnings
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

os.environ.setdefault("PYTHONWARNINGS", "ignore:.*sklearn.utils.parallel.delayed.*:UserWarning")
warnings.filterwarnings(
    "ignore",
    message=r".*sklearn\.utils\.parallel\.delayed.*",
    category=UserWarning,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.dependencies import get_scanning_pipeline
from app.models.schemas import AnalyzeUrlRequest
from app.services.campaign_context import CampaignContext, build_campaign_context, evaluate_campaign_url


FIELDNAMES = [
    "index",
    "input_url",
    "normalized_url",
    "final_verdict",
    "risk_score",
    "confidence",
    "malicious_probability",
    "clean_probability",
    "summary",
    "positive_signals",
    "campaign_signal",
    "error",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze a feed file with the local PhishCatch pipeline.")
    parser.add_argument("--input", type=Path, default=Path("feed1.txt"))
    parser.add_argument("--output", type=Path, default=Path("feed_1_results.csv"))
    parser.add_argument("--summary-output", type=Path, default=Path("feed_1_results.json"))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int, default=0, help="0 means analyze all URLs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    urls = read_urls(args.input)
    if args.limit > 0:
        urls = urls[: args.limit]

    started_at = time.perf_counter()
    campaign_context = build_campaign_context(urls)
    print(f"Analyzing {len(urls)} URL(s) from {args.input} with {args.workers} worker(s)...", flush=True)

    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(analyze_one, index, url, campaign_context): (index, url)
            for index, url in enumerate(urls, start=1)
        }
        completed = 0
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            results.append(result)
            if completed % 10 == 0 or completed == len(urls):
                counts = Counter(str(item.get("final_verdict") or "error") for item in results)
                print(
                    f"  {completed}/{len(urls)} done | "
                    f"malicious={counts.get('malicious', 0)} unknown={counts.get('unknown', 0)} "
                    f"clean={counts.get('clean', 0)} "
                    f"errors={counts.get('error', 0)}",
                    flush=True,
                )

    results.sort(key=lambda item: int(item["index"]))
    write_csv(args.output, results)

    elapsed_seconds = round(time.perf_counter() - started_at, 2)
    summary = build_summary(results, elapsed_seconds)
    args.summary_output.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)
    print(f"CSV written: {args.output}", flush=True)
    print(f"Summary written: {args.summary_output}", flush=True)
    return 0


def read_urls(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def analyze_one(index: int, input_url: str, campaign_context: CampaignContext | None = None) -> dict[str, object]:
    try:
        payload = AnalyzeUrlRequest.model_validate({"url": input_url})
        response = get_scanning_pipeline().run(payload.url, original_input=payload.original_input)
        positive_signals = list(response.signals.get("positive", []))
        result = {
            "index": index,
            "input_url": input_url,
            "normalized_url": response.normalized_url,
            "final_verdict": response.final_verdict,
            "risk_score": response.risk_score,
            "confidence": response.confidence,
            "malicious_probability": response.malicious_probability,
            "clean_probability": response.clean_probability,
            "summary": response.summary or "",
            "positive_signals": json.dumps(positive_signals, ensure_ascii=False),
            "campaign_signal": "",
            "error": "",
        }
        if campaign_context is not None:
            apply_campaign_signal(result, positive_signals, input_url, campaign_context)
        result["positive_signals"] = json.dumps(positive_signals, ensure_ascii=False)
        return result
    except Exception as exc:
        return {
            "index": index,
            "input_url": input_url,
            "normalized_url": "",
            "final_verdict": "error",
            "risk_score": "",
            "confidence": "",
            "malicious_probability": "",
            "clean_probability": "",
            "summary": "",
            "positive_signals": "[]",
            "campaign_signal": "",
            "error": str(exc),
        }


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def build_summary(results: list[dict[str, object]], elapsed_seconds: float) -> dict[str, object]:
    verdict_counts = Counter(str(item.get("final_verdict") or "error") for item in results)
    total = len(results)
    malicious = verdict_counts.get("malicious", 0)
    unknown = verdict_counts.get("unknown", 0)
    return {
        "total": total,
        "malicious": malicious,
        "unknown": unknown,
        "clean": verdict_counts.get("clean", 0),
        "errors": verdict_counts.get("error", 0),
        "malicious_rate": round(malicious / total, 4) if total else 0.0,
        "malicious_or_unknown_rate": round((malicious + unknown) / total, 4) if total else 0.0,
        "elapsed_seconds": elapsed_seconds,
        "verdict_counts": dict(verdict_counts),
    }


def apply_campaign_signal(
    result: dict[str, object],
    positive_signals: list[dict[str, object]],
    input_url: str,
    campaign_context: CampaignContext,
) -> None:
    campaign_signal = evaluate_campaign_url(input_url, campaign_context)
    if campaign_signal is None:
        return

    signal_dict = campaign_signal.as_positive_signal()
    positive_signals.append(signal_dict)
    result["campaign_signal"] = json.dumps(signal_dict, ensure_ascii=False)

    current_risk = _as_float(result.get("risk_score"))
    merged_risk = _noisy_or([current_risk, campaign_signal.score])
    result["risk_score"] = round(merged_risk, 4)
    result["malicious_probability"] = round(merged_risk, 4)
    result["clean_probability"] = round(1 - merged_risk, 4)

    original_verdict = str(result.get("final_verdict") or "clean")
    if merged_risk >= 0.6:
        result["final_verdict"] = "malicious"
    elif merged_risk >= 0.35 and original_verdict == "clean":
        result["final_verdict"] = "unknown"

    result["confidence"] = _campaign_adjusted_confidence(str(result["final_verdict"]), merged_risk)
    if original_verdict != result["final_verdict"]:
        result["summary"] = f"{result.get('summary') or ''} | Campaign clustering: {campaign_signal.reason}".strip(" |")


def _as_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _noisy_or(scores: list[float]) -> float:
    safe_product = 1.0
    for score in scores:
        safe_product *= 1 - max(0.0, min(1.0, float(score)))
    return min(1.0, 1 - safe_product)


def _campaign_adjusted_confidence(verdict: str, risk_score: float) -> float:
    if verdict == "malicious":
        return round(max(0.5, min(1.0, 0.5 + ((risk_score - 0.6) / 0.4 * 0.5))), 4)
    if verdict == "unknown":
        return 0.6
    return round(max(0.5, min(1.0, 0.5 + ((0.35 - risk_score) / 0.35 * 0.5))), 4)


if __name__ == "__main__":
    raise SystemExit(main())
