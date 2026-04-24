import argparse
import json

import requests


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PhishCatch URL analyzer CLI",
    )
    parser.add_argument("-u", "--url", required=True, help="Analyzedilecek URL")
    parser.add_argument(
        "-b",
        "--base-url",
        default="http://127.0.0.1:8001",
        help="API base URL (varsayılan: http://127.0.0.1:8001)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Tam API JSON çıktısını göster",
    )
    return parser.parse_args()


def _print_compact_result(payload: dict) -> None:
    compact = {
        "input": payload.get("original_input") or payload.get("url"),
        "normalized_url": payload.get("normalized_url") or payload.get("url"),
        "verdict": payload.get("final_verdict"),
        "risk_score": payload.get("risk_score"),
        "confidence": payload.get("confidence"),
        "malicious_probability": payload.get("malicious_probability"),
        "decided_by": payload.get("decided_by"),
        "summary": payload.get("summary"),
    }
    print(json.dumps(compact, indent=2, ensure_ascii=False))


def run_http_mode(base_url: str, url: str, verbose: bool) -> int:
    endpoint = f"{base_url.rstrip('/')}/api/v1/analyze"
    try:
        response = requests.post(endpoint, json={"url": url}, timeout=30)
        payload = response.json()
        if response.status_code == 200:
            if verbose:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
            else:
                _print_compact_result(payload)
            return 0

        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 1
    except requests.RequestException as exc:
        print("API'ye bağlanılamadı:", str(exc))
        print("İpucu: Önce API sunucusunu başlat.")
        return 2


def main() -> int:
    args = parse_args()
    return run_http_mode(args.base_url, args.url, args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
