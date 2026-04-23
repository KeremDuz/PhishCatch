#!/usr/bin/env python3
"""
feed1.txt URL'lerini async olarak PhishCatch API'ye gönderip
başarı oranı hesaplayan test scripti.

Tüm URL'ler phishing olarak bilindiğinden:
  - "malicious" verdict = True Positive (TP)
  - "clean"/"unknown" verdict = False Negative (FN)
  - Başarı Oranı = TP / (TP + FN)
"""

import asyncio
import json
import time
import sys
from pathlib import Path

import aiohttp

API_BASE = "http://127.0.0.1:8001/api/v1/analyze"
CONCURRENCY = 10  # aynı anda max istek sayısı
TIMEOUT = aiohttp.ClientTimeout(total=60)  # URL başına 60s


async def analyze_url(session: aiohttp.ClientSession, sem: asyncio.Semaphore, url: str, idx: int, total: int):
    """Tek URL analiz et."""
    async with sem:
        try:
            async with session.post(API_BASE, json={"url": url}, timeout=TIMEOUT) as resp:
                data = await resp.json()
                verdict = data.get("final_verdict", "error")
                decided_by = data.get("decided_by", "?")
                confidence = data.get("confidence")
                mal_prob = data.get("malicious_probability")
                
                status = "✅ TP" if verdict == "malicious" else "❌ FN"
                print(f"[{idx:3d}/{total}] {status} | {verdict:10s} | conf={confidence} | mal_prob={mal_prob} | by={decided_by} | {url[:80]}")
                
                return {
                    "url": url,
                    "verdict": verdict,
                    "decided_by": decided_by,
                    "confidence": confidence,
                    "malicious_probability": mal_prob,
                    "correct": verdict == "malicious",
                }
        except asyncio.TimeoutError:
            print(f"[{idx:3d}/{total}] ⏰ TIMEOUT | {url[:80]}")
            return {"url": url, "verdict": "timeout", "decided_by": "timeout", "confidence": None, "malicious_probability": None, "correct": False}
        except Exception as e:
            print(f"[{idx:3d}/{total}] 💥 ERROR  | {e} | {url[:80]}")
            return {"url": url, "verdict": "error", "decided_by": "error", "confidence": None, "malicious_probability": None, "correct": False}


async def main():
    feed_path = Path(__file__).parent / "feed1.txt"
    urls = [line.strip() for line in feed_path.read_text().splitlines() if line.strip()]
    total = len(urls)
    
    print(f"{'='*80}")
    print(f"PhishCatch Feed Test — {total} phishing URL")
    print(f"Concurrency: {CONCURRENCY} | Timeout: {TIMEOUT.total}s")
    print(f"{'='*80}\n")
    
    sem = asyncio.Semaphore(CONCURRENCY)
    start = time.time()
    
    async with aiohttp.ClientSession() as session:
        tasks = [
            analyze_url(session, sem, url, i + 1, total)
            for i, url in enumerate(urls)
        ]
        results = await asyncio.gather(*tasks)
    
    elapsed = time.time() - start
    
    # İstatistikler
    tp = sum(1 for r in results if r["correct"])
    fn = sum(1 for r in results if not r["correct"] and r["verdict"] not in ("timeout", "error"))
    timeouts = sum(1 for r in results if r["verdict"] == "timeout")
    errors = sum(1 for r in results if r["verdict"] == "error")
    
    tested = tp + fn  # timeout/error hariç gerçek test edilen
    accuracy = (tp / tested * 100) if tested > 0 else 0
    
    # Karar veren scanner dağılımı
    decided_by_counts = {}
    for r in results:
        db = r["decided_by"]
        decided_by_counts[db] = decided_by_counts.get(db, 0) + 1
    
    # FALSE NEGATIVE detayları
    fn_list = [r for r in results if not r["correct"] and r["verdict"] not in ("timeout", "error")]
    
    print(f"\n{'='*80}")
    print(f"SONUÇLAR")
    print(f"{'='*80}")
    print(f"Toplam URL        : {total}")
    print(f"Test edilen       : {tested}")
    print(f"True Positive     : {tp}")
    print(f"False Negative    : {fn}")
    print(f"Timeout           : {timeouts}")
    print(f"Error             : {errors}")
    print(f"")
    print(f"🎯 BAŞARI ORANI   : {accuracy:.1f}%  ({tp}/{tested})")
    print(f"⏱  Süre           : {elapsed:.1f}s")
    print(f"📊 Ortalama/URL   : {elapsed/total:.2f}s")
    print(f"")
    print(f"Scanner Dağılımı:")
    for scanner, count in sorted(decided_by_counts.items(), key=lambda x: -x[1]):
        print(f"  {scanner:30s} : {count}")
    
    if fn_list:
        print(f"\n{'='*80}")
        print(f"❌ FALSE NEGATIVE URL'ler ({fn} adet):")
        print(f"{'='*80}")
        for r in fn_list:
            print(f"  [{r['verdict']:10s}] {r['decided_by']:25s} | mal_prob={r['malicious_probability']} | {r['url']}")
    
    # JSON kaydet
    report = {
        "total": total,
        "tested": tested,
        "tp": tp,
        "fn": fn,
        "timeouts": timeouts,
        "errors": errors,
        "accuracy_percent": round(accuracy, 2),
        "elapsed_seconds": round(elapsed, 1),
        "decided_by_distribution": decided_by_counts,
        "false_negatives": fn_list,
        "all_results": results,
    }
    report_path = Path(__file__).parent / "feed1_results.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\nDetaylı rapor: {report_path}")


if __name__ == "__main__":
    asyncio.run(main())
