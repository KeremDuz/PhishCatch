import sys
import json
import requests
import concurrent.futures

API_URL = "http://localhost:8001/api/v1/analyze"

def test_url(url):
    url = url.strip()
    if not url:
        return None
    try:
        response = requests.post(API_URL, json={"url": url}, timeout=15)
        if response.status_code == 200:
            data = response.json()
            return {
                "url": url,
                "verdict": data.get("final_verdict"),
                "decided_by": data.get("decided_by"),
                "error": None
            }
        else:
            return {
                "url": url,
                "verdict": "error",
                "decided_by": None,
                "error": f"HTTP {response.status_code}"
            }
    except Exception as e:
        return {
            "url": url,
            "verdict": "error",
            "decided_by": None,
            "error": "Timeout or failed"
        }

def main():
    try:
        with open("feed1.txt", "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"File read error: {e}")
        return

    total = len(urls)
    
    malicious = 0
    clean = 0
    errors = 0
    unknown = 0
    
    print(f"Starting test for {total} URLs...\n")

    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(test_url, url): url for url in urls}
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            completed += 1
            if res:
                results.append(res)
                if res['verdict'] == 'malicious':
                    malicious += 1
                elif res['verdict'] == 'clean':
                    clean += 1
                elif res['verdict'] == 'error':
                    errors += 1
                else: # unknown
                    unknown += 1
                    
            if completed % 10 == 0 or completed == total:
                print(f"[{completed}/{total}] Progress... Malicious: {malicious}, Clean: {clean}, Error/Unknown: {errors+unknown}")

    print("\n--- RESULTS ---")
    print(f"Total Tested: {total}")
    print(f"Detected as Malicious (TRUE POSITIVE): {malicious} ({(malicious/total)*100:.2f}%)")
    print(f"Detected as Clean (FALSE NEGATIVE): {clean} ({(clean/total)*100:.2f}%)")
    print(f"Unknown/Error: {unknown+errors} ({((unknown+errors)/total)*100:.2f}%)")

if __name__ == "__main__":
    main()
