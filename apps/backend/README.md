# PhishCatch backend ve ALLSAFE bağlantısı

Bu servis geliştirme aşamasındaki prototiptir. URL analizi, doğrulanmış eğitim etiketi ve model yayımlama ayrı işlemlerdir. Tarama çağrısı eğitim örneği oluşturmaz veya canlı modeli güncellemez.

## Bağımlılıklar

Python 3.12 ile ayrı bir sanal ortam kullanın. Çalışma zamanı bağımlılıkları ve dolaylı bağımlılıkları sürüm ve hash değerleriyle sabitlenmiştir:

```powershell
python -m pip install --require-hashes -r requirements.lock
```

Testler için `requirements-dev.lock` kullanılır. Ağsız tarayıcı kanıtı ayrı renderer imajı ve Unix socket ile isteğe bağlıdır; Chromium analiz servisi veya ALLSAFE ağı üzerinde başlatılmaz. `requirements-browser.lock` yalnız bağımlılık kaynağıdır, tek başına güvenli çalışma ortamı değildir. Renderer varsayılan olarak kapalıdır. `requirements.txt` eski kurulum komutları için çalışma zamanı lock dosyasına yönlendirir.

Lock dosyaları Python 3.12 ve pip-tools 7.6.2 ile güncellenir:

```powershell
python -m piptools compile --generate-hashes --strip-extras --output-file requirements.lock requirements.in
python -m piptools compile --generate-hashes --strip-extras --output-file requirements-dev.lock requirements-dev.in
python -m piptools compile --generate-hashes --strip-extras --output-file requirements-browser.lock requirements-browser.in
```

Windows ve Linux üzerinde CI/kurulum kontrolü yapılmalıdır. Model dosyaları Git'e veya imaja eklenmez. Docker imajı model olmadan kurulabilir; yerel modeller `/app/models` yoluna salt okunur bağlanır. Model yokken API çalışır, model katmanı erişilemez görünür; bu durum temiz bağlantı kanıtı değildir. Eski modelin uyumluluğu için Python, scikit-learn, numpy, joblib ve özellik şeması sürümleri model metadata'sında kaydedilmeli ve aynı ortamda doğrulanmalıdır.

## Analiz sözleşmesi, sürüm 2

Normal `/api/v1/analyze` çağrısı standalone mobil/web istemcisini destekler. Cevap `contract_version: "2"`, `observation_id` ve `scan_status` (`complete`, `partial`, `failed`) içerir. Her katmanda `status` (`completed`, `unavailable`, `failed`, `skipped`) bulunur. Gözlem kaydı yazılamazsa `observation_id` null kalır.

Eksik inceleme temiz kabul edilmez. Güvenilir bir zararlı kanıt, başka katmanlar erişilemese de zararlı sonucunu korur. Fetch güvenlik engeli tek başına phishing kanıtı değildir; engel görünür bir katman olarak kaydedilir. `risk_score` kuralların birleşik puanıdır, gerçek olasılık değildir. Nihai kararın kalibre edilmiş güven değeri olmadığı için `confidence` null'dır. `malicious_probability` ve `clean_probability` yalnızca çalışan URL modelinin gerçek `predict_proba` çıktısından alınır; kaynak `signals.probability_source` alanındadır. Bu alanlar yokken olasılıklar null kalır.

## ALLSAFE için sunucular arası API

Yalnızca backend ortamında `ALLSAFE_INTEGRATION_KEY` tanımlayın. Bu anahtar mobil uygulamaya gömülmez veya tarama URL'sine eklenmez. ALLSAFE istekleri `X-Integration-Key` başlığı taşır. Anahtar yapılandırılmadığında 503, hatalı veya eksik olduğunda 401 döner.

- `POST /api/v1/integrations/allsafe/analyze`: `{ "url": "https://example.com" }` alır. `{ "analysis": <sürüm 2 analiz>, "feature_version": "phishcatch-v1", "features": { "url.UrlLength": 19.0 } }` döner.
- `GET /api/v1/integrations/allsafe/health`: sözleşme sürümü, servis durumu ve URL/HTML modellerinin erişilebilirlik boolean değerlerini verir. Dosya yollarını veya anahtarları döndürmez.

`features`, yalnızca bilinen URL/HTML özellik kolonlarının sonlu sayısal değerlerini içerir; kolon adları `url.` veya `html.` öneklidir. Ham URL, kullanıcı kimliği, notlar ve HTML metni bu sözlüğe alınmaz. `analysis` operasyonel URL ve kanıtları içerebilir; ALLSAFE bu verileri kurum kayıt ve erişim politikasına göre işlemelidir. İstek kullanıcı kimliği kabul etmez; kullanıcı ilişkilendirmesinden ALLSAFE sorumludur.

```powershell
python -m pytest tests -q
python scripts/smoke_test_fastapi.py
```

Davranış testleri gerçek internet veya model dosyası gerektirmez. Gerçek model kabulü, mobil kamera ve bağlı cihaz testi ayrı olarak yapılır.

## Tespit mekanizması

Güncel karar profili, liste güncellemesi, model değerlendirme koşulları ve bilinen sınırlar: [DETECTION.md](DETECTION.md).
