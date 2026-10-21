# Bağımsız değerlendirme

`scripts/benchmark_pipeline.py`, doğrulanmış özel HTML arşivindeki son tüketici kararlarını ağ erişimi olmadan ölçer. Yeni sayfa toplamaz, etiket üretmez, model eğitmez veya yayımlamaz. Gerçek URL/HTML scanner sınıfları, karar akışı ve tüketici sözleşmesi kullanılır; ağ girdileri önceden kaydedilmiş, zamanları bilinen karşılıklarla değiştirilir.

## Veri ve ayrım

Başlangıç hedefi 1.000 yakın tarihli phishing ve 3.000 zor temiz örnektir; bu hedef henüz toplanmış veri veya başarı değildir. Banka/kargo/e-Devlet taklitleri ile gerçek ödeme, giriş/SSO, kısa bağlantı, QR hedefi ve ortak barındırma örnekleri birlikte değerlendirilmeli.

Manifest; etiket kanıtı, inceleyiciler, gözlem ve etiket zamanı, URL, yönlendirme zinciri, şablon/kampanya grupları ve HTML dosya özetini ister. Model tahmini etiket kanıtı değildir. JSON schema gerçek kullanıcı verisi içermeden dışa aktarılır. Ham örnekler, manifestler ve sonuçlar Git dışında tutulur; CLI çıktı dosyalarını POSIX'te oluşturulduğu anda 0600 açar, var olan dosyanın üzerine yazmaz. Windows'ta özel klasörün ACL'si ayrıca geçerlidir.

Eğitim, eşik ayarı ve nihai değerlendirme URL, alan adı/landing/yönlendirme alanı, birebir HTML ve incelemeyle belirlenen şablon/kampanya grupları bakımından ayrılır. Nihai gözlemler zaman kesiminden sonra olmalı. Manifest ve sayfa dosyalarının özetleri doğrulanır; değiştirilmiş dondurulmuş manifest reddedilir. Birebir HTML özeti, tek başına şablon ailesi tespiti değildir.

Eski aktif modelin tüm eğitim verisi bilinmiyorsa `training_provenance=unavailable` kullanılır. Bu durumda araç tanılama raporu üretir fakat bağımsız başarı iddiasına uygunluk vermez. Bir alanı elle `declared_complete` yapmak geçmiş verinin gerçekten eksiksiz olduğunu kanıtlamaz; doğrulanmış eğitim dışlama kaydı gerekir.

## Kullanım

Backend dizininde; `PRIVATE` yalnız Git dışında tutulan özel bir dizini temsil eder:

```sh
python scripts/benchmark_pipeline.py schema --output PRIVATE/schema.json
python scripts/benchmark_pipeline.py freeze PRIVATE/manifest.json --output PRIVATE/frozen.json
python scripts/benchmark_pipeline.py run PRIVATE/frozen.json --url-model TRUSTED/url.pkl --html-model TRUSTED/html.pkl --trust-local-models --name active-local --output PRIVATE/active-local.json
python scripts/benchmark_pipeline.py run PRIVATE/frozen.json --url-model TRUSTED/url.pkl --html-model TRUSTED/html.pkl --trust-local-models --external-reputation --name active-context --output PRIVATE/active-context.json
python scripts/benchmark_pipeline.py compare PRIVATE/active-local.json PRIVATE/active-context.json --output PRIVATE/comparison.json
```

Dondurulmuş manifest aslı ve HTML dosyalarıyla aynı dizinde tutulmalıdır. Yalnız güvenilir yerel pickle/joblib dosyalarını yükleyin. Araç canlı API sunucusu içinde çalıştırılmaz; Python ağ engeli, güvenilmeyen kod için işletim sistemi sandbox'ı değildir.

`--external-reputation` canlı API çağrısı yapmaz; arşivdeki aynı zamana ait DNS/API sonuçlarını yeniden kullanır. DNS filtresiyle içerik alınmamış örnekler `not_fetched_dns_review` olarak kaydedilebilir; bunlar phishing yakalandı diye sayılmaz. Yerel liste için o tarihe ait sonuç yoksa katman erişilemez olur; sessizce kaldırılmaz. Bilinen yerel tehdit, API'de bilinen tehdit, DNS inceleme uyarısı ve kaynaklarda bilinmeyen örnekler ayrılır. API'nin sonuç zamanından sonraki verisiyle geçmiş karar iyileştirilmez.

## Raporun anlamı

Son karar matrisi `clean/malicious/unknown` ayrıdır. Phishing'in temiz çıkması, temiz sayfanın zararlı çıkması, her sınıf için belirsiz sonuç ve karar kapsaması; sayılar ve Wilson güven aralıklarıyla verilir. Belirsiz sonuç başarılı yakalama değildir. Aktif/aday sürümler ve API açık/kapalı profiller aynı dokunulmamış kümede karşılaştırılır. Rapor model yayımlama yetkisi üretmez.

Replay işlem süresi model yüklemeyi, üretimdeki yardımcı süreçleri ve canlı ağı içermez. Arşivde gerçek yakalama süresi varsa ayrıca raporlanır. Bu iki süre sunucunun gerçek p95 gecikmesi veya kapasite garantisi olarak sunulmaz. Kontrolsüz gerçek şüpheli URL'ler ev sunucusundan topluca açılmaz.

Testler sentetik arşivlerle aracı doğrular; gerçek dünya doğruluğunu ölçmez. [scikit-learn veri ayrımı ilkeleri](https://scikit-learn.org/stable/common_pitfalls.html).

İmajda aynı CLI `python -m app.ml.benchmark_cli` olarak bulunur; `scripts/` dizini imaja alınmaz. Özel veri ve model dizinlerini salt okunur, yalnız çıktı dizinini yazılabilir bağlayarak ayrı `--network none` konteynerinde çalıştırılabilir. Çalışan analiz sürecinde ağ engeli veya benchmark çalıştırılmaz.
