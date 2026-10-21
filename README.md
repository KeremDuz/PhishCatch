# PhishCatch

URL ve QR bağlantılarını inceleyen FastAPI servisi ve sade, mavi Flutter web/Android uygulaması. Mezuniyet projesi prototipidir; güncel doğruluk oranı veya kesin güvenlik garantisi sunmaz.

Bağımsız tüketici sürümü giriş gerektirmez ve yalnız dar `consumer-1` yanıtını kullanır. ALLSAFE kurum oturumu, merkezi kayıtlar ve yönetici tarafından eğitim onayı ayrı tutulur. Anonim tarama eğitim örneği oluşturmaz.

## Çalışan analiz profili

Güncel yerel uyarı listesi, aynı GET içeriğinden yönlendirme ve HTML incelemesi, eğitilmiş URL modeli ve HTML modeli birlikte değerlendirilir. RDAP kayıt bilgisi yardımcı bağlamdır. Alan adı yaşı, HTTPS veya listede bulunmamak temiz kanıtı değildir. Eksik ya da çözülemeyen inceleme belirsiz kalır.

`REPUTATION_FREE_ONLY=true` varsayılandır. Bu profilde anahtar tanımlansa bile Google, VirusTotal ve URLhaus gibi eski kimlik bilgili sağlayıcılar etkinleştirilmez. `CLOUDFLARE_DNS_SECURITY_ENABLED=1` ücretsiz, anahtarsız Cloudflare güvenlik DNS kontrolünü ekler. Yalnız hostname gönderilir; Radar URL taraması yayımlanmaz. DNS filtre uyarısı kesin phishing sayılmaz, inceleme gerektirir.

Hassas formun JavaScript davranışı veya iframe içeriği incelenemiyorsa sonuç temiz/tamamlandı olmaz. İsteğe bağlı ağsız renderer yalnız mevcut HTML içindeki koddan ek DOM kanıtı çıkarabilir; dış kaynaklar, gerçek kullanıcı etkileşimi ve tam dinamik inceleme sağladığı iddia edilmez.

## Kurulum ve kontrol

Python 3.12 ile ayrı sanal ortamda, backend dizininden:

```sh
python -m pip install --require-hashes -r requirements-dev.lock
python -m pytest tests -q
python scripts/smoke_test_fastapi.py
uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Çalışma zamanı kurulumu için `requirements.lock` kullanılır. Gerçek model dosyaları Git ve imaj dışında sağlanır; uyumlu, yönetici tarafından doğrulanmış artifact gerekir. Model eksikliği temiz sonuç ürettirmez. `.env`, anahtarlar, ham HTML, model dosyaları ve yerel veritabanları Git'e veya paylaşılacak proje arşivine eklenmez.

## Eğitim ve değerlendirme

Eski `train_model.py` ve `train_html_model.py` çalıştırmaları dosya yazmadan kapanır. Doğrulanmış veriyi `scripts/export_training_datasets.py` ile dışa aktarın; `scripts/retrain_models.py` yalnız aday oluşturur. `scripts/promote_candidate_models.py` dosya kimliği ve kalite kapılarından sonra ayrı yayın işlemidir. Aktif artifact salt okunur bağlanmışsa bu koruma kaldırılmaz; yayın ayrı yönetici işidir ve servis yeniden başlatılması gerekir.

Gerçek analiz edilen HTML'nin UTF-8 özeti ve kaynak URL'si eğitim kaydına kadar taşınır. Ham HTML varsayılan olarak saklanmaz. Tahmin etiketi otomatik olarak doğrulanmış etiket sayılmaz.

Bağımsız, özel arşivden ağsız değerlendirme: [BENCHMARK.md](apps/backend/BENCHMARK.md). Eğitim ve test ayrımı, belirsiz sonuçlar, model sürümleri ve kaynak kanıtı raporlanır. Test verisi toplanmadan bir başarı yüzdesi verilmez.

## Web ve mobil

Halka açık web: https://keremduz.github.io/PhishCatch/ . Analiz ev sunucusundaki tüketici API'sinde yapılır; model ve veritabanı Pages'e taşınmaz. APK ve Flutter bilgileri [mobil belgede](apps/flutter_app/README.md).

Pages iş akışı yalnız ayrıca etkinleştirilen `PHISHCATCH_PAGES_ENABLED=true` depo değişkeniyle yayın yapar. Tüketici sürümü ALLSAFE kullanıcı oturumu veya entegrasyon anahtarı taşımaz.

## Belgeler

- [Tespit politikası, ücretsiz kaynaklar ve sınırlar](apps/backend/DETECTION.md)
- [Bağımsız değerlendirme](apps/backend/BENCHMARK.md)
- [Backend ve ALLSAFE sözleşmesi](apps/backend/README.md)
- [Mobil/web kullanımı](apps/flutter_app/README.md)
