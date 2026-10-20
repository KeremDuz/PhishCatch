# PhishCatch tespit akışı

Bu uygulama bir mezuniyet projesi prototipidir. Bir URL hakkında kesin güvenlik garantisi vermez. Bu belgedeki test sayıları veya eski model raporları güncel uçtan uca doğruluk oranı değildir.

## Karar profili

Varsayılan profilin gerekli bileşenleri: güncel yerel uyarı listesi, aynı GET içeriğine dayanan yönlendirme/HTML incelemesi, URL modeli ve HTML modeli. Yerel liste sağlayıcısı açıkça seçilir: PhishTank tam URL eşleşmesi veya CERT Polska alan adı ve alt alan adı eşleşmesi. RDAP kayıt bilgisi yardımcı bağlamdır; tarih bulunamaması temiz olduğuna dair kanıt oluşturmaz. URLhaus yalnız anahtar tanımlandığında eklenen zararlı yazılım kaynağıdır; phishing listesinin yerine geçmez. Google ve VirusTotal entegrasyonları isteğe bağlıdır. Kaynakların kullanım koşulları ve URL paylaşımı etkinleştirmeden önce değerlendirilmelidir.

İlk URL yerel listede doğrulanmış phishing olarak bulunursa hedef sayfa indirilmez. Diğer durumlarda tek GET akışı en fazla beş HTTP/meta-refresh yönlendirmesi izler. Her bağlantıda DNS yanıtı kontrol edilir ve soket bu genel IP'ye sabitlenir; Host/SNI/sertifika doğrulaması korunur. İlk, ara ve son URL'ler itibar ve URL modeli kontrollerine girer. HTML analizi aynı son GET gövdesini kullanır. İstekler çerez, uygulama anahtarı veya kullanıcı hesabı taşımaz; form gönderilmez.

Normal kart, adres, CVV, otomatik doldurma, CSRF, klavye olayı ve ödeme iframe'i tek başına phishing kanıtı değildir. Form/base/formaction ve `//host/path` hedefleri çözülür; alan adı karşılaştırması özel barındırma eklerini de içeren çevrim dışı Public Suffix List ile yapılır. Bir marka iddiası bir kez sayılır. Hassas formun ilgisiz hedefe gönderilmesi inceleme gerektirir; güçlü marka taklidiyle birleştiğinde yüksek risk oluşturabilir. Yalnız düzenli ifade eşleşmesi veri sızdırma ispatı sayılmaz.

Yerel model uyarısı diğer modelin düşük puanıyla temiz sonuca çevrilmez; çelişki çözülemiyorsa sonuç belirsizdir. Yaşlı alan adı güven puanı düşürmez. Bir VirusTotal şüpheli uyarısı veya tek zararlı motor sonucu tek başına engellemez, inceleme gerektirir. İki zararlı motor için kullanılan eşik bir politika tercihidir; ölçülmüş doğruluk iddiası değildir. Kuralların birleşik skoru kalibre edilmiş phishing olasılığı değildir.

Gerekli bileşen çalışmazsa sonuç temiz olamaz. JS ile oluşturulan boş uygulama kabukları boyut dolgusu olsa da ek analiz gerektirir. Güvenli ağ izolasyonu olan tarayıcı henüz yoktur: JS çalıştırma, ekran görüntüsü/OCR ve etkileşimli oturum analizi yapılmış gibi gösterilmez. `HTML_BROWSER_RENDER_ENABLED=1` bu sınırı kaldırmaz. Dinamik içerik değerlendirilemezse statik kanıtlar korunur ve tarama eksik kalır.

## Kaynak ve süre sınırları

Üretim bağımlılık fabrikası, URL güvenlik ön kontrolünü (8 sn), GET işini (35 sn), yardımcı RDAP işini (10 sn) ve HTML ayrıştırma/model işini (20 sn) ayrı, sonlandırılabilir işlemlerde çalıştırır. Unix'te işlem grubu öldürülür ve beklenerek temizlenir; CPU/bellek/çıktı sınırları da uygulanır. Bu bir tarayıcı/ağ sandbox'ı değildir. İşlem ortamına yönetim anahtarları aktarılmaz; dosya sistemi ayrı bir güven sınırı sağlamaz. Model dosyaları yalnız yöneticinin doğruladığı yerel dosyalardır.

HTML/JSON gövdeleri ve gzip açılmış çıktı en fazla 1 MiB'dir; gzip artıkları ve eksik akış reddedilir. Brotli desteği yoktur. Varsayılan anahtarsız profilde yukarıdaki işler sınırlıdır; isteğe bağlı eski uzak itibar istemcileri tüm işlem için ortak zorunlu süre sınırı sağlamaz. Bu sağlayıcılar açılırken ayrı süre sınırlı adaptör ve yük kabulü gereklidir. Genel istek sıklığı ve eşzamanlılık sınırları kapasite testi yerine geçmez.

GET ve HTML sonucu istekler arasında saklanmaz. Başarısız/eksik taramalar önbelleğe alınmaz; normal URL model/itibar girdileri en fazla 300 sn, itibar listesindeki eşleşmeme en fazla 60 sn saklanır. Yerel liste sorgusu önbelleğe alınmaz. Süresi dolan girdiler sonraki erişimde temizlenir; boşta çalışan RAM için arka plan silme garantisi yoktur. Modeller süreç boyunca sabittir; model değişiminden sonra servis yeniden başlatılarak önbellek sıfırlanır.

## Yerel listenin hazırlanması

Ev sunucusunda CERT Polska v2 etkinleştirilir. [Resmi kullanım koşulları](https://cert.pl/lista-ostrzezen/) her amaçla kullanıma izin verir; iş ortaklığı/onay ima edilmez. [Entegrasyon talimatı](https://cert.pl/en/warning-list/) gereği beş dakikada bir güncellenir; listedeki alan adı ve alt alan adları eşleşir, üst alan adı veya benzer son ekler eşleşmez. Silinen alan adları tam dosya değişimiyle kaldırılır. 15 dakikadan eski yerel kopya kullanılamaz. ETag/304 doğrulaması gereksiz dosya aktarımını azaltır. Kullanıcı URL'si kaynağa gönderilmez. Bu liste özellikle Polonya'yı hedefleyen kampanyalarla ilgilidir; küresel veya Türkiye'ye özel tam kapsama iddiası değildir.

```sh
python -m app.services.feed_update --download --provider certpl --output data/phishing-feed.json
```

PhishTank adaptörü de korunur. 21 Ekim 2026 kontrolünde resmi dosya/CDN isteği 404 döndüğünden bu sağlayıcının etkin olduğu iddia edilmez. Yalnız gözlenen sabit HTTPS CDN dosyasına yönlendirme kabul edilir; HTTP'ye düşülmez.

Kaynak: [PhishTank geliştirici belgesi](https://phishtank.org/developer_info.php). Doğrulanmış ve çevrim içi kayıtların saatlik dosyası kullanılır. Otomatik indirme için uygulama anahtarı önerilir; anahtarsız indirmeler sınırlıdır. OpenPhish Community koşulları halka açık bu hizmet için varsayılan izin kabul edilmediğinden otomatik etkinleştirilmez.

Backend çalışma ortamında:

```sh
python scripts/update_phishing_feed.py --download --app-key-file /private/phishtank-key --output data/phishing-feed.json
# Anahtar olmadan izin verilen tekil indirme için --app-key-file seçeneğini kaldırın.
# Yönetici tarafından resmi kaynaktan alınmış dosya için:
python scripts/update_phishing_feed.py --input /private/online-valid.json.bz2 --output data/phishing-feed.json
```

Güncelleme sıkıştırılmış/gövde boyutunu sınırlar, yalnız URL/alan adı SHA-256 özetlerini saklar, dosyayı özel izinle atomik değiştirir. Başarısız güncelleme önceki dosyayı bozmaz. Anonim analiz eğitim verisi kaydetmez. Dosya/anahtar/ham liste Git'e konmaz. Docker imajında güncelleme modülü `python -m app.services.feed_update` olarak kullanılabilir. PhishTank anahtarlı indirmeyi saatlik, anahtarsız indirmeyi en fazla günde iki kez; CERT Polska indirmesini beş dakikada bir ve her işi dışarıdan 90 sn süre sınırıyla zamanlayın. PhishTank için 26 saat, CERT Polska için 15 dakika aşımı veya bozuk liste `unavailable` olur; eksik kaynak sessizce çıkarılarak yeşil sonuç üretilmez.

## Model değerlendirme ve yayına alma

Tahmin, doğrulanmış etiket ve modelin yayına alınması ayrı işlemlerdir. Dışa aktarma onay bilgisi, etiket kaynağı, gerçek gözlem zamanı ve URL/alan adı/HTML kimlik özetlerini korur. Etiket zamanı gözlem zamanı yerine kullanılmaz. Eski kimliksiz CSV'ler otomatik olarak güvenilir değerlendirme verisi sayılmaz.

Yeniden eğitimde yeni zamandaki kayıtlar testte ayrılır; testteki alan adı, yakalanmış HTML özeti ve aynı özellik vektörleri eğitimden çıkarılır. Aynı URL'nin tekrarları test sayısını artırmaz; çelişkili etiket reddedilir. Ham HTML özeti kampanya/şablon ailesi tanıma değildir; kampanya benzerliği ayrıca incelenmelidir. Kaydedilen aday tam olarak değerlendirilen modeldir, test kümesi üzerinde tekrar eğitilmez. Veri ve model özeti ile test kimlik özeti rapora bağlanır.

Yayına alma tabanı: en az 500 test örneği, 300 temiz/100 phishing, 100 farklı alan adı grubu; precision ≥0.98, recall ≥0.90, F1 ≥0.94, yanlış alarm ≤%1 ve %95 Wilson üst sınırı ≤%2. Aday özeti eşleşmeli, karar eşiği 0.5 olmalı; `--force` bunları aşamaz. Bunlar başlangıç kabul hedefleridir, sağlandıkları iddia edilmemektedir. Deneme amaçlı küçük veriler aktif modeli değiştiremez. Bağımsız yakın tarihli bir kohort ile tüm karar akışı için ayrıca kapsama, belirsiz sonuç oranı, yanlış alarm, kaçırma ve gecikme ölçülmelidir; model metriği tek başına uygulama doğruluğu değildir.

## Doğrulama

```sh
python -m pytest tests -q
python scripts/smoke_test_fastapi.py
```

Davranış testleri kontrollü örnekleri ve model çıktısı taklitlerini kullanır; gerçek phishing yakalama oranını ölçmez. Canlı zararsız site denemeleri de yalnız işlev kontrolüdür. Mevcut büyük URL ve HTML modellerinin ağırlıkları bu değişiklikte değiştirilmez. Geniş ve bağımsız bir veri kümesi olmadan güncel başarı yüzdesi verilemez.
