# PhishCatch analizinin kapsamı ve sınırları

PhishCatch mezuniyet projesi prototipidir. Sade mobil/web sonucu kesin güvenlik garantisi değildir. Güncel karar profili ve işlem sınırları için [DETECTION.md](../apps/backend/DETECTION.md) esas alınır.

## Modeller ve başarı ölçümü

Ev sunucusundaki büyük URL modeli 30 URL özelliği ve 300 ağaç kullanan StandardScaler/RandomForest; HTML modeli 78 özellik kullanan HistGradientBoosting modelidir. Yaklaşık 656 MB ve 859 KB dosyalar özel salt okunur dizindedir, Git'e veya APK'ya gömülmez. İki model gerçek akışta tahmin üretmiştir; dosya büyüklüğü güncel başarı kanıtı değildir.

Kaynak artifact'ler scikit-learn 1.8.0'dan 1.9.1 ortamına uyarlanırken sınırlı yapay örnekler ve eğitilmiş durum kontrol edilmiştir. Bu, bütün girdilerde eşdeğerlik veya güncel doğruluk kanıtlamaz. Özellik çıkarıcıları özgün projeyle korunmuştur. Birleşik kural puanı phishing yüzdesi değildir.

Bağımsız yakın tarihli, doğrulanmış özel arşiv ve [değerlendirme aracı](../apps/backend/BENCHMARK.md) hazırlanır. Eğitim, ayar ve test URL/alan adı/zaman/şablon bakımından ayrılır; belirsiz sonuç başarılı tespit sayılmaz. Testlerin geçmesi ve birkaç zararsız canlı sorgu bu veri çalışmasının yerine geçmez.

## Ücretsiz kaynaklar

Varsayılan ücretsiz profil, eski sağlayıcı anahtarı bulunsa da ücretli/kimlik bilgili entegrasyonu açmaz. Güncel CERT Polska yerel listesi zorunlu kanıttır; özellikle Polonya kullanıcılarını hedefleyen kampanyalara yöneliktir, küresel tam kapsam değildir. URLhaus artık zorunlu phishing kaynağı değildir.

Etkinleştirilen Cloudflare Security DoH yalnız hostname gönderir. Tam URL yolu, query veya HTML paylaşmaz; Radar'da public tarama oluşturmaz. DNS filtre işareti kesin phishing türü sayılmaz, inceleme/belirsiz sonucudur. Normal DNS cevabı, NXDOMAIN ve hata temiz kanıtı değildir. Yönlendirmede DNS itibar kontrolü GET zincirinden sonradır.

## İçerik, özel ağ ve dinamik sayfalar

GET ve yönlendirmelerde hedefler DNS ile doğrulanır; genel IP gerçek sokete sabitlenir ve TLS Host/SNI/sertifika kontrolü korunur. Local/private/reserved/CGNAT/Tailscale ve geçiş IP'leri engellenir. Çerez, netrc, ortam proxy'si veya kullanıcı kimliği taşınmaz. HTML ve açılmış gzip çıktısı en fazla 1 MiB; Brotli desteklenmez. DNS, GET, RDAP ve HTML ayrı sonlandırılabilir süreçlerdedir; bunlar tek başına tarayıcı/ağ sandbox'ı değildir.

Hassas formdaki değerlendirilemeyen JavaScript, iframe, erişim engeli veya gerekli katmanın çalışmaması temiz sonuç verdirmez. Normal kart/CSRF/iframe/klavye olayı tek başına tehdit puanı değildir. Alan adı yaşı ve HTTPS temizlik kanıtı değildir. RDAP yalnız yardımcı bağlamdır.

İsteğe bağlı renderer ayrı ağsız konteynerde yalnız verilen orijinal HTML ve inline kodu çalıştırır. Dış JS/CSS/iframe, özgün HTTP güvenlik başlıkları, kullanıcı etkileşimi, OCR/ekran görüntüsü yoktur; kapsam her zaman eksik kalır. Ev sunucusunda ilk Chromium sandbox açılışı başarısız olduğundan bu özellik kapalıdır. Güvenlik kısıtları kaldırılarak açılmaz. Statik modeller çalışmaya devam eder.

## Anonim kullanım ve eğitim

Anonim consumer-1 yanıtı yalnız sürüm, URL, karar ve tarama durumunu içerir; gözlem veya eğitim örneği oluşturmaz. ALLSAFE kimliği ve yönetim yetkileri ayrı korunur. Tahmin, insan tarafından doğrulanmış etiket ve model yayını farklı işlemlerdir.

Gözlem kaydında ham HTML yerine gerçekten analiz edilen kaynağın özeti ve sayısal özellikler korunur. Kaynak URL eşleşmezse HTML eğitim verisi kullanılmaz. Eski doğrudan eğiticiler dosya yazmaz; aday/yayın akışı aktif dosya, takma ad ve kalite kapılarını denetler. Bu sürüm modelleri yeniden eğitmez veya otomatik yayımlamaz.
