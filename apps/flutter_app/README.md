# PhishCatch Flutter uygulamasi

QR ve URL analizi iki bağlantı moduyla kullanılır. Genel derleme bağımsız PhishCatch modunu korur. Ev sunucusu derlemesi `ALLSAFE_MANAGED_MODE=true` ile yalnız ALLSAFE üzerinden çalışır; eski Render servisine veya bağımsız analize geçemez. Bu bitirme projesi prototipidir.

## Baglanti ve oturum

- ALLSAFE sunucu adresi yalnizca HTTPS kok adresi olabilir: `https://allsafe.example`.
- Adreste kullanici bilgisi, yol, sorgu veya fragment kabul edilmez.
- Mobil giris `POST /api/v1/auth/mobile/login`, hesap bilgisi `GET /api/v1/auth/me`, cikis `POST /api/v1/auth/mobile/logout` kullanir.
- Mobil Bearer oturumu yalnızca uygulama belleğinde saklanır; parola ve oturum diske yazılmaz. Uygulama yeniden açıldığında tekrar giriş gerekir.
- Web kendi açıldığı kökeni kullanır; `/api/*` aynı kökende proxy edilir. Giriş/çıkış `/api/v1/auth/login` ve `/auth/logout` üzerinden HttpOnly çerez ve CSRF ile yapılır. Sayfa açılışında oturum `/auth/me` ile doğrulanır; başka kökene token/CSRF taşınmaz.
- Tarama geçmişi Core API üzerinden okunur. Çalışan kendi kayıtlarını, yetkili analist ve yönetici kurum kayıtlarını görür.
- Cikis, sunucu/mod degisikligi veya `401` yaniti yerel oturumu temizler. Giris basarisizsa taramalar bagimsiz servise otomatik yonlendirilmez.
- ALLSAFE taramalari `POST /api/v1/phishcatch/scans` uzerinden `source: qr|url` ve istemcinin urettigi UUID `client_request_id` ile gonderilir. Otomatik tekrar yapilmaz. API istemcisiyle ayni istek tekrar denenirse onceki UUID verilmelidir.
- Eksik, kismi veya basarisiz analiz temiz kabul edilmez. Bilinmeyen olasiliklar `—` olarak gosterilir; sifir risk puani uydurulmaz.
- Yerel kullanici girisi desteklenir; kurum OIDC girisi icin mobil akis henuz uygulanmamistir.

## Yerel gelistirme

Varsayilan bagimsiz sunucu `https://phishcatch-p4jc.onrender.com` adresidir. HTTP icin hem debug derlemesi hem acik `PHISHCATCH_ALLOW_DEV_HTTP=true` bayragi gerekir. Yalnizca `localhost`, `127.0.0.1`, `::1` ve Android emulatorunun ana makine adresi `10.0.2.2` kabul edilir. Release ve profile derlemeleri HTTPS gerektirir.

```sh
flutter run --dart-define=PHISHCATCH_ALLOW_DEV_HTTP=true --dart-define=PHISHCATCH_API_BASE_URL=http://10.0.2.2:8001 --dart-define=ALLSAFE_API_BASE_URL=http://10.0.2.2:8000
```

`ALLSAFE_API_BASE_URL` mobil başlangıç sunucusunu seçer. Web kendi kökenini kullanır ve aynı kökende API proxy gerekir. Android debug manifesti yerel HTTP trafiğine izin verir; release için erişilebilir HTTPS gerekir. Fiziksel telefon/kamera kabulü mock veya widget testiyle kanıtlanmaz.

## Dogrulama ve derleme

```sh
flutter pub get --enforce-lockfile
dart format --output=none --set-exit-if-changed lib test
flutter analyze
flutter test
flutter build web --release --no-web-resources-cdn --pwa-strategy=none --dart-define=ALLSAFE_MANAGED_MODE=true --dart-define=ALLSAFE_API_BASE_URL=https://sunucu.tailnet.ts.net
flutter build apk --release --dart-define=ALLSAFE_MANAGED_MODE=true --dart-define=ALLSAFE_API_BASE_URL=https://sunucu.tailnet.ts.net
```

Android APK ve iOS derlemesi icin ilgili platform araclari ayrica gerekir. Mock HTTP testleri oturumun yalnizca ALLSAFE'ye gonderilmesini, tarama kaynagini, `401` temizligini, baglanti degisikliklerini ve eksik sonuclarin guvenli sunumunu kontrol eder.

Örnek HTTPS adresi çalışan sunucu iddiası değildir. Windows PowerShell'de repo kökündeki `scripts/build_home_web.ps1`, boş hedef dizinine yönetilen web çıktısını üretir. `scripts/build_android.ps1` mevcut `android/key.properties` ve keystore ile imzalı release APK üretir; imza yoksa durur, debug imzasına geçmez. Anahtarlar Git'e alınmaz. Mevcut kurulu uygulamayı güncellemek için aynı paket/imza ve daha yüksek sürüm gerekir.

Özel sunucuya telefondan erişmek için aynı tailnet'te Tailscale açık olmalıdır; ayrıca ALLSAFE hesabıyla giriş gerekir. Sunucu entegrasyon anahtarı, modeller ve dış servis anahtarları istemciye eklenmez. Yönetilen profil ham upstream toplu analiz/eğitim API'lerini yayımlamaz; bu ekranlar bağımsız mod için kaynakta korunur, kurum inceleme ve eğitim onayı ALLSAFE yönetim panelindedir.

URLhaus sorguları için backend ortamında `URLHAUS_AUTH_KEY` gereklidir; [resmî URLhaus belgesi](https://urlhaus.abuse.ch/api/) anahtar edinme adımlarını açıklar. Anahtar APK/web derlemesine gömülmez. Anahtar yoksa URLhaus'a ağ isteği gönderilmez, katman `unavailable`, sağlık bilgisi `degraded` olur; bu durum temiz sonuç sayılmaz. Anahtar yapılandırılmış olsa da yanlış/iptal edilmiş bir anahtarın döndürdüğü 401, başarısız kontrol olarak kalır. Model yüklenmesi ve dış veri kaynaklarının erişilebilirliği ayrı durumlardır.

Arayüz mobil/tablet/masaüstü düzenine, azaltılmış hareket tercihine ve okunabilir açık temaya sahiptir. Kamera yaşam döngüsü ve izinleri yönetilir. Gerçek ilerleme bilgisi yoksa yüzde üretilmez; kısmi/başarısız analiz temiz sayılmaz. Gerçek Android kurulumu ve kamera ayrıca denenmelidir.
