# PhishCatch Flutter uygulamasi

QR ve URL analizi iki baglanti moduyla kullanilir. Varsayilan bagimsiz mod dogrudan PhishCatch servisine gider. Ana ekrandaki **Baglanti** dugmesinden ALLSAFE sunucusu secilip kurum hesabiyla giris yapildiginda taramalar merkezi ALLSAFE kaydina eklenir. Bu bitirme projesi prototipidir.

## Baglanti ve oturum

- ALLSAFE sunucu adresi yalnizca HTTPS kok adresi olabilir: `https://allsafe.example`.
- Adreste kullanici bilgisi, yol, sorgu veya fragment kabul edilmez.
- Mobil giris `POST /api/v1/auth/mobile/login`, hesap bilgisi `GET /api/v1/auth/me`, cikis `POST /api/v1/auth/mobile/logout` kullanir.
- ALLSAFE Bearer oturumu yalnizca uygulama belleginde saklanir; parola ve oturum diske yazilmaz. Uygulama yeniden acildiginda tekrar giris gerekir.
- Cikis, sunucu/mod degisikligi veya `401` yaniti yerel oturumu temizler. Giris basarisizsa taramalar bagimsiz servise otomatik yonlendirilmez.
- ALLSAFE taramalari `POST /api/v1/phishcatch/scans` uzerinden `source: qr|url` ve istemcinin urettigi UUID `client_request_id` ile gonderilir. Otomatik tekrar yapilmaz. API istemcisiyle ayni istek tekrar denenirse onceki UUID verilmelidir.
- Eksik, kismi veya basarisiz analiz temiz kabul edilmez. Bilinmeyen olasiliklar `—` olarak gosterilir; sifir risk puani uydurulmaz.
- Yerel kullanici girisi desteklenir; kurum OIDC girisi icin mobil akis henuz uygulanmamistir.

## Yerel gelistirme

Varsayilan bagimsiz sunucu `https://phishcatch-p4jc.onrender.com` adresidir. HTTP icin hem debug derlemesi hem acik `PHISHCATCH_ALLOW_DEV_HTTP=true` bayragi gerekir. Yalnizca `localhost`, `127.0.0.1`, `::1` ve Android emulatorunun ana makine adresi `10.0.2.2` kabul edilir. Release ve profile derlemeleri HTTPS gerektirir.

```sh
flutter run --dart-define=PHISHCATCH_ALLOW_DEV_HTTP=true --dart-define=PHISHCATCH_API_BASE_URL=http://10.0.2.2:8001 --dart-define=ALLSAFE_API_BASE_URL=http://10.0.2.2:8000
```

Web veya masaustu icin `10.0.2.2` yerine `localhost` kullanilir. `ALLSAFE_API_BASE_URL` yalnizca baglanti ekranindaki adresi doldurur; giris ve mod secimi kullanicinin islemidir. Android debug manifesti yerel HTTP trafigine izin verir; uygulama istemcisi yukaridaki adres/bayrak kisitlamasini uygular. Fiziksel telefonda erisilebilir bir HTTPS sunucusu gerekir. Fiziksel telefon/kamera kabul testi bu degisiklikte yapilmamistir.

## Dogrulama ve derleme

```sh
flutter pub get
dart format --output=none --set-exit-if-changed lib test
flutter analyze
flutter test
flutter build web --release --dart-define=PHISHCATCH_API_BASE_URL=https://phishcatch-p4jc.onrender.com
flutter build apk --release --dart-define=PHISHCATCH_API_BASE_URL=https://phishcatch-p4jc.onrender.com
```

Android APK ve iOS derlemesi icin ilgili platform araclari ayrica gerekir. Mock HTTP testleri oturumun yalnizca ALLSAFE'ye gonderilmesini, tarama kaynagini, `401` temizligini, baglanti degisikliklerini ve eksik sonuclarin guvenli sunumunu kontrol eder.
