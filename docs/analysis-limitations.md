# PhishCatch analizinin kapsamı ve sınırları

PhishCatch bir bitirme projesi prototipidir. Sonuç, bağlantının her koşulda
güvenli olduğuna ilişkin garanti değildir. Mobil uygulamadaki sade sonuç ekranı,
sunucudaki analiz ve eksik kanıt bilgisini değiştirmez.

## Eğitilmiş modeller

Ev sunucusunda seçilen URL modeli, 30 URL özelliğini kullanan bir
`StandardScaler + RandomForestClassifier` modelidir; 300 ağaç içerir. Dosya
yaklaşık 656 MB'dır. HTML modeli 78 URL/DOM özelliğini kullanan
`HistGradientBoostingClassifier` modelidir; çalışma dosyası yaklaşık 859 KB'dır.
Dosyalar özel, salt okunur model dizininden yüklenir; Git'e veya uygulama
paketine eklenmez.

İki model Linux sunucusunda yüklenmiş ve gerçek analiz akışında tahmin
üretmiştir. URL modeli, yönlendirme sonrasındaki URL özelliklerini inceler;
HTML modeli, indirilebilen HTML içeriğini ve DOM özelliklerini inceler. Modelin
yüklü olması ile belirli bir sayfada HTML analizi yapılabilmesi ayrı durumlardır.

Kaynak modeller scikit-learn 1.8.0 ile oluşturulmuş, çalışma kopyaları 1.9.1
ortamına uyarlanmıştır. Uyarlama sırasında sınırlı yapay örneklerde tahmin ve
eğitilmiş durum kontrolleri yapılmıştır. Bu kontrol, sürümler arasında tüm
girdiler için eşdeğerlik veya güncel internette belirli bir doğruluk oranı
kanıtlamaz. Dosyanın büyük olması da daha doğru olduğu anlamına gelmez.

Güvenilir bir başarı oranı açıklamadan önce yeni, etiketleri bağımsız doğrulanmış
bir test kümesi hazırlanmalıdır. Aynı alan adına ait örnekler eğitim ve test
arasında ayrılmalı; tarih ayrımı, yanlış alarm oranı, phishing yakalama oranı ve
karar eşiği birlikte değerlendirilmelidir. Model çıktısı, sistemin birleştirilmiş
kural puanıyla aynı şey değildir; birleşik puan kalibre edilmiş olasılık değildir.

## Kısmi ve belirsiz sonuç

- URLhaus anahtarı mevcut ev sunucusunda tanımlı değildir. Bu kaynak mevcut
  analiz akışında zorunlu adım olarak bulunduğundan, diğer adımlar çalışsa bile
  sonuç kısmi/belirsiz kalabilir. Anahtar olmaması, bağlantının zararlı veya temiz
  olduğuna kanıt sayılmaz. URLhaus dışındaki isteğe bağlı sağlayıcıların da
  anahtarları tanımlı değildir.
- Bir tehdit kaynağının URL'yi listesinde bulamaması, sayfanın güvenli olduğunu
  kanıtlamaz.
- JavaScript ile oluşan içerik, bot engeli, erişim hatası, süre aşımı, eksik model
  veya HTML olmayan hedef nedeniyle gerekli kanıt elde edilemeyebilir. Böyle
  bir sonuç temiz kabul edilmez. Yeterince güçlü zararlı kanıt bulunduğunda,
  başka bir kaynak eksik olsa bile zararlı uyarısı üretilebilir.
- Giriş yapılmış kullanıcı oturumu gerektiren veya kullanıcısına özel içerik,
  tarayıcısındaki hâliyle görülmez; kullanıcının çerezleri sunucuya taşınmaz.

## Sayfa indirme güvenliği ve kaynak sınırları

URL çözümleme ve HTML indirme yalnızca HTTP(S) hedeflerini kullanır. Her
yönlendirmede hedef tekrar denetlenir. Yerel, özel, ayrılmış, multicast, CGNAT
(Tailscale dahil) ve IPv6 geçiş adresleri engellenir. Karışık DNS yanıtındaki
adreslerden biri engelliyse hedefin tamamı reddedilir.

Denetlenmiş genel IP, gerçek bağlantı hedefine sabitlenir; böylece DNS'in kontrol
sonrası farklı IP vermesi özel ağa erişim açmaz. HTTPS bağlantısı özgün sunucu
adını Host, TLS SNI ve sertifika denetiminde korur. Ortam proxy'leri, netrc
kimlik bilgileri ve otomatik yönlendirmeler kullanılmaz. Sertifika denetimi
kapatılmaz.

HTML gövdesi en fazla 1 MB'dır. Gövde okuyucusu dolu bir blok beklemek yerine
eldeki veriyi okur; okumalar arasında 15 saniyelik duvar saati bütçesini denetler.
Soket bekleme süresi en fazla 5 saniyedir, mümkün olduğunda kalan bütçeye göre
kısaltılır. Geç gelen veri özellik çıkarımına aktarılmaz. Bağlantılar hata ve
yönlendirme durumunda da kapatılır. Sunucunun `Accept-Encoding: identity`
isteğine rağmen sıkıştırılmış gövde göndermesi, kontrolsüz açma döngüsü yerine
eksik analiz olarak ele alınır.

Bu bütçe tüm analiz isteğinin kesin toplam süresi değildir. İlk DNS çözümlemesi,
yanıt başlıkları, HTTP aktarım çerçevesi ve diğer tarayıcı adımları için ayrı,
zorla sonlandırılabilir bir işçi süreci henüz yoktur. Eşzamanlı istek ve istek
sıklığı sınırları riski azaltır; uygulama hizmet engelleme saldırılarına dayanıklı
bir genel servis olarak sunulamaz. Herhangi bir kaynak eksiğini temiz sonucuna
çevirerek süreyi kısaltmamak gerekir.

WHOIS sorgusu ayrı bir yerel araçla, kabuk açmadan, yalnızca geçerli DNS
etiketleriyle, seçenek sonlandırıcısı (`--`) ve 3 saniyelik süreç zaman aşımıyla
çalıştırılır. Bu protokolün kayıt kuruluşu yönlendirmeleri, HTTP için uygulanan
IP sabitleme politikasını kullanmaz. WHOIS ağ çıkışı ve süreç çıktısı için tam
yalıtım, ayrı analiz işçisi tasarımında ayrıca ele alınmalıdır.

## JavaScript ve tarayıcı yalıtımı

Ev sunucusunda headless tarayıcı kapalıdır. Önceki tarayıcı uygulamasının yalnız
ilk URL'yi denetlemesi; yönlendirme, iframe ve JavaScript alt isteklerini
sınırlandırmaması nedeniyle, seçenek açılsa bile tarayıcı başlatılmaz ve açıkça
eksik analiz döner. Dinamik sayfa desteği ancak ağ çıkışı kısıtlanmış, sunucunun
özel ağlarına erişemeyen ayrı bir tarayıcı işçisiyle eklenmelidir. Bu özellik
kapalıyken statik HTML ve URL modelleri çalışmaya devam eder.

## Anonim kullanım ve eğitim verisi

Anonim tüketici akışı yalnızca sade analiz sonucunu döndürmelidir; hesap,
yönetim, genel tarama geçmişi, model dosya yolu, sağlayıcı ayrıntıları veya eğitim
onayı vermez. Anonim tarama, tek başına bir eğitim etiketi değildir. Anonim
akışın varsayılanı sunucuda tarama gözlemi veya eğitim örneği oluşturmamaktır.

Kurumsal ALLSAFE akışının kimlik doğrulaması ve yetkileri ayrıdır. Doğrulanmış
etiket, eğitim için onay ve yeni modelin yayına alınması ayrı işlemler olarak
kalır. Bir tahminin kendi çıktısıyla yeniden eğitilmesi, modelin hatalarını
doğrulanmış veri gibi çoğaltacağı için otomatik yapılmaz.
