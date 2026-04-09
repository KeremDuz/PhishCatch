import pandas as pd
import re
import math
from urllib.parse import urlparse

# --- 1. Matematiksel Yardımcı Fonksiyon (Entropi Hesaplama) ---
# Entropi, bir metindeki karakterlerin rastgeleliğini/karmaşıklığını ölçer. 
# Phishing URL'leri genelde anlamsız rastgele harflerden oluştuğu için entropisi yüksektir.
def calculate_entropy(url):
    if not url:
        return 0
    entropy = 0
    for x in set(url):
        p_x = float(url.count(x)) / len(url)
        entropy += - p_x * math.log(p_x, 2)
    return round(float(entropy), 4)

# --- 2. Ana Özellik Çıkarım Fonksiyonu ---
def extract_final_features(url):
    if not isinstance(url, str):
        return pd.Series([0]*16) # Hata almamak için 16 sıfır dönüyoruz
    
    features = {}
    url_lower = url.lower()
    
    # URL'yi yapısal parçalara ayırıyoruz (Örn: netloc = domain, path = klasörler)
    # Eğer url 'http' ile başlamıyorsa parser doğru çalışmayabilir, o yüzden ekliyoruz
    parsed_url = urlparse(url) if url.startswith('http') else urlparse('http://' + url)
    
    # --- GRUP 1: Yapısal ve Uzunluk Özellikleri (Structural & Length) ---
    features['url_length'] = len(url)
    features['hostname_length'] = len(parsed_url.netloc)
    features['path_length'] = len(parsed_url.path)
    
    # İlk dizin uzunluğu (örn: site.com/admin/login -> 'admin' uzunluğu)
    path_parts = [part for part in parsed_url.path.split('/') if part]
    features['first_dir_length'] = len(path_parts[0]) if path_parts else 0
    
    # --- GRUP 2: Karakter Sayımları (Character Counts) ---
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['at_symbol_count'] = url.count('@')
    features['slash_count'] = url.count('/')
    features['question_mark_count'] = url.count('?')
    features['equal_count'] = url.count('=')
    
    features['digit_count'] = sum(c.isdigit() for c in url)
    features['letter_count'] = sum(c.isalpha() for c in url)
    
    # --- GRUP 3: İleri Düzey Siber Güvenlik Metrikleri (Advanced Security) ---
    features['entropy'] = calculate_entropy(url)
    
    # Domain kısmında IP adresi kullanılmış mı?
    features['has_ip_in_domain'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc) else 0
    
    # Şüpheli kelime barındırıyor mu?
    suspicious_words = ['login', 'secure', 'update', 'account', 'verify', 'bank', 'free', 'admin', 'webscr', 'password']
    features['has_suspicious_word'] = 1 if any(word in url_lower for word in suspicious_words) else 0
    
    # URL Kısaltıcı kullanılmış mı?
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'is.gd', 'ow.ly', 'cutt.ly']
    features['is_shortened'] = 1 if any(short in parsed_url.netloc for short in shorteners) else 0
    
    return pd.Series(features)

# --- 3. Veri Setine Uygulama ve Kaydetme ---
print("CSV dosyası okunuyor...")
df = pd.read_csv('balanced_urls.csv') # İndirdiğin dosyanın adı

print("Özellikler çıkarılıyor... (Bu işlem veri boyutuna göre birkaç dakika sürebilir)")
# Apply fonksiyonu ile her URL'yi parçalayıp yeni kolonlar üretiyoruz
extracted_features = df['url'].apply(extract_final_features)

# Etiket (result: 0 veya 1) kolonunu ve çıkardığımız özellikleri birleştiriyoruz
# (Eğitimde bize URL'nin metni lazım değil, sadece sayılar ve etiket lazım)
final_dataset = pd.concat([df['result'], extracted_features], axis=1)

print("Kayıt işlemi yapılıyor...")
# Eğitimde kullanmak üzere yeni CSV olarak kaydediyoruz!
final_dataset.to_csv('phishcatch_training_data.csv', index=False)

print("İşlem tamamlandı! 'phishcatch_training_data.csv' dosyası model eğitimi için hazır.")