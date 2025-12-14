G-EGS: Güvenli Envanter Yönetim Sistemi (Flask)
🌟 Proje Özeti : Bu proje, bir kurumun Bilgi Teknolojileri (BT) envanterini (donanım, cihazlar) merkezi ve güvenli bir şekilde yönetmek amacıyla Python Flask ile geliştirilmiş, tam özellikli bir web uygulamasıdır. Sistem, personel bazlı zimmet takibini kolaylaştırır, arızalı envanteri kaydeder ve barkod oluşturma gibi operasyonel süreçleri optimize eder.
🔑 Güvenlik ve Mimari Odak Noktaları (SecDevOps Vurgusu)Bu projenin temel farklılığı, sadece işlevselliğe değil, aynı zamanda güvenilir ve sürdürülebilir bir mimariye odaklanmasıdır.
Güçlü Parola Hashing: Tüm kullanıcı parolaları, standart hash fonksiyonları yerine endüstri standardı olan bcrypt kullanılarak güvenli bir şekilde saklanır ve yönetilir.
Erişim Kontrolü (ACL): Yönetici paneli ve kritik veri manipülasyon rotaları (/admin/*), yetkisiz erişimi engellemek için Flask-Login ile katı yetkilendirme kontrolüne (is_admin()) tabi tutulmuştur.
SQL Enjeksiyonu Koruması: Veritabanı etkileşimlerinin tamamında (app.py), güvenli ve parametreli sorgulama metotları kullanılarak SQL Enjeksiyonu riskleri minimize edilmiştir.Modüler Mimari: Veritabanı bağlantıları (get_db_connection()) global g objesi üzerinden yönetilerek kaynak sızıntıları önlenir ve kod okunabilirliği artırılır.
✨ Temel Özellikler : Yönetim ve Kullanıcı Kontrolü
Kullanıcı Yönetimi: Personel ve Yönetici (Admin) rollerinin eklenmesi/silinmesi ve yetkilendirilmesi.
Marka/Model Yönetimi: Merkezi bir listeden envanter marka ve model bilgilerinin kontrolü.
Nitelik Yönetimi: Cihaz türlerine özgü teknik özelliklerin (RAM, İşlemci Tipi vb.) merkezi olarak yönetilmesi.
Envanter ve Zimmet Süreçleri
Envanter Ekleme/Düzenleme: Kapsamlı özelliklerle yeni envanter kaydı ve mevcut kayıtların güncellenmesi.
Toplu Zimmet: Envanter öğelerinin seçili personele zimmetlenmesi ve zimmetten düşülmesi.
Zimmet Formu: Atama işlemini resmileştirmek için Yazdırılabilir Zimmet Formu oluşturma yeteneği (zimmet_form.html).
Barkod Etiketleme: Seçilen ürünler için farklı etiket boyutlarına uygun Barkod Yazdırma özelliği.
Raporlama ve AnalizTransfer Geçmişi: Tüm zimmet ve iade işlemlerinin tarih, gönderen ve alıcı bazında detaylı kaydı.
Arızalı Envanter Takibi: Arızalanan cihazları takip etme ve tamir sonrası kolayca envantere geri ekleme yeteneği.
🛠️ Kurulum ve ÇalıştırmaBu projeyi yerel ortamınızda ayağa kaldırmak için aşağıdaki adımları izleyin.
Ön Koşullar : Python 3.xGitAdım Adım KurulumBash# 1. Depoyu Klonlayın
git clone https://github.com/FaraoneyO77/G-EGS.git
cd G-EGS

# 2. Sanal Ortam Kurulumu
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# .\venv\Scripts\activate  # Windows

# 3. Bağımlılıkları Yükleyin
# requirements.txt dosyası olmadığı varsayılırsa:
pip install Flask Flask-Login bcrypt pandas

# 4. Uygulamayı Başlatın
python3 app.py
Uygulama başlatıldıktan sonra tarayıcınızda genellikle http://127.0.0.1:5000 adresinde erişilebilir olacaktır.İlk Giriş: login.html dosyasındaki ipucuna göre test amaçlı kullanıcılar mevcuttur: admin/adminpass (Yönetici) veya ahmet/1234 (Personel).
👨‍💻 Yazar ve İletişim: Bu proje, gerçek bir kurumsal ihtiyaca cevap vermek ve sağlam yazılım geliştirme prensiplerini uygulamak amacıyla oluşturulmuştur.
Geliştirici: Cihan Dik
Uzmanlık Alanı: SecDevOps, Python Geliştirme, Siber Güvenlik
LinkedIn: https://www.linkedin.com/in/cihan-dik/
E-posta: faraoney077@gmail.com
