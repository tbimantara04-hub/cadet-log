# Proposal Paper: Implementasi Keamanan Kriptografi Hibrida (ECC dan Ascon-128) pada Sistem Informasi Pencatatan Keluar Masuk Taruna (Guard App)

## 1. Latar Belakang
Manajemen pergerakan mahasiswa atau taruna yang keluar masuk area kampus merupakan aspek krusial dalam menjaga keamanan lingkungan, khususnya pada institusi dengan standar operasional yang ketat seperti Politeknik Siber dan Sandi Negara (Poltek SSN). Sistem pencatatan konvensional (seperti buku tamu manual) atau sistem digital dasar yang tidak dilindungi dengan algoritma enkripsi yang memadai sangat rentan terhadap manipulasi data, penyadapan jaringan, kebocoran privasi identitas taruna, dan tidak memiliki integritas yang dapat dipertanggungjawabkan dalam proses audit keamanan. 

Oleh karena itu, diperlukan sebuah aplikasi pencatatan (*gate-log*) terpusat yang responsif, mudah digunakan oleh petugas keamanan (satpam), serta mampu menjamin kerahasiaan dan keaslian data operasional sejak dari perangkat klien (*browser*) hingga ke server. Solusi ini harus dicapai dengan meminimalisasi beban komputasi menggunakan standar keamanan kriptografi tingkat lanjut yang tergolong ringan (*lightweight cryptography*).

## 2. Rumusan Masalah
Berdasarkan latar belakang di atas, rumusan masalah dalam perancangan sistem ini adalah:
1. Bagaimana merancang antarmuka sistem pencatatan perizinan keluar taruna yang efisien dan dapat mengakomodasi pencatatan individu maupun massal (rombongan) guna mempercepat antrean di pos penjagaan?
2. Bagaimana mengamankan jalur transmisi data sensitif dari perangkat klien (petugas) ke server API agar tahan terhadap serangan intersepsi seperti *Man-In-The-Middle (MITM)* dan modifikasi muatan (*payload manipulation*)?
3. Bagaimana mengimplementasikan protokol Kriptografi Hibrida menggunakan perpaduan algoritma *Elliptic Curve Cryptography* (ECC) dan standar *Lightweight Cryptography* Ascon-128 di lingkungan antarmuka web dan *backend*?

## 3. Keamanan dan Algoritma Kriptografi yang Digunakan
Sistem *Guard App* dirancang dengan arsitektur **Kriptografi Hibrida (Hybrid Cryptography)**, sebuah metode yang menggabungkan algoritma kunci publik (asimetris) untuk menyelesaikan masalah distribusi kunci yang aman, dan algoritma kunci simetris untuk melakukan enkripsi data riil secara cepat.

**Komponen Algoritma yang Digunakan:**
1. **Elliptic Curve Cryptography (ECC) - Curve P-256:** 
   Digunakan sebagai basis protokol pertukaran kunci rahasia (*Elliptic Curve Diffie-Hellman / ECDH*). ECC dipilih karena mampu memberikan tingkat keamanan yang sangat tinggi dengan ukuran kunci yang jauh lebih kecil (256-bit) jika dibandingkan dengan algoritma konvensional (seperti RSA yang membutuhkan 3072-bit untuk tingkat keamanan yang setara), sehingga menghemat *bandwidth* dan proses komputasi (*resource-constrained friendly*).
2. **HKDF-SHA256 (HMAC-based Key Derivation Function):** 
   Fungsi ini digunakan untuk menurunkan (*derive*) nilai *Shared Secret* hasil kesepakatan ECDH menjadi sebuah *Key Encryption Key* (KEK) berukuran 16-byte yang tangguh dan terdistribusi secara seragam (*cryptographically strong*).
3. **Ascon-128 (Lightweight AEAD):** 
   Merupakan algoritma pemenang standar kriptografi ringan dari *National Institute of Standards and Technology* (NIST). Algoritma ini digunakan di dua tempat: pertama, membungkus (*key wrapping*) kunci simetris; kedua, mengenkripsi muatan data JSON (*payload*). Ascon berjenis *Authenticated Encryption with Associated Data* (AEAD), yang tidak hanya menjamin **kerahasiaan** (*confidentiality*), tetapi juga melakukan validasi **otentikasi/integritas** (*integrity*), yang akan langsung membatalkan proses apabila *ciphertext* mengalami modifikasi satu bit pun di tengah jalan.

**Alur Kerja Keamanan (Kriptografi Workflow):**
1. **Server** membangkitkan/menyimpan pasangan kunci statis ECC P-256 dan mendistribusikan *Public Key* miliknya kepada *browser* petugas secara bebas.
2. Saat form akan disubmit, **Klien (Browser)** secara lokal membangkitkan pasangan kunci *ephemeral* (sementara) ECC dan menghitung *Shared Secret* menggunakan ECDH dengan *Public Key* server.
3. Klien menurunkan *Shared Secret* menjadi KEK menggunakan algoritma HKDF.
4. Klien menghasilkan *Ascon Symmetric Key* acak (16-byte). Kunci ini dibungkus/dienkripsi (*wrapped*) menggunakan KEK dan algoritma Ascon.
5. Klien mengenkripsi data log mahasiswa sesungguhnya (*payload data*) menggunakan *Ascon Symmetric Key*.
6. Klien mengirim paket ke server berisi: *Client Ephemeral Public Key*, *Wrapped Key*, dan *Ciphertext Data*.
7. Server menerima paket, mengekstraksi *Client Public Key*, lalu menjalankan perhitungan ECDH yang sama dengan *Private Key* statisnya untuk merekonstruksi *Shared Secret* dan KEK.
8. Server menguraikan (*unwrap*) *Ascon Symmetric Key*, dan menggunakannya untuk mendekripsi data log mahasiswa (*payload*) sebelum menyimpannya ke dalam database.

## 4. Fitur Utama Sistem (Guard App)
Aplikasi dibangun menggunakan *tech-stack* FastAPI (Python) sebagai *backend* dan *Vanilla JavaScript* di *frontend*. Berikut adalah rincian fiturnya:
1. **Pencatatan Mode Ganda (Dual-Mode Entry):**
   - **Mode Individu:** Pencatatan izin keluar untuk satu taruna menggunakan menu pencarian interaktif.
   - **Mode Massal (Bulk Entry):** Memungkinkan petugas untuk melakukan pemililihan banyak taruna sekaligus menggunakan metode *multi-select* (Ctrl/Cmd-Click & Long-press), yang dirancang untuk mengurai antrean panjang saat ada izin keluar rombongan.
2. **Dashboard Monitoring dan Kendali Interaktif:** 
   - Antarmuka petugas memiliki desain berstandar modern menggunakan tema gelap bertempo transparan (*Glassmorphism Dark Theme*) yang dirancang khusus untuk kenyamanan visibilitas petugas saat berjaga malam. Tabel dibuat dengan dukungan *sticky header* dan *custom scroll* agar muatan ribuan baris data tetap dapat dibaca dengan mudah.
3. **Automasi Impor Data (Spreadsheet Sync):**
   - Backend terintegrasi dengan modul yang membaca file berekstensi *Excel* (di dalam `db_folder`) untuk secara otomatis menarik pangkalan data identitas mahasiswa (NPM dan Nama) masuk ke basis data operasional (SQLite), meniadakan input manual dari pihak admin.
4. **Log Audit Sistem (Audit Trail / Non-Repudiation):**
   - Setiap operasi krusial, baik itu "pencatatan taruna keluar", maupun aksi "Tandai Semua Kembali" yang mengeksekusi penghapusan log aktif, akan otomatis direkam di dalam tabel `audit_logs` yang terpisah, melampirkan identitas penjaga (*Guard ID*) dan stempel waktu murni dari sisi server.

## 5. Harapan dan Tujuan yang Ingin Dicapai
- **Keamanan dan Integritas Data Mutlak:** Mencegah dengan sukses upaya rekayasa atau manipulasi (*tampering*) data keluar-masuk taruna oleh peretas jaringan atau pihak *insider*, melindungi privasi taruna dengan penyandian kriptografi terotorisasi yang *seamless* (berjalan transparan di latar belakang).
- **Meningkatkan Efisiensi dan Akurasi Data Pos Jaga:** Memangkas drastis waktu pengisian izin keluar secara manual melalui mekanisme sinkronisasi database dan fitur *Bulk Entry*, menghapus celah salah catat *(human error)* pada sistem konvensional.
- **Manajemen Kampus Terpusat:** Menghadirkan lingkungan institusi yang lebih aman dan terkontrol. Pimpinan dan administrator dapat melakukan penelusuran (audit) mutlak berbasis waktu siapa dan penjaga mana yang memfasilitasi log tersebut.
- **Sumbangsih Nilai Akademik & Literatur:** Menjadi *Proof of Concept* (purwarupa bukti konsep) konkrit dari implementasi algoritma terbaru **NIST Lightweight Cryptography (Ascon)** pada aplikasi web berskala mikro (*micro-framework*) FastAPI yang diintegrasikan langsung dengan *Web Crypto API* Javascript, menunjukkan bahwa standar kriptografi tingkat militer dapat berjalan secara gegas walau diterapkan pada web dan *device* bersumber daya terbatas.
