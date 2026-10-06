# 🛡️ CyberTrack - Website Security Vulnerability & Posture Auditor

**CyberTrack** adalah platform sistem deteksi dan audit keamanan siber (*cybersecurity posture & vulnerability auditor*) website berbasis web yang beroperasi secara pasif, non-intrusif, cepat, dan legal untuk semua target domain publik.

Aplikasi ini mendeteksi celah keamanan konfigurasi (*Security Misconfiguration*), kelemahan transport SSL/TLS, celah proteksi injeksi skrip (XSS), pembajakan frame (*Clickjacking*), pembajakan sesi cookie (*Session Hijacking* & CSRF), dan celah pemalsuan email (*Email Spoofing* / Phishing) sesuai standar **OWASP Top 10**.

---

## 🚀 Fitur Utama

1. **Audit HTTP Security Headers Lengkap**:
   - `Content-Security-Policy (CSP)`: Perlindungan terhadap XSS dan injeksi data skrip liar.
   - `Strict-Transport-Security (HSTS)`: Menegakkan enkripsi HTTPS dan mencegah *SSL Stripping*.
   - `X-Frame-Options (XFO)`: Mencegah serangan *Clickjacking / UI Redressing*.
   - `X-Content-Type-Options (XCTO)`: Mencegah eksploitasi *MIME-sniffing*.
   - `Referrer-Policy`: Melindungi kebocoran token rahasia URL ke server pihak ketiga.
   - `Permissions-Policy`: Membatasi akses browser ke sensor/fitur perangkat (kamera, mikrofon, geolokasi).

2. **Inspeksi Sertifikat SSL/TLS & Enkripsi**:
   - Deteksi versi protokol (TLS 1.3, TLS 1.2, atau versi usang TLS 1.0/1.1).
   - Analisis kekuatan *Cipher Suite*.
   - Pengecekan masa berlaku sertifikat X.509, penerbit (CA), dan peringatan kedaluwarsa.
   - Deteksi *HTTP to HTTPS Automatic 301 Redirect* untuk memastikan tidak ada data plaintext.

3. **Audit Keamanan Cookie (Set-Cookie)**:
   - Evaluasi flag `Secure` (mencegah transmisi cookie via HTTP).
   - Evaluasi flag `HttpOnly` (mencegah pencurian cookie via JavaScript `document.cookie`).
   - Evaluasi atribut `SameSite` (`Strict`, `Lax`, `None`) untuk mitigasi *Cross-Site Request Forgery (CSRF)*.

4. **Pencegahan Kebocoran Informasi (Information Disclosure)**:
   - Deteksi kebocoran versi web server pada header `Server`.
   - Deteksi kebocoran framework backend pada header `X-Powered-By` (Express, PHP, ASP.NET).

5. **Postur Keamanan Domain & Email (Anti-Spoofing)**:
   - Pengecekan DNS **SPF (Sender Policy Framework)** (`v=spf1`).
   - Pengecekan DNS **DMARC Policy** (`_dmarc.domain.com`) untuk mencegah spoofing domain & phishing.
   - Pengecekan DNS **MX (Mail Exchange)** records.

6. **Scoring Engine & Rekomendasi Solusi Siap Pakai**:
   - Skor dinamis (0 - 100) dan Letter Grade (`A+`, `A`, `B`, `C`, `D`, `F`).
   - Pemetaan langsung ke kategori **OWASP Top 10**.
   - Dilengkapi *copy-paste remediation code snippets* untuk Nginx, Apache, Node.js Express, dan Cloudflare.

7. **Laporan & Ekspor**:
   - Cetak langsung / Simpan ke PDF (*Print-Ready*).
   - Unduh laporan lengkap dalam format JSON.
   - Salin ringkasan temuan ke clipboard.
   - Riwayat pemindaian tersimpan lokal (*LocalStorage*).

8. **Keamanan Sistem Internal (SSRF Protection)**:
   - Terintegrasi filter proteksi SSRF (*Server-Side Request Forgery*) terhadap IP lokal/private (RFC 1918, link-local, loopback).

---

## 💻 Cara Menjalankan

### Persyaratan:
- Node.js versi 18 ke atas (Direkomendasikan v20+)
- npm

### Langkah Menjalankan:
```bash
# 1. Masuk ke direktori proyek
cd c:\Users\verand\dev\cybertrack

# 2. Instal dependensi (jika belum)
npm install

# 3. Jalankan server
npm start
```

Buka browser Anda dan akses:
👉 **`http://localhost:3000`**

---

## 🛡️ Etika & Legalitas Pemindaian

Sistem ini dirancang sebagai **Passive Posture & Vulnerability Scanner**:
- Menggunakan permintaan standar HTTP/HTTPS (GET/HEAD) dan query DNS publik.
- **Tidak mengirimkan payload berbahaya**, tidak melakukan SQL injection test, tidak melakukan brute force, dan tidak melakukan fuzzing aktif.
- Sepenuhnya aman dan legal dijalankan untuk mengecek kesiapan keamanan website Anda sendiri maupun domain publik lainnya.
