# PRD — Cisco Switch Access Review Tool

**Status:** Draft untuk implementasi  
**Tanggal:** 27 Oktober 2026  
**Target:** aplikasi lokal dengan satu entry point/script dan UI yang rapi

## 1. Ringkasan produk

Bangun tool lokal untuk mengumpulkan bukti access review dari Cisco switch melalui SSH dan menyajikannya dalam file Excel yang rapi, dapat ditelusuri, dan siap ditinjau auditor TI. Pengguna memasukkan satu atau banyak IP address, memilih kredensial yang sama untuk semua perangkat atau kredensial berbeda per perangkat, lalu menjalankan pengumpulan data. Tool hanya menjalankan perintah baca yang telah disetujui dan tidak menyediakan fitur perubahan konfigurasi perangkat.

**Penting mengenai cakupan versi:** Cisco IOS 12.x dan Cisco IOS XE adalah keluarga/versioning yang berbeda. Istilah “IOS XE versi 12 sampai latest” dalam permintaan ditafsirkan sebagai dukungan terhadap Cisco IOS 12.x serta IOS XE versi yang relevan hingga rilis terbaru saat implementasi. Dukungan tidak dapat dijamin untuk semua model dan rilis tanpa pengujian; versi/model yang teruji harus dicatat di matriks kompatibilitas. Perangkat yang belum teruji dapat dicoba secara best effort dengan hasil yang menyatakan batasannya.

## 2. Tujuan dan ukuran keberhasilan

- Mengurangi pekerjaan manual pengumpulan bukti akses dari satu atau banyak switch.
- Menghasilkan workbook dengan identitas perangkat, bukti, hasil evaluasi awal, status pengumpulan, serta keterbatasannya.
- Menjaga kredensial dan data sensitif tetap lokal dan meminimalkan penyimpanannya.
- Menjamin desain aplikasi tidak menawarkan perintah konfigurasi, edit, delete, atau write.

**Kriteria keberhasilan rilis:** seluruh kriteria penerimaan pada bagian 12 lulus; matriks pengujian mencakup sekurangnya satu perangkat/fixture IOS 12.x dan satu IOS XE, termasuk kasus command tidak didukung, output tidak lengkap, dan kegagalan koneksi. Kualitas audit diukur dari keterlacakan bukti dan status yang jujur, bukan klaim bahwa semua kontrol pasti compliant.

## 3. Pengguna dan ruang lingkup

**Pengguna:** IT auditor, network administrator, dan tim security yang berwenang mengakses perangkat.  
**Platform awal:** aplikasi lokal Python dengan UI berbasis browser lokal atau desktop; satu perintah/entry point untuk menjalankan aplikasi. Dependensi boleh terpisah dan harus didokumentasikan. Tidak membutuhkan layanan cloud.  
**Di dalam cakupan:** SSH, input dan validasi daftar perangkat, pengumpulan terkontrol, analisis awal, ekspor XLSX, status per perangkat, dan dokumentasi penggunaan.  
**Di luar cakupan:** perubahan konfigurasi, remediasi, provisioning, pencarian otomatis jaringan, penjadwalan, integrasi SIEM/ITSM, SSH key/MFA dan inventaris akun pada server AAA eksternal untuk MVP. Hasil switch tidak membuktikan keanggotaan atau status akun di server AAA.

## 4. Alur pengguna dan UI

1. Buka aplikasi lokal. UI memiliki halaman/input **Devices & Credentials**, **Review & Run**, **Progress**, dan **Results**; tampilan bersih, label jelas, serta status berwarna yang juga memiliki teks.
2. Pilih mode **Single device**, **Bulk — shared credentials**, atau **Bulk — credentials per device**. Input alamat IP satu per baris atau impor CSV. Mode shared meminta username dan password sekali. Mode per-device menerima IP, username, dan password untuk setiap baris, dengan opsi menambah/menghapus baris input UI; hapus di sini hanya menghapus input lokal, bukan data perangkat.
3. Validasi sebelum menjalankan: IP IPv4/IPv6 yang valid, port SSH 1–65535 (default 22), username/password wajib, duplikasi endpoint ditandai dan harus diperbaiki, serta batas jumlah perangkat dan concurrency yang dapat dikonfigurasi dengan default konservatif. Tampilkan kesalahan per baris tanpa menampilkan password. Versi awal tidak wajib menerima hostname.
4. Tampilkan ringkasan jumlah target, mode kredensial, dan peringatan bahwa output dapat berisi data sensitif. Tidak pernah tampilkan password pada ringkasan atau log.
5. Verifikasi SSH host key sesuai bagian 6, lalu jalankan. Tampilkan status per target: queued, connecting, collecting, completed, partial, failed, atau cancelled; tampilkan alasan yang aman untuk operator.
6. Pengguna dapat membatalkan run. Target aktif dihentikan dengan menutup sesi dan target dalam antrean tidak dimulai. Hasil yang sudah terkumpul tetap dapat diekspor dan diberi status cancelled/partial.
7. Tampilkan ringkasan hasil dan simpan workbook ke lokasi lokal pilihan pengguna. Tampilkan pesan keberhasilan dan lokasi hasil.

**Impor CSV:** UTF-8, header `ip,port,username,password` untuk mode per-device; `ip,port` untuk shared, dengan port opsional. Template per-device hanya berisi header dan contoh placeholder, tanpa kredensial nyata. Peringatkan bahwa CSV berisi password adalah plaintext; pengguna bertanggung jawab melindungi dan menghapus file sumber. Aplikasi tidak membuat salinan permanen, log, atau file sementara berisi password. Error impor menyebut nomor baris dan kolom, tanpa nilai password. Untuk shared mode, kredensial di CSV ditolak agar tidak terabaikan secara diam-diam.

## 5. Kebutuhan fungsional dan bukti

### 5.1 Koleksi terbatas

Gunakan SSH interaktif dengan timeout koneksi, autentikasi, perintah, dan batas ukuran output yang dapat dikonfigurasi. Jalankan perintah secara berurutan per perangkat, dengan concurrency antar perangkat dibatasi. Tangani pagination dan prompt secara aman tanpa mengirim respons yang dapat mengonfirmasi perubahan; jika pagination tidak dapat ditangani secara aman, tandai output incomplete. Jika `terminal length 0` digunakan, perintah ini hanya mengubah pengaturan sesi sementara, bukan konfigurasi tersimpan; penggunaannya harus berada dalam allowlist, didokumentasikan, dan diuji. Jangan masuk configuration mode, menjalankan shell, atau mengirim perintah sewenang-wenang dari UI, CSV, maupun input perangkat.

Allowlist awal hanya untuk pengambilan bukti; keberhasilan setiap perintah bergantung pada model, versi, privilege, dan konfigurasi:

| Tujuan | Kandidat perintah read-only | Bukti yang diharapkan / batasan |
|---|---|---|
| Identitas | `show version`, `show inventory` | Hostname/model, versi, serial bila tersedia; stack mungkin memiliki lebih dari satu anggota. |
| Akun lokal | `show running-config` disaring di perangkat atau dikumpulkan sesuai kontrol data di bawah | Baris `username` yang tersedia, privilege dan metode secret secara terbatas; jangan ekspor nilai secret/hash. |
| AAA dan akses manajemen | `show running-config` dengan aturan yang sama | Konfigurasi AAA authentication/authorization/accounting, VTY, transport, access-class, SSH dan sumber AAA terkait jika tersedia. Urutan dan penggunaan method list harus dipertahankan. |
| Sesi akses saat pengambilan | `show users`, `show ssh` | Sesi yang terlihat saat snapshot; bukan histori akses lengkap. |
| Informasi privilege saat ini | `show privilege` | Privilege sesi pengumpulan, bukan privilege semua pengguna. |
| Status SSH | `show ip ssh` | Versi/status SSH dan parameter yang tersedia. |

Rincian allowlist final dan varian command harus melalui pengujian kompatibilitas. Tidak boleh ada fallback ke perintah konfigurasi atau command bebas saat sebuah command gagal. `show running-config` dapat memuat password, hash, community, key, sertifikat, dan data sensitif lain: utamakan filter sisi perangkat yang kompatibel, tetapi jangan menganggap filter cukup untuk keamanan. Terapkan parser dan redaksi lokal sebelum data disimpan, ditampilkan, atau diekspor; raw output tidak disimpan secara default. Jangan ekspor nilai secret, hash password, shared secret, SNMP community, private key, token, atau materi kredensial lain. Jika redaksi tidak yakin, sembunyikan seluruh baris/blok terkait dan tandai bukti sebagai direduksi; jangan mengeluarkan data mentah. Hindari mencatat respons SSH mentah dalam log atau pesan error.

### 5.2 Evaluasi awal untuk auditor

Buat satu hasil per kontrol dan per perangkat dengan **Pass / Fail / Needs Review / Not Available**. Pass/Fail hanya berlaku jika ada aturan eksplisit dan bukti yang cukup; jika tidak, gunakan Needs Review atau Not Available. Default penilaian harus konservatif dan aturan, versi, serta asumsi dicantumkan. Contoh:

- **Akun lokal:** identifikasi nama akun dan privilege yang terlihat; status aktif, pemilik, kebutuhan bisnis, dan tanggal review tidak dapat disimpulkan dari konfigurasi saja → Needs Review.
- **Remote management:** evaluasi apakah konfigurasi VTY yang relevan membatasi transport ke SSH jika seluruh line dan konfigurasi terkait terbaca; jika data parsial atau ambigu → Needs Review/Not Available. Jangan menyimpulkan seluruh jalur manajemen aman hanya dari VTY.
- **AAA:** tampilkan method list, penerapannya pada line jika dapat ditentukan, dan fallback yang terlihat. Penilaian kesesuaian dengan kebijakan organisasi memerlukan review; konfigurasi perangkat tidak membuktikan efektivitas server AAA atau daftar pengguna di server.
- **Pembatasan sumber:** identifikasi access-class pada VTY dan ACL terkait bila berhasil dikumpulkan; jika definisi ACL, penerapan, atau cakupan tidak lengkap, jangan menyatakan akses aman. Tambahkan `show access-lists` ke allowlist hanya setelah redaksi dan kompatibilitas diuji.
- **Logging/accounting:** catat konfigurasi yang terlihat; jangan mengklaim log diterima atau direview tanpa bukti eksternal.
- **Sesi saat ini dan SSH:** tampilkan fakta yang berhasil dikumpulkan dan waktu snapshot; kebijakan serta kebutuhan pemeriksaan lanjutan ditentukan auditor.

Untuk masing-masing kontrol sediakan deskripsi, kriteria atau alasan review, hasil, bukti yang sudah disanitasi, sumber perintah/rujukan baris bukti, timestamp, dan keterbatasan. Auditor dapat mengisi kolom keputusan akhir, owner, komentar, dan tanggal review di Excel. Data yang tidak terkumpul tidak boleh dianggap aman atau compliant.

## 6. Keamanan dan batas read-only

- **Enforcement berlapis:** aplikasi hanya menerima perintah dari allowlist hard-coded/versioned, tanpa custom command, mode konfigurasi, SCP/SFTP, atau kemampuan push. Uji semua jalur eksekusi SSH dan payload UI/CSV terhadap allowlist. Gunakan akun perangkat dengan privilege read-only dan AAA command authorization yang membatasi command sebagai kontrol independen; hak akses aplikasi tidak bisa menggantikan kebijakan perangkat.
- **SSH host key:** verifikasi terhadap known_hosts lokal yang dipercaya. Host key baru/berubah tidak diterima otomatis. Tampilkan fingerprint, tipe key, dan target; pengguna memverifikasi fingerprint melalui kanal tepercaya dan secara eksplisit menyetujui key baru untuk disimpan. Key berubah harus diblokir dan diselesaikan melalui pembaruan trust yang disengaja setelah verifikasi; tidak ada opsi bypass global. Jika belum disetujui, target gagal dengan alasan jelas.
- **Kredensial:** password masked di UI, hanya di memori selama diperlukan, tidak disimpan dalam konfigurasi, log, workbook, URL, telemetry, ataupun error. Jangan mengklaim penghapusan memori sempurna di Python. Jangan otomatis retry password berulang agar tidak memicu lockout; default satu percobaan autentikasi per target per run.
- **Lokal:** bind UI hanya ke loopback, gunakan port dinamis atau yang dapat dikonfigurasi, proteksi akses sesi/CSRF bila UI HTTP, batasi origin, dan hindari CDN atau layanan eksternal. Tidak ada telemetry atau pengiriman data ke luar; koneksi keluar hanya SSH ke target yang dipilih.
- **Output:** simpan hanya setelah pengguna memilih lokasi; file berisi data audit sensitif dan hak akses file mengikuti OS. Jangan mengklaim XLSX terenkripsi. Tampilkan anjuran menyimpan pada lokasi yang aksesnya dibatasi sesuai kebijakan organisasi. Escape nilai yang diawali `=`, `+`, `-`, atau `@` dan karakter kontrol relevan agar teks dari perangkat tidak dieksekusi sebagai formula Excel. Semua evidence diperlakukan sebagai data tidak tepercaya.
- **Log:** catat timestamp, endpoint, tahapan, status, durasi, dan kategori error yang sudah disanitasi; tidak mencatat password, raw output, atau secret. Retensi file log default tidak permanen; jika ekspor log disediakan, harus eksplisit dan disanitasi.

## 7. Desain workbook Excel

Satu workbook per run; nama default `Cisco_Access_Review_YYYYMMDD_HHMMSS.xlsx`. Format konsisten, judul dan header jelas, filter, freeze header, lebar kolom dan wrap text sesuai kebutuhan, warna status dengan label teks, serta timestamp dan timezone yang konsisten. Jangan mengandalkan warna sebagai satu-satunya penanda.

| Sheet | Isi minimum |
|---|---|
| **Run Summary** | Run ID, waktu mulai/selesai dan timezone, versi tool, jumlah target per status, keterbatasan serta legenda status. |
| **Device Inventory** | IP/port, hostname, model, versi OS, serial jika ada, waktu koleksi, status, error aman, dan indikator kelengkapan. |
| **Control Results** | Device ID, control ID/nama, kriteria, status, observasi, evidence ID, sumber command, waktu, keterbatasan, serta kolom keputusan auditor, owner, komentar, dan tanggal review. |
| **Local Accounts** | Device ID, username, privilege/metode autentikasi yang terlihat tanpa secret, evidence ID, dan kolom review owner/status bisnis. |
| **AAA & Management** | Device ID, jenis setting, nilai yang disanitasi, konteks/penerapan, evidence ID, dan keterbatasan. |
| **Evidence** | Evidence ID unik, device ID, command yang disetujui, waktu, kutipan yang disanitasi dengan konteks yang cukup, status lengkap/parsial/reduksi. |
| **Collection Issues** | Device ID, tahapan/command, kategori, alasan aman, dampak pada cakupan dan rekomendasi tindak lanjut. |

Pisahkan data dan bukti antar perangkat; gunakan ID konsisten agar setiap hasil dapat ditelusuri. Jika output terpotong, command tidak didukung, hak tidak cukup, atau parsing gagal, cantumkan secara eksplisit. Batasi ukuran sel dan workbook secara aman; jika bukti dipotong karena batas Excel, tandai sebagai truncated dan jangan menyatakan bukti lengkap.

## 8. Kompatibilitas, batasan, dan error

- Deteksi OS/model/versi berdasarkan output identitas yang tersedia; simpan nilai sebenarnya dan tandai unknown jika tidak dapat dipastikan. Jangan menjanjikan dukungan semua model atau future release.
- Catat matriks model, OS, versi, metode autentikasi, perintah, hasil, dan tanggal uji. Fixture berguna untuk regresi tetapi tidak menggantikan uji perangkat nyata.
- Bedakan timeout, unreachable, host key unknown/changed, authentication failed, insufficient privilege, unsupported command, parse error, output truncated, dan cancellation. Perangkat lain tetap diproses ketika satu target gagal.
- SSH legacy pada perangkat lama mungkin membutuhkan algoritma lemah yang tidak didukung library/OS. Default gunakan konfigurasi SSH aman; jangan otomatis menurunkan keamanan. Jika tidak dapat terhubung, jelaskan keterbatasan secara spesifik. Dukungan legacy opsional memerlukan desain dan persetujuan terpisah.
- Output dapat berbeda karena privilege, locale, konfigurasi, stack, dan versi. Nilai tidak dikenal ditandai unknown, bukan ditebak. Snapshot hanya menggambarkan waktu pengumpulan dan bukan bukti menyeluruh atas hak akses efektif.

## 9. Kebutuhan nonfungsional

- **Reliability:** kegagalan satu perangkat tidak menghentikan run; timeout, batas output, antrean, dan cancellation mencegah proses menggantung.
- **Performance:** default concurrency konservatif, misalnya 5 perangkat, dapat diubah dalam batas aman; target performa ditentukan setelah benchmark pada jaringan dan perangkat yang disetujui.
- **Usability:** pesan dapat ditindaklanjuti, password masked, validasi per baris, progress terlihat, dan dapat digunakan tanpa keahlian CLI.
- **Maintainability:** modul UI, validasi, SSH/allowlist, parser, redaksi, evaluasi, dan XLSX terpisah di belakang satu entry point. Aturan evaluasi dan versi tool tercatat di workbook.
- **Portabilitas:** target OS dan versi Python ditentukan dan diuji saat implementasi; sertakan petunjuk instalasi offline bila dependensi telah disiapkan.

## 10. Rancangan teknis tingkat tinggi

UI lokal → validator input dan penyimpanan kredensial sementara di memori → antrean worker terbatas → SSH dengan verifikasi host key dan allowlist → redaksi → parser/evaluator → generator XLSX. Data mentah dibatasi di memori selama pemrosesan; hanya hasil yang telah disanitasi diteruskan ke UI, log, dan workbook. Pisahkan status transport, keberhasilan command, kelengkapan bukti, dan hasil kontrol agar kegagalan koleksi tidak berubah menjadi Pass.

## 11. Tahapan implementasi

1. Tetapkan matriks perangkat dan aturan kontrol bersama auditor/network owner; siapkan fixture yang disanitasi dan lingkungan uji berwenang.
2. Bangun SSH read-only, validasi host key, allowlist, timeout, redaksi, serta penanganan error.
3. Bangun UI single/bulk dan progress/cancellation.
4. Bangun parser, evaluasi konservatif, workbook, dan dokumentasi operasional.
5. Uji keamanan, kompatibilitas, ketertelusuran hasil, dan user acceptance; catat keterbatasan sebelum rilis.

## 12. Kriteria penerimaan

1. Pengguna dapat menjalankan single, bulk shared, dan bulk per-device dari UI; validasi kesalahan menunjukkan baris terkait tanpa membocorkan password.
2. Tes transport membuktikan seluruh command yang dikirim hanya berasal dari allowlist; input berbahaya dan output perangkat tidak dapat menjadi command. Tidak ada jalur perubahan konfigurasi, file transfer, atau command bebas.
3. Unknown host key memerlukan verifikasi dan persetujuan eksplisit; changed key diblokir. Password salah tidak dicoba berulang otomatis. Kredensial/secret uji tidak muncul di UI hasil, log, workbook, konfigurasi, atau file sementara yang dibuat tool.
4. Workbook berhasil dibuka di Excel, memiliki semua sheet yang disebutkan, status terbaca tanpa warna, serta setiap hasil kontrol merujuk bukti yang disanitasi atau menjelaskan bukti tidak tersedia. Payload formula uji diperlakukan sebagai teks.
5. Command unsupported, privilege kurang, timeout, output terpotong, parsing gagal, dan cancellation menghasilkan status serta keterbatasan yang akurat; tidak menghasilkan Pass tanpa bukti cukup. Kegagalan satu target tidak menghentikan target lain.
6. Uji dengan fixture dan minimal satu perangkat/lab IOS 12.x serta satu IOS XE yang disetujui mencatat model, versi dan hasil di matriks. Rilis menyebutkan bagian yang belum diuji, termasuk versi terbaru saat rilis bila belum tersedia.
7. Workbook tidak berisi secret/hash atau raw configuration. Kasus redaksi yang tidak pasti menyembunyikan bagian terkait dan mencatat reduksi bukti.
8. Operator dapat membatalkan run dan mengekspor hasil parsial yang diberi label; file hasil hanya dibuat di lokasi yang dipilih.

## 13. Keputusan yang perlu disepakati sebelum implementasi

- Daftar model dan versi nyata, OS workstation, dan jumlah target tipikal; ini menentukan matriks kompatibilitas serta batas concurrency.
- Kebijakan audit organisasi untuk menetapkan aturan Pass/Fail, kriteria privilege, AAA, akses VTY, dan retensi output.
- Metode verifikasi host key dan lokasi known_hosts yang disetujui organisasi.
- Apakah penggunaan SSH legacy diperlukan; jika ya, tentukan perangkat, risiko, dan mekanisme persetujuan terpisah.
- Apakah field tambahan, format workbook, atau bukti dari sistem AAA eksternal diperlukan pada fase berikutnya.
