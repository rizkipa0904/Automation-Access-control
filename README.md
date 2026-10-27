# Network Access Review

Tool lokal berbasis browser untuk mempercepat pengumpulan dan review informasi akses administratif pada **Cisco switch IOS / IOS XE** dan **Palo Alto Networks firewall PAN-OS**. Pilih platform, masukkan satu atau banyak IP beserta kredensial, lalu unduh hasil scan sebagai Excel.

Aplikasi menggunakan SSH dan hanya mengirim perintah baca yang tercantum dalam daftar tetap di bawah. Tidak ada fitur untuk mengirim perintah bebas, mengubah konfigurasi, atau mentransfer file. Gunakan akun dengan hak read-only dan pembatasan command di perangkat sebagai kontrol tambahan.

> **Status validasi:** kompatibilitas belum diuji pada semua model dan versi; belum ada jaminan dukungan semua versi PAN-OS, IOS, maupun IOS XE. Perbedaan privilege, format output, prompt dan algoritma SSH dapat menyebabkan hasil parsial. Uji pada lab dan perangkat yang relevan sebelum penggunaan produksi.

## Persiapan

- Linux atau macOS, Python **3.10+** dengan modul `venv` dan `pip`, Git, browser, dan jaringan SSH ke perangkat yang diotorisasi.
- Akun perangkat **read-only** dengan akses ke perintah yang dibutuhkan. Untuk PAN-OS, periksa bahwa peran read-only yang dipilih memiliki akses ke command yang tercantum; untuk Cisco batasi juga melalui AAA command authorization. Hak kurang dapat menghasilkan output parsial tanpa selalu menampilkan error.
- Fingerprint host key dari sumber yang dipercaya dan terpisah, untuk setiap perangkat.
- Akses ke Python package index untuk instalasi awal, atau dependensi dalam wheel yang telah disiapkan administrator dan dikonfigurasi melalui mekanisme pip. Aplikasi tidak memerlukan layanan cloud dan tidak mengirim telemetry.

## Instalasi dan menjalankan

Clone repositori setelah dipublikasikan. Ganti placeholder dengan URL dan nama direktori sebenarnya:

```bash
git clone <URL-REPOSITORI>
cd <NAMA-DIREKTORI>
python3 start.py
```

Pada peluncuran pertama, command membuat `.venv` dan memasang dependensi; berikutnya command yang sama menjalankan aplikasi. Terminal menampilkan URL seperti `http://127.0.0.1:54321/` dengan port aktual yang dipilih otomatis. Jika browser tidak terbuka, buka URL yang ditampilkan pada **komputer yang sama**. Biarkan terminal terbuka dan tekan **Ctrl+C** saat selesai. Aplikasi hanya listen di loopback dan tidak dirancang sebagai server bersama.

## Cara menjalankan scan

1. Pada **Workspace proyek**, masukkan nama perusahaan/proyek dan klik **Buat proyek**, atau pilih proyek yang sudah ada. Satu proyek dapat berisi beberapa scan Cisco dan Palo Alto. Untuk scan perusahaan lain, buat atau pilih proyek lain; scan sebelumnya tetap berjalan.
2. Pilih **Cisco Switch · IOS / IOS XE** atau **Palo Alto Firewall · PAN-OS**. Semua target dalam satu run harus menggunakan platform yang dipilih; jalankan platform berbeda dalam run terpisah.
3. Pilih **Bulk · kredensial sama** untuk satu atau banyak perangkat dengan username/password yang sama. Masukkan satu IP per baris. Port opsional menggunakan format `IP,port`:

   ```text
   192.0.2.10
   192.0.2.11,2222
   2001:db8::10,22
   ```

   Contoh di atas adalah alamat dokumentasi. Port default `22`; IPv4 dan IPv6 tanpa scope ID didukung. Hostname tidak didukung.
4. Untuk kredensial berbeda, pilih **Bulk · kredensial berbeda**, isi tabel, atau gunakan **Unduh template** dan **Impor CSV**. Formatnya harus berurutan `ip,port,username,password`; port kosong berarti `22`. Unduh contoh dari tombol di aplikasi atau dari [devices-sample.csv](examples/devices-sample.csv), lalu ganti semua nilai contoh:

   ```csv
   ip,port,username,password
   192.0.2.10,22,auditor1,CONTOH_PASSWORD_1
   192.0.2.11,,auditor2,CONTOH_PASSWORD_2
   ```

   Password CSV berupa plaintext. Batasi akses ke file, jangan commit ke Git, dan hapus sesuai kebijakan setelah digunakan. Maksimum 1 MB per CSV, 200 target per scan, tanpa batas jumlah scan aktif yang ditetapkan aplikasi, dan 5 koneksi SSH bersamaan secara keseluruhan. Jumlah scan yang dapat ditangani tetap bergantung pada kapasitas komputer dan penyimpanan. Target di atas batas koneksi menunggu dalam antrean. IP dan port yang sama tidak boleh duplikat.
5. Untuk Cisco lawas yang memerlukannya, opsi **Kompatibilitas SSH lawas** dapat diaktifkan secara eksplisit. Opsi ini mengizinkan algoritma SSHv2 yang lebih lemah jika masih tersedia dalam library, berlaku untuk seluruh target dalam run, dan tidak menjamin dukungan semua perangkat lawas atau SSHv1. Gunakan hanya pada perangkat dan jaringan tepercaya sesuai kebijakan. Untuk Palo Alto opsi ini tidak tersedia.
6. Klik **Mulai review**. Jika status `host_key_unknown`, cocokkan tipe dan fingerprint dengan sumber tepercaya; hanya jika cocok, klik **Saya sudah memverifikasi fingerprint ini**. Lalu jalankan kembali target yang memerlukan koneksi. Daftar di form dijalankan ulang seluruhnya, jadi ubah daftar jika hanya sebagian target perlu diulang. Host key yang disetujui pada UI berlaku selama proses aplikasi berjalan. Key yang berubah dari `known_hosts` diblokir dan perlu diselesaikan melalui prosedur organisasi.
7. Tunggu hasil selesai. **Batalkan** menghentikan pekerjaan yang memungkinkan, melewati target dalam antrean dan menyediakan hasil parsial setelah worker selesai. Koneksi yang sedang menunggu dapat membutuhkan waktu hingga timeout. Satu autentikasi dilakukan per target per run; menjalankan ulang merupakan percobaan baru dan dapat memengaruhi lockout.
8. Klik **Unduh Excel**. File `Access_Review_<ID>.xlsx` disimpan melalui browser. Nama proyek dan hasil yang sudah disaring disimpan otomatis di `.access-review-data/projects.json` agar tersedia kembali setelah restart. Host key yang disetujui pada UI tidak dipertahankan; scan yang masih berjalan saat aplikasi berhenti ditandai terhenti dan tidak dilanjutkan otomatis. Klik **Bersihkan kredensial** setelah selesai.

### Live view dan beberapa scan

Pada **Workspace proyek**, pilih proyek lalu pilih salah satu scan untuk melihat daftar IP dan statusnya. Klik sebuah perangkat untuk membuka preview bukti yang sudah disaring, command yang sedang berjalan, dan masalah yang terdeteksi. Preview diperbarui saat pengumpulan berlangsung, bukan tampilan terminal mentah. Scan aktif terbaru otomatis dibuka ketika proyek dipilih; scan lain tetap berjalan ketika Anda berpindah proyek atau scan. Input target, platform dan kredensial dibersihkan ketika berpindah proyek agar data antarperusahaan tidak tertukar. Tombol **Batalkan** dan **Unduh Excel** berlaku untuk scan yang sedang dipilih.

Status perangkat mencakup antre, menghubungkan SSH, SSH terhubung dan review berlangsung, selesai, hasil parsial, gagal, verifikasi host key, dibatalkan, serta terhenti akibat restart. `Selesai` tidak menjamin seluruh informasi akses tersedia. Persetujuan host key pada UI terpisah antarproyek; selalu cocokkan fingerprint sebelum menyetujui.

Data proyek disimpan di `.access-review-data/` pada direktori aplikasi dengan hak akses direktori `0700` dan file `0600` pada Linux/macOS. Data tersebut dapat memuat nama pengguna, IP dan konfigurasi yang disaring: lindungi direktori dan cadangannya sesuai kebijakan. Password, raw output, dan key SSH tidak disimpan dalam data proyek; fingerprint dan hasil yang telah disaring dapat tersimpan. Hanya satu instance aplikasi dapat memakai direktori data yang sama. Jika ada peringatan penyimpanan, hasil terbaru mungkin hilang. Penyimpanan diperbarui selama scan; storage yang lambat atau riwayat yang besar dapat menambah latensi. Direktori tersebut dikecualikan dari Git; jangan commit atau bagikan data proyek secara tidak sengaja.

## Perintah dan cakupan pengumpulan

| Platform | Perintah tetap | Informasi yang dicari |
| --- | --- | --- |
| Cisco IOS / IOS XE | `show version`, `show inventory`, `show privilege`, `show ip ssh`, `show users`, `show ssh`, `show running-config` | Identitas, akun lokal dan privilege, field AAA, VTY, access-class, status SSH, dan field manajemen yang berhasil diekstrak. Output sesi tidak diekspor. |
| Palo Alto PAN-OS | `show system info`, `show admins all`, `show config running` | Identitas, administrator yang diketahui perangkat, serta field konfigurasi administrator dan password complexity yang berhasil diekstrak. |

Output konfigurasi lengkap dibaca sementara dalam memori, lalu disaring sebelum disimpan atau diekspor. Nilai secret dan hash tidak sengaja dimasukkan ke hasil. Jika format, privilege, ukuran output atau prompt tidak didukung, bagian yang gagal ditandai pada **Collection Issues**; tidak ada fallback ke mode konfigurasi atau perintah bebas. Pagination ditangani dengan spasi pada sesi SSH.

`show admins all` bukan daftar sesi aktif dan tidak menjamin semua entitlement pada sistem identitas eksternal. PAN-OS XML dan bentuk output berbeda antar versi; konfigurasi yang tidak dapat diparse ditandai tidak tersedia. Pada Cisco, output `show running-config` dapat terbatas oleh privilege tanpa error. Field kosong tidak membuktikan akun, pengaturan, atau akses tidak ada. Definisi ACL lengkap, akun server AAA eksternal dan akses efektif tidak dicakup secara menyeluruh.

## Hasil Excel

Workbook adalah snapshot dari data yang dapat dikumpulkan dan disanitasi pada waktu scan; bukan bukti otomatis bahwa kontrol memenuhi kebijakan organisasi. Waktu dicatat dalam UTC. File tidak terenkripsi dan berisi informasi sensitif; simpan di lokasi yang aksesnya dibatasi.

| Sheet | Isi |
| --- | --- |
| **Run Summary** | Platform, ID run, waktu, profil SSH, jumlah target dan status koleksi. |
| **Device Inventory** | Identitas yang berhasil diekstrak, IP, status perangkat dan keterbatasan. |
| **Scan Results** | Hasil pemeriksaan berdasarkan data yang tersedia, nilai yang teramati, sumber command dan Evidence ID. |
| **Accounts** | Akun/administrator dan privilege atau role yang berhasil diekstrak, dengan sumber bukti untuk akun dan role. |
| **Access Configuration** | Field konfigurasi akses yang disanitasi beserta sumber dan batasannya. |
| **Evidence** | Kutipan yang disanitasi, sumber command, timestamp dan ID bukti untuk penelusuran. |
| **Collection Issues** | Command atau tahapan yang gagal dan dampak terhadap kelengkapan data. |

Di **Scan Results**, `Observed` berarti ada data yang berhasil diekstrak; `Attention` menunjukkan kondisi tertentu yang terlihat dan perlu perhatian; `Not Available` berarti informasi tidak dapat diekstrak. Status tersebut bukan kesimpulan Pass/Fail atau jaminan kelengkapan. `completed` pada perangkat berarti perintah selesai tanpa error yang terdeteksi, bukan semua akses berhasil diidentifikasi.

## Keamanan dan troubleshooting

- Kredensial diproses lokal dan tidak sengaja disimpan di konfigurasi, log atau workbook. CSV sumber, memori proses/browser dan workbook tetap harus dilindungi; Python tidak menjamin penghapusan memori sempurna. Jalankan hanya pada akun OS dan host yang dipercaya, karena proses lain pada host yang sama dapat mengakses UI lokal.
- **Instalasi gagal:** periksa Python/venv, hak tulis direktori proyek dan akses package index atau konfigurasi wheel offline. Jalankan ulang `python3 start.py` setelah masalah diperbaiki.
- **Browser tidak terbuka:** salin URL aktual dari terminal ke browser pada host yang sama.
- **Host key berubah:** verifikasi melalui kanal tepercaya dan ikuti prosedur pembaruan `known_hosts`; jangan bypass verifikasi.
- **Autentikasi gagal:** periksa kredensial dan AAA; hindari pengulangan yang dapat memicu lockout.
- **Gagal atau parsial:** periksa platform, rute, port, SSH, privilege, kompatibilitas versi dan sheet **Collection Issues**. Ketiadaan data tidak boleh dianggap hasil aman.

## Pengujian dan referensi

Setelah dependensi terpasang, jalankan `.venv/bin/python -m unittest discover -s tests -v`. Sebelum penggunaan produksi, validasi alur penuh dengan akun read-only dan perangkat/lab yang diotorisasi pada model, versi, privilege dan format output yang digunakan organisasi, termasuk host key, autentikasi gagal, pagination, output parsial dan hasil Excel. Pengujian fixture tidak menggantikan pengujian perangkat nyata.

Dokumentasi vendor untuk memahami cakupan: [Palo Alto CLI device management](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-device-management), [Palo Alto CLI administrator roles](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/get-started-with-the-cli/give-administrators-access-to-the-cli), dan [Cisco output running configuration untuk privilege rendah](https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/212149-Configure-IOS-XE-to-display-full-show-ru.html).
