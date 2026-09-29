# pydpi

Windows için Python + [WinDivert](https://reqrypt.org/windivert.html) tabanlı, [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) benzeri bir DPI (Deep Packet Inspection) atlatma aracı. Öğrenme ve deney amaçlı yazılmıştır.

## Özellikler

- **TLS ClientHello parçalama:** SNI'nın ortasından bölünür
- **Sahte paket:** düşük TTL / otomatik TTL / bozuk checksum / bozuk seq
- **HTTP hileleri:** `hoSt`, karışık harf, boşluk silme, ek boşluk
- **DNS yönlendirme** (IPv4 + IPv6), varsayılan Yandex DNS `77.88.8.8:1253`
- **Pasif DPI engelleme:** ISP'nin enjekte ettiği RST ve yönlendirme paketlerini düşürür
- **QUIC engelleme:** tarayıcıyı TCP'ye döndürür
- **`--auto`:** farklı stratejileri sırayla dener, çalışanı bulup kaydeder
- **Otomatik başlatma:** Görev Zamanlayıcı ile oturum açılışında

## Kullanım

Yönetici olarak çalıştır:

```
pydpi.exe --auto
```

Bulunan ayar `%APPDATA%\pydpi\profile.json` dosyasına kaydedilir; sonraki açılışta önce o denenir. Ağ/ISP değişirse dosyayı sil.

| Seçenek | Açıklama |
|---|---|
| `--auto` | Çalışan ayarı otomatik bul |
| `--test-host H [H ...]` | `--auto` için test siteleri (varsayılan `discord.com`) |
| `--mode sni\|fixed` | SNI/Host içinden bol ya da `--frag` baytından bol |
| `--frag N` | Sabit bölme noktası |
| `--ttl N` / `--auto-ttl` | Sahte paket TTL'i / sunucu uzaklığına göre otomatik |
| `--wrong-chksum` / `--wrong-seq` | Sahte pakette bozuk checksum / seq |
| `--no-host-replace`, `--host-mixcase`, `--host-remove-space`, `--extra-space` | HTTP hileleri |
| `--no-dns`, `--dns`, `--dns6`, `--no-dns6`, `--dns-port` | DNS yönlendirme |
| `--no-passive`, `--allow-quic` | Pasif DPI / QUIC engellemeyi kapat |
| `--install-task` / `--remove-task` | Oturum açılışında otomatik başlat / kaldır |
| `-v` | Ayrıntılı çıktı |

`--auto` verdiysen elle girilen parçalama/sahte paket ayarlarının üzerine yazılır.

## Kaynaktan çalıştırma

```
pip install -r requirements.txt
python main.py --auto
```

Testler (Windows gerekmez): `python -m unittest discover -s tests`

## EXE üretme

```
build.bat
```

`dist\pydpi.exe` oluşur (yönetici izni ister).

## Notlar

- DNS sorguları Yandex'e gider. Gizlilik açısından bunu bilerek kullan; `--dns` ile değiştirebilirsin (ISP'ler genelde 53 dışı porta karışmıyor, o yüzden Yandex:1253 tercih edilir).
- Tarayıcıda "Güvenli DNS/DoH" açıksa DNS yönlendirme devre dışı kalır, tarayıcı zaten kendi yolunu kullanır.
- Sesli kanallar (UDP) bu aracın kapsamında değildir.
- Sadece o bilgisayarı etkiler; modem/router seviyesinde çalışmaz.
- Antivirüsler WinDivert sürücüsünü (ve PyInstaller çıktılarını) yanlışlıkla işaretleyebilir.
- Pasif DPI engelleme yalnızca IP ID değeri 1–15 olan paketleri düşürür (0 hariç); böylece IP ID'si 0 olan normal Linux sunucularının cevapları etkilenmez.
- **Lisans:** WinDivert ve pydivert kendi lisanslarına (LGPL/GPL) tabidir. Exe'yi dağıtırken bunlara uy. Projenin kendi lisansını sen seç.

## Teşekkür

Fikir ve teknikler GoodbyeDPI (ValdikSS), zapret ve SpoofDPI projelerinden esinlenmiştir.
