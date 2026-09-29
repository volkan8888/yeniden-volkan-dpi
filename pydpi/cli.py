import argparse
import ctypes
import sys
import time

from . import __version__, tasks
from .autotune import autotune
from .config import Config


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse(argv=None):
    ap = argparse.ArgumentParser(prog="pydpi", description="WinDivert tabanli DPI atlatma araci")
    ap.add_argument("--auto", action="store_true", help="calisan ayari otomatik bul (onerilen)")
    ap.add_argument("--test-host", nargs="+", default=["discord.com"], metavar="HOST",
                    help="--auto icin test edilecek engelli siteler")
    g = ap.add_argument_group("parcalama / sahte paket")
    g.add_argument("--mode", choices=["sni", "fixed"], default="sni")
    g.add_argument("--frag", type=int, default=2, help="sabit bolme noktasi (bayt)")
    g.add_argument("--ttl", type=int, default=5, help="sahte paket TTL (0 = kapali)")
    g.add_argument("--auto-ttl", action="store_true", help="TTL'i sunucu uzakligina gore sec")
    g.add_argument("--wrong-chksum", action="store_true", help="sahte paketin checksum'u bozuk")
    g.add_argument("--wrong-seq", action="store_true", help="sahte paketin seq'i bozuk")
    h = ap.add_argument_group("HTTP")
    h.add_argument("--no-host-replace", action="store_true", help="Host -> hoSt yapma")
    h.add_argument("--host-mixcase", action="store_true")
    h.add_argument("--host-remove-space", action="store_true")
    h.add_argument("--extra-space", action="store_true")
    d = ap.add_argument_group("DNS")
    d.add_argument("--no-dns", action="store_true", help="DNS yonlendirmeyi kapat")
    d.add_argument("--dns", default="77.88.8.8")
    d.add_argument("--dns6", default="2a02:6b8::feed:0ff")
    d.add_argument("--no-dns6", action="store_true", help="IPv6 DNS yonlendirmeyi kapat")
    d.add_argument("--dns-port", type=int, default=1253)
    o = ap.add_argument_group("diger")
    o.add_argument("--no-passive", action="store_true", help="pasif DPI engellemeyi kapat")
    o.add_argument("--allow-quic", action="store_true", help="QUIC'i engelleme")
    o.add_argument("--install-task", action="store_true", help="oturum acilisinda otomatik baslat")
    o.add_argument("--remove-task", action="store_true")
    o.add_argument("-v", "--verbose", action="store_true")
    o.add_argument("--version", action="version", version=__version__)
    return ap.parse_args(argv)


def build_config(a) -> Config:
    return Config(
        mode=a.mode, frag=a.frag, fake_ttl=a.ttl, auto_ttl=a.auto_ttl,
        fake_badsum=a.wrong_chksum, fake_badseq=a.wrong_seq,
        host_replace=not a.no_host_replace, host_mixcase=a.host_mixcase,
        host_remove_space=a.host_remove_space, extra_space=a.extra_space,
        dns=not a.no_dns, dns4=a.dns, dns6="" if a.no_dns6 else a.dns6, dns_port=a.dns_port,
        passive_block=not a.no_passive, block_quic=not a.allow_quic, verbose=a.verbose)


def main(argv=None) -> int:
    a = parse(argv)
    if a.install_task:
        return tasks.install()
    if a.remove_task:
        return tasks.remove()
    if sys.platform != "win32":
        print("pydpi sadece Windows'ta calisir (WinDivert).")
        return 1
    if not is_admin():
        print("[!] Yonetici olarak calistirmalisin.")
        _pause()
        return 1

    from .engine import Engine          # pydivert sadece burada yuklenir
    cfg = build_config(a)
    eng = Engine(cfg, need_hops=a.auto or cfg.auto_ttl)
    try:
        eng.start()
    except Exception as e:
        print(f"[!] WinDivert baslatilamadi: {e}")
        print("    (Yonetici misin? Antivirus surucuyu engelliyor olabilir mi?)")
        _pause()
        return 1

    print(f"[*] pydpi {__version__} basladi. Durdurmak icin Ctrl+C")
    try:
        if a.auto:
            autotune(cfg, a.test_host)
        while eng.alive():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        eng.stop()
    return 0


def _pause():
    if getattr(sys, "frozen", False):
        try:
            input("Kapatmak icin Enter...")
        except EOFError:
            pass
