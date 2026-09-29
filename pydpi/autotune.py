"""Calisan stratejiyi otomatik bulur: sirayla dener, gercek TLS baglantisi ile test eder."""
import socket
import ssl

from .config import load_profile, save_profile


def _s(**kw):
    base = dict(mode="sni", frag=2, fake_ttl=0, auto_ttl=False, fake_badsum=False, fake_badseq=False)
    base.update(kw)
    return base


STRATEGIES = [
    _s(fake_ttl=5),
    _s(auto_ttl=True),
    _s(fake_badseq=True, fake_badsum=True),
    *[_s(fake_ttl=t) for t in (3, 4, 6, 7, 8, 2)],
    _s(fake_badsum=True),
    _s(fake_badseq=True),
    _s(),
    *[_s(mode="fixed", frag=f) for f in (1, 2, 4)],
    *[_s(mode="fixed", frag=2, fake_ttl=t) for t in (5, 3, 7)],
]


def test_connect(host, timeout=3.0):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except Exception:
        return False


def _label(s):
    fake = []
    if s["fake_ttl"]:
        fake.append(f"ttl={s['fake_ttl']}")
    if s["auto_ttl"]:
        fake.append("auto-ttl")
    if s["fake_badsum"]:
        fake.append("badsum")
    if s["fake_badseq"]:
        fake.append("badseq")
    return f"{s['mode']:5} frag={s['frag']} sahte=[{', '.join(fake) or '-'}]"


def autotune(cfg, hosts, log=print, tester=test_connect):
    """Uygun stratejiyi bulup cfg'ye uygular. Bulunamazsa False doner."""
    log(f"[*] Otomatik ayar basladi (test: {', '.join(hosts)})")
    cached = load_profile()
    candidates = ([cached] if cached else []) + [s for s in STRATEGIES if s != cached]
    for strat in candidates:
        cfg.apply(strat)
        ok = all(tester(h) and tester(h) for h in hosts)   # her site 2 kez gecmeli
        log(f"    {_label(strat)} -> {'CALISIYOR' if ok else 'olmadi'}")
        if ok:
            save_profile(strat)
            log("[+] Ayar bulundu ve kaydedildi.")
            return True
    cfg.apply(STRATEGIES[0])
    log("[-] Hicbir ayar calismadi. DNS/IP engeli olabilir; --test-host'u kontrol et.")
    return False
