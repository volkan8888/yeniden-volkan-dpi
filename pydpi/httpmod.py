"""HTTP istegi ayristirma ve DPI'i sasirtan degisiklikler (saf Python)."""

METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
_FILL = b"www.w3.org"


def is_http_request(p: bytes) -> bool:
    return p.startswith(METHODS)


def _locate(p: bytes):
    """(baslik_adi_baslangic, deger_baslangic, deger_bitis) dondurur."""
    i = p[:4096].lower().find(b"\r\nhost:")
    if i < 0:
        return None
    name = i + 2
    v = name + 5
    while v < len(p) and p[v:v + 1] in (b" ", b"\t"):
        v += 1
    e = p.find(b"\r\n", v)
    return name, v, (len(p) if e < 0 else e)


def find_host(p: bytes):
    """Host degerinin (baslangic, uzunluk) degerini dondurur."""
    loc = _locate(p)
    return (loc[1], loc[2] - loc[1]) if loc else None


def make_fake(p: bytes, off: int, ln: int) -> bytes:
    filler = (_FILL * (ln // len(_FILL) + 1))[:ln]
    return p[:off] + filler + p[off + ln:]


def mutate(p: bytes, cfg) -> bytes:
    if cfg.extra_space:
        p = p.replace(b" ", b"  ", 1)
    loc = _locate(p)
    if not loc:
        return p
    name, v, e = loc
    host = p[v:e]
    if cfg.host_mixcase:
        host = bytes(((c - 32) if (i & 1 and 97 <= c <= 122) else (c + 32) if (not i & 1 and 65 <= c <= 90) else c)
                     for i, c in enumerate(host))
    ws = b"" if cfg.host_remove_space else p[name + 5:v]
    label = b"hoSt" if cfg.host_replace else p[name:name + 4]
    return p[:name] + label + b":" + ws + host + p[e:]
