"""TLS ClientHello ayristirma ve sahte paket uretimi (saf Python)."""
import struct

_FILL = b"www.w3.org"


def is_client_hello(p: bytes) -> bool:
    return len(p) > 43 and p[0] == 0x16 and p[1] == 0x03 and p[5] == 0x01


def find_sni(p: bytes):
    """SNI hostname'in (baslangic, uzunluk) degerini dondurur, yoksa None."""
    try:
        pos = 5 + 4 + 2 + 32                       # kayit + handshake basligi + surum + random
        pos += 1 + p[pos]                          # session id
        pos += 2 + struct.unpack_from("!H", p, pos)[0]   # cipher suites
        pos += 1 + p[pos]                          # compression
        end = min(pos + 2 + struct.unpack_from("!H", p, pos)[0], len(p))
        pos += 2
        while pos + 4 <= end:
            typ, ln = struct.unpack_from("!HH", p, pos)
            pos += 4
            if typ == 0:                           # server_name
                nlen = struct.unpack_from("!H", p, pos + 3)[0]
                start = pos + 5
                return (start, nlen) if nlen and start + nlen <= len(p) else None
            pos += ln
    except (IndexError, struct.error):
        pass
    return None


def make_fake(p: bytes, off: int, ln: int) -> bytes:
    """SNI'yi ayni uzunlukta zararsiz bir hostname ile degistirir."""
    filler = (_FILL * (ln // len(_FILL) + 1))[:ln]
    return p[:off] + filler + p[off + ln:]
