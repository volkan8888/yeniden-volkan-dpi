import copy
import struct
import sys
import types
import unittest
from types import SimpleNamespace as NS

# pydivert'i taklit et (Linux'ta motor mantigini test edebilmek icin)
stub = types.ModuleType("pydivert")
stub.Packet = object
stub.WinDivert = object
sys.modules["pydivert"] = stub

from pydpi import autotune, engine, httpmod, tls          # noqa: E402
from pydpi.config import Config                            # noqa: E402


def make_client_hello(host: bytes) -> bytes:
    sni = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
    ext = struct.pack("!HH", 0, len(sni)) + sni
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01"
            + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


HTTP_REQ = b"GET /index HTTP/1.1\r\nHost: Example.com\r\nUser-Agent: x\r\n\r\n"


class TestParsers(unittest.TestCase):
    def test_sni(self):
        ch = make_client_hello(b"discord.com")
        self.assertTrue(tls.is_client_hello(ch))
        off, ln = tls.find_sni(ch)
        self.assertEqual(ch[off:off + ln], b"discord.com")

    def test_sni_truncated(self):
        self.assertIsNone(tls.find_sni(make_client_hello(b"discord.com")[:60]))

    def test_tls_fake_same_length(self):
        ch = make_client_hello(b"discord.com")
        off, ln = tls.find_sni(ch)
        fake = tls.make_fake(ch, off, ln)
        self.assertEqual(len(fake), len(ch))
        self.assertNotIn(b"discord", fake)

    def test_http_mutations(self):
        c = Config(host_replace=True)
        self.assertIn(b"\r\nhoSt: Example.com", httpmod.mutate(HTTP_REQ, c))
        c = Config(host_replace=False, host_mixcase=True, host_remove_space=True)
        out = httpmod.mutate(HTTP_REQ, c)
        self.assertIn(b"\r\nHost:eXaMpLe.cOm", out)
        c = Config(host_replace=False, extra_space=True)
        self.assertTrue(httpmod.mutate(HTTP_REQ, c).startswith(b"GET  /index"))

    def test_http_host_and_fake(self):
        off, ln = httpmod.find_host(HTTP_REQ)
        self.assertEqual(HTTP_REQ[off:off + ln], b"Example.com")
        self.assertEqual(len(httpmod.make_fake(HTTP_REQ, off, ln)), len(HTTP_REQ))


class Tcp:
    def __init__(self, payload, seq=1000, dst_port=443):
        self.payload, self.seq_num, self.dst_port, self.cksum = payload, seq, dst_port, 0x1111


class Pkt:
    def __init__(self, payload=b"", seq=1000, dst_port=443, **kw):
        self.tcp = Tcp(payload, seq, dst_port)
        self.ipv4, self.ipv6 = NS(ttl=64), None
        self.dst_addr = "1.2.3.4"
        self.__dict__.update(kw)

    def recalculate_checksums(self):
        self.tcp.cksum = 0xABCD


class W:
    def __init__(self):
        self.sent = []

    def send(self, pkt, recalculate_checksum=True):
        self.sent.append((pkt, recalculate_checksum))


class TestEngine(unittest.TestCase):
    def setUp(self):
        engine.clone = copy.deepcopy

    def test_tls_split_at_sni_and_reassembles(self):
        ch = make_client_hello(b"discord.com")
        e, w = engine.Engine(Config(fake_ttl=0)), W()
        e.on_tcp(w, Pkt(ch, seq=5000))
        self.assertEqual(len(w.sent), 2)
        p1, p2 = w.sent[0][0], w.sent[1][0]
        self.assertEqual(p1.tcp.payload + p2.tcp.payload, ch)
        self.assertEqual(p2.tcp.seq_num, 5000 + len(p1.tcp.payload))
        off, ln = tls.find_sni(ch)
        self.assertTrue(off < len(p1.tcp.payload) < off + ln)      # SNI ikiye bolundu

    def test_fake_ttl_comes_first(self):
        ch = make_client_hello(b"discord.com")
        e, w = engine.Engine(Config(fake_ttl=3)), W()
        e.on_tcp(w, Pkt(ch))
        self.assertEqual(len(w.sent), 3)
        fake = w.sent[0][0]
        self.assertEqual(fake.ipv4.ttl, 3)
        self.assertEqual(len(fake.tcp.payload), len(ch))
        self.assertNotIn(b"discord", fake.tcp.payload)

    def test_badsum_badseq(self):
        ch = make_client_hello(b"discord.com")
        e, w = engine.Engine(Config(fake_ttl=0, fake_badsum=True, fake_badseq=True)), W()
        e.on_tcp(w, Pkt(ch, seq=20000))
        fake, recalc = w.sent[0]
        self.assertEqual(fake.tcp.seq_num, 10000)
        self.assertFalse(recalc)
        self.assertEqual(fake.tcp.cksum, 0xABCD ^ 0x1234)

    def test_auto_ttl_uses_hops(self):
        e = engine.Engine(Config(fake_ttl=0, auto_ttl=True))
        e.hops["1.2.3.4"] = 9
        self.assertEqual(e._fake_ttl("1.2.3.4"), 8)
        self.assertEqual(e._fake_ttl("9.9.9.9"), 5)                # bilinmiyorsa varsayilan

    def test_http_path(self):
        e, w = engine.Engine(Config(fake_ttl=0)), W()
        e.on_tcp(w, Pkt(HTTP_REQ, dst_port=80))
        joined = w.sent[0][0].tcp.payload + w.sent[1][0].tcp.payload
        self.assertIn(b"hoSt:", joined)

    def test_other_traffic_untouched(self):
        e, w = engine.Engine(Config()), W()
        e.on_tcp(w, Pkt(b"\x17\x03\x03" + b"x" * 200))
        self.assertEqual(len(w.sent), 1)

    def test_dns_roundtrip(self):
        e, w = engine.Engine(Config()), W()
        out = NS(is_outbound=True, src_addr="10.0.0.2", src_port=5555, dst_addr="8.8.8.8",
                 dst_port=53, ipv6=None)
        e.on_dns(w, out)
        self.assertEqual((out.dst_addr, out.dst_port), ("77.88.8.8", 1253))
        back = NS(is_outbound=False, dst_addr="10.0.0.2", dst_port=5555, src_addr="77.88.8.8",
                  src_port=1253, ipv6=None)
        e.on_dns(w, back)
        self.assertEqual((back.src_addr, back.src_port), ("8.8.8.8", 53))

    def test_quic_and_passive(self):
        e, w = engine.Engine(Config()), W()
        e.on_quic(w, NS(udp=NS(payload=b"\xc3" + b"\0" * 1200)))
        self.assertEqual(len(w.sent), 0)                           # QUIC Initial dusuruldu
        e.on_quic(w, NS(udp=NS(payload=b"\x43" + b"\0" * 1200)))
        self.assertEqual(len(w.sent), 1)                           # kisa baslik gecer
        e.on_passive(w, NS(tcp=NS(rst=True, payload=b"")))
        e.on_passive(w, NS(tcp=NS(rst=False, payload=b"HTTP/1.1 302 Found\r\n")))
        self.assertEqual(len(w.sent), 1)                           # ikisi de dusuruldu
        e.on_passive(w, NS(tcp=NS(rst=False, payload=b"HTTP/1.1 200 OK\r\n")))
        self.assertEqual(len(w.sent), 2)


class TestAutotune(unittest.TestCase):
    def test_picks_first_working(self):
        cfg, log = Config(), []
        autotune.load_profile = lambda: None
        autotune.save_profile = lambda s: log.append(s)
        ok = autotune.autotune(cfg, ["x.com"], log=lambda *a: None,
                               tester=lambda h: cfg.auto_ttl)      # sadece auto_ttl calisiyor
        self.assertTrue(ok)
        self.assertTrue(cfg.auto_ttl)
        self.assertEqual(len(log), 1)

    def test_none_works(self):
        cfg = Config()
        autotune.load_profile = lambda: None
        autotune.save_profile = lambda s: None
        self.assertFalse(autotune.autotune(cfg, ["x.com"], log=lambda *a: None, tester=lambda h: False))


if __name__ == "__main__":
    unittest.main()
