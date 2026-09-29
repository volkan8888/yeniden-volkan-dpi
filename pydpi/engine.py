"""WinDivert motoru: paketleri yakalar, degistirir ve geri enjekte eder.

Her gorev (TCP, DNS, QUIC, pasif DPI, hop olcumu) kendi WinDivert handle'i ve
thread'i ile calisir; boylece agir TCP trafigi DNS gecikmesini etkilemez.
Hata olursa paket bozulmadan gecirilir (fail-open).
"""
import threading

import pydivert

from . import httpmod, tls

BADSEQ_DELTA = 10000
DNS_MAP_LIMIT = 8192

# Cekirdek seviyesinde filtre: sadece isimize yarayan paketler Python'a gelir.
TCP_FILTER = ("outbound and tcp and ((tcp.DstPort == 443 and tcp.PayloadLength > 100) "
              "or (tcp.DstPort == 80 and tcp.PayloadLength > 0))")
QUIC_FILTER = "outbound and udp.DstPort == 443 and udp.PayloadLength >= 1200"
PASSIVE_FILTER = ("inbound and ip and ip.Id >= 0x0001 and ip.Id <= 0x000F and tcp and "
                  "(tcp.SrcPort == 80 or tcp.SrcPort == 443) and (tcp.Rst or tcp.PayloadLength > 0)")
HOPS_FILTER = "inbound and tcp.Syn and tcp.Ack and (tcp.SrcPort == 443 or tcp.SrcPort == 80)"


def clone(pkt):
    return pydivert.Packet(memoryview(bytearray(pkt.raw)), pkt.interface, pkt.direction)


def _set_ttl(pkt, ttl):
    if pkt.ipv4:
        pkt.ipv4.ttl = ttl
    elif pkt.ipv6:
        pkt.ipv6.hop_limit = ttl


def _get_ttl(pkt):
    return pkt.ipv4.ttl if pkt.ipv4 else pkt.ipv6.hop_limit


class Worker(threading.Thread):
    def __init__(self, name, flt, handler, log):
        super().__init__(name=name, daemon=True)
        self.flt, self.handler, self.log = flt, handler, log
        self.w = None
        self.error = None
        self.ready = threading.Event()

    def run(self):
        try:
            self.w = pydivert.WinDivert(self.flt)
            self.w.open()
        except Exception as e:
            self.error = e
            self.ready.set()
            return
        self.ready.set()
        w = self.w
        while True:
            try:
                pkt = w.recv()
            except Exception:
                break                      # handle kapatildi
            try:
                self.handler(w, pkt)
            except Exception as e:
                self.log(f"[!] {self.name}: {e!r}")
                try:
                    w.send(pkt)
                except Exception:
                    pass

    def stop(self):
        try:
            if self.w:
                self.w.close()
        except Exception:
            pass


class Engine:
    def __init__(self, cfg, need_hops=False):
        self.cfg = cfg
        self.need_hops = need_hops or cfg.auto_ttl
        self.hops = {}
        self.dns_map = {}
        self.workers = []
        self.log = print if cfg.verbose else (lambda *a: None)

    # ---------- filtreler ----------
    def _dns_filter(self):
        c = self.cfg
        parts = ["(ip and outbound and udp.DstPort == 53 and ip.DstAddr != 127.0.0.1)",
                 f"(inbound and udp.SrcPort == {c.dns_port})"]
        if c.dns6:
            parts.append("(ipv6 and outbound and udp.DstPort == 53 and ipv6.DstAddr != ::1)")
        return " or ".join(parts)

    # ---------- yasam dongusu ----------
    def start(self):
        c = self.cfg
        specs = [("tcp", TCP_FILTER, self.on_tcp)]
        if c.dns:
            specs.append(("dns", self._dns_filter(), self.on_dns))
        if c.block_quic:
            specs.append(("quic", QUIC_FILTER, self.on_quic))
        if c.passive_block:
            specs.append(("passive", PASSIVE_FILTER, self.on_passive))
        if self.need_hops:
            specs.append(("hops", HOPS_FILTER, self.on_hops))
        for name, flt, handler in specs:
            wk = Worker(name, flt, handler, print)
            wk.start()
            self.workers.append(wk)
        for wk in self.workers:
            wk.ready.wait(10)
            if wk.error:
                self.stop()
                raise RuntimeError(f"{wk.name}: {wk.error}")

    def alive(self):
        return all(wk.is_alive() for wk in self.workers)

    def stop(self):
        for wk in self.workers:
            wk.stop()

    # ---------- yardimcilar ----------
    def _fake_ttl(self, dst):
        c = self.cfg
        if c.auto_ttl:
            h = self.hops.get(dst)
            if h:
                return max(1, min(h - 1, 12))
        return c.fake_ttl or (5 if c.auto_ttl else 0)

    def _send_fake(self, w, pkt, payload):
        c = self.cfg
        f = clone(pkt)
        f.tcp.payload = payload
        ttl = self._fake_ttl(pkt.dst_addr)
        if ttl:
            _set_ttl(f, ttl)
        if c.fake_badseq:
            f.tcp.seq_num = (f.tcp.seq_num - BADSEQ_DELTA) & 0xFFFFFFFF
        if c.fake_badsum:
            f.recalculate_checksums()
            f.tcp.cksum ^= 0x1234          # IP checksum dogru kalir, TCP bozulur
            w.send(f, recalculate_checksum=False)
        else:
            w.send(f)

    @staticmethod
    def _send_split(w, pkt, data, at):
        if not 0 < at < len(data):
            pkt.tcp.payload = data
            w.send(pkt)
            return
        second = clone(pkt)
        pkt.tcp.payload = data[:at]
        second.tcp.payload = data[at:]
        second.tcp.seq_num = (pkt.tcp.seq_num + at) & 0xFFFFFFFF
        w.send(pkt)
        w.send(second)

    # ---------- islemciler ----------
    def on_tcp(self, w, pkt):
        c = self.cfg
        data = bytes(pkt.tcp.payload)
        port = pkt.tcp.dst_port
        if port == 443 and tls.is_client_hello(data):
            loc = tls.find_sni(data)
            at = c.frag
            if loc:
                self.log(f"[TLS] {data[loc[0]:loc[0] + loc[1]].decode('ascii', 'replace')}")
                if c.mode == "sni":
                    at = loc[0] + loc[1] // 2
                if c.uses_fake:
                    self._send_fake(w, pkt, tls.make_fake(data, *loc))
            self._send_split(w, pkt, data, at)
        elif port == 80 and httpmod.is_http_request(data):
            loc = httpmod.find_host(data)
            if loc and c.uses_fake:
                self._send_fake(w, pkt, httpmod.make_fake(data, *loc))
            data = httpmod.mutate(data, c)
            at = c.frag
            loc = httpmod.find_host(data)
            if loc and c.mode == "sni":
                at = loc[0] + loc[1] // 2
            self._send_split(w, pkt, data, at)
        else:
            w.send(pkt)

    def on_dns(self, w, pkt):
        c = self.cfg
        if pkt.is_outbound:
            if len(self.dns_map) > DNS_MAP_LIMIT:
                self.dns_map.clear()
            self.dns_map[(pkt.src_addr, pkt.src_port)] = pkt.dst_addr
            pkt.dst_addr = c.dns6 if pkt.ipv6 else c.dns4
            pkt.dst_port = c.dns_port
        else:
            orig = self.dns_map.get((pkt.dst_addr, pkt.dst_port))
            if orig:
                pkt.src_addr = orig
                pkt.src_port = 53
        w.send(pkt)

    def on_quic(self, w, pkt):
        payload = pkt.udp.payload
        if payload and payload[0] & 0xC0 == 0xC0:      # QUIC Initial -> dusur, tarayici TCP'ye doner
            return
        w.send(pkt)

    def on_passive(self, w, pkt):
        t = pkt.tcp
        if t.rst:
            return                                     # ISP'nin enjekte ettigi RST
        head = bytes(t.payload)[:12]
        if head.startswith(b"HTTP/1.") and head[8:11] == b" 30":
            return                                     # ISP'nin enjekte ettigi yonlendirme
        w.send(pkt)

    def on_hops(self, w, pkt):
        ttl = _get_ttl(pkt)
        init = 64 if ttl <= 64 else 128 if ttl <= 128 else 255
        self.hops[pkt.src_addr] = init - ttl
        w.send(pkt)
