"""Ayarlar ve otomatik bulunan profilin kaydi."""
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

STRATEGY_FIELDS = ("mode", "frag", "fake_ttl", "auto_ttl", "fake_badsum", "fake_badseq")


@dataclass
class Config:
    # --- parcalama / sahte paket (calisirken degistirilebilir) ---
    mode: str = "sni"            # sni: SNI/Host ortasindan bol | fixed: frag. bayttan bol
    frag: int = 2
    fake_ttl: int = 5            # 0 = TTL'e dokunma
    auto_ttl: bool = False       # sunucu uzakligina gore TTL sec
    fake_badsum: bool = False    # sahte paketin TCP checksum'u bozuk
    fake_badseq: bool = False    # sahte paketin seq numarasi bozuk
    # --- HTTP hileleri ---
    host_replace: bool = True    # Host: -> hoSt:
    host_mixcase: bool = False   # test.com -> tEsT.cOm
    host_remove_space: bool = False
    extra_space: bool = False    # "GET /" -> "GET  /"
    # --- DNS (baslangicta filtreye islenir) ---
    dns: bool = True
    dns4: str = "77.88.8.8"
    dns6: str = "2a02:6b8::feed:0ff"   # bos birakilirsa IPv6 DNS yonlendirilmez
    dns_port: int = 1253
    # --- diger ---
    passive_block: bool = True
    block_quic: bool = True
    verbose: bool = False

    @property
    def uses_fake(self) -> bool:
        return bool(self.fake_ttl or self.auto_ttl or self.fake_badsum or self.fake_badseq)

    def apply(self, strategy: dict):
        for k in STRATEGY_FIELDS:
            if k in strategy:
                setattr(self, k, strategy[k])

    def strategy(self) -> dict:
        d = asdict(self)
        return {k: d[k] for k in STRATEGY_FIELDS}


def profile_path() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home())
    return Path(base) / "pydpi" / "profile.json"


def load_profile():
    try:
        return json.loads(profile_path().read_text(encoding="utf-8"))
    except Exception:
        return None


def save_profile(strategy: dict):
    p = profile_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(strategy), encoding="utf-8")
