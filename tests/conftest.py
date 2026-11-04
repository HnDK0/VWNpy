import pytest

from vwn.modules import xray
from vwn.core import system


_VALID_DEC = "mlkem768x25519plus.native.600s.100-111-1111.75-0-111.50-0-3333." + "a" * 24
_VALID_ENC = "mlkem768x25519plus.native.0rtt.100-111-1111.75-0-111.50-0-3333." + "b" * 24

@pytest.fixture(autouse=True)
def _stub_vless_keypair(monkeypatch):
    monkeypatch.setattr(xray, "generate_vless_keypair", lambda strict=False: (_VALID_DEC, _VALID_ENC))
    monkeypatch.setattr(system, "generate_vless_keypair", lambda strict=False: (_VALID_DEC, _VALID_ENC))