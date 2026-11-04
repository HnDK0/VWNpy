import pytest

from vwn.modules import xray
from vwn.core import system


@pytest.fixture(autouse=True)
def _stub_vless_keypair(monkeypatch):
    monkeypatch.setattr(xray, "generate_vless_keypair", lambda: (None, None))
    monkeypatch.setattr(system, "generate_vless_keypair", lambda: (None, None))