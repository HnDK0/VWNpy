"""Tests for tor module."""

import os

import pytest

from vwn.modules import tor


def test_status_inactive(monkeypatch):
    monkeypatch.setattr(tor.shell, "service_active", lambda s: False)
    s = tor.status()
    assert s["active"] is False
    assert s["port"] == 40003


def test_status_active(monkeypatch, tmp_path):
    monkeypatch.setattr(tor.shell, "service_active", lambda s: True)
    monkeypatch.setattr(tor, "CONFIG", str(tmp_path / "torrc"))
    with open(tor.CONFIG, "w") as f:
        f.write("SocksPort 127.0.0.1:40003\nExitNodes {DE}\nStrictNodes 1\n")
    s = tor.status()
    assert s["active"] is True
    assert s["country"] == "DE"


def test_install(monkeypatch, tmp_path):
    monkeypatch.setattr(tor, "CONFIG", str(tmp_path / "torrc"))
    monkeypatch.setattr(tor.time, "sleep", lambda s: None)
    calls = []
    class R:
        returncode = 0
        stdout = ""
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return R()
    monkeypatch.setattr(tor.shell, "run", fake_run)

    tor.install()

    flat = [" ".join(c) for c in calls]
    assert any("install" in c for c in flat)
    assert any("enable" in c for c in flat)
    assert os.path.isfile(tor.CONFIG)
    with open(tor.CONFIG) as f:
        assert "SocksPort" in f.read()


def test_install_with_country(monkeypatch, tmp_path):
    monkeypatch.setattr(tor, "CONFIG", str(tmp_path / "torrc"))
    monkeypatch.setattr(tor.time, "sleep", lambda s: None)
    class R:
        returncode = 0
        stdout = ""
    monkeypatch.setattr(tor.shell, "run", lambda *a, **k: R())

    tor.install(country="CH")

    with open(tor.CONFIG) as f:
        content = f.read()
    assert "ExitNodes {CH}" in content
    assert "StrictNodes 1" in content


def test_remove(monkeypatch, tmp_path):
    monkeypatch.setattr(tor, "CONFIG", str(tmp_path / "torrc"))
    with open(tor.CONFIG, "w") as f:
        f.write("SocksPort 40003\n")
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(tor.shell, "run", fake_run)

    tor.remove()

    assert not os.path.isfile(tor.CONFIG)
    flat = [" ".join(c) for c in calls]
    assert any("stop" in c for c in flat)
    assert any("remove" in c for c in flat)


def test_change_country(monkeypatch, tmp_path):
    monkeypatch.setattr(tor, "CONFIG", str(tmp_path / "torrc"))
    with open(tor.CONFIG, "w") as f:
        f.write("SocksPort 40003\n")
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(tor.shell, "run", fake_run)

    tor.change_country("US")

    with open(tor.CONFIG) as f:
        content = f.read()
    assert "ExitNodes {US}" in content
    assert any("restart" in str(c) for c in calls)


def test_renew_circuit(monkeypatch):
    import socket
    class FakeSocket:
        def __init__(self, *a, **kw): pass
        def connect(self, *a): pass
        def sendall(self, d): self.sent = d
        def close(self): pass
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: FakeSocket())
    tor.renew_circuit()  # no crash


# ── Bridges ─────────────────────────────────────────────────

def test_install_obfs4(monkeypatch):
    calls = []
    class R:
        returncode = 0
        stdout = "/usr/bin/obfs4proxy"
    monkeypatch.setattr(tor.shell, "run", lambda *a, **k: R())
    assert tor.install_obfs4()
    # already installed → no apt calls


def test_install_obfs4_not_found(monkeypatch):
    class R:
        returncode = 0
        stdout = ""
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        if "which" in cmd:
            return type("R", (), {"returncode": 1, "stdout": ""})()
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(tor.shell, "run", fake_run)
    assert tor.install_obfs4()
    assert any("obfs4proxy" in str(c) for c in calls)


def test_install_obfs4_fallback_lyrebird(monkeypatch):
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        if "which" in cmd:
            return type("R", (), {"returncode": 1, "stdout": ""})()
        if "lyrebird" in cmd:
            return type("R", (), {"returncode": 0, "stdout": ""})()
        if "obfs4proxy" in cmd:
            return type("R", (), {"returncode": 1, "stdout": ""})()
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(tor.shell, "run", fake_run)
    assert tor.install_obfs4()
    assert any("lyrebird" in str(c) for c in calls)


def test_add_bridges(monkeypatch, tmp_path):
    monkeypatch.setattr(tor, "CONFIG", str(tmp_path / "torrc"))
    with open(tor.CONFIG, "w") as f:
        f.write("SocksPort 40003\n")
    class R:
        returncode = 0
        stdout = "/usr/bin/obfs4proxy"
    monkeypatch.setattr(tor.shell, "run", lambda *a, **k: R())
    ok = tor.add_bridges("obfs4", ["obfs4 1.2.3.4:443 FINGERPRINT cert=abc iat-mode=0"])
    assert ok
    with open(tor.CONFIG) as f:
        content = f.read()
    assert "UseBridges 1" in content
    assert "ClientTransportPlugin" in content
    assert "Bridge obfs4 1.2.3.4" in content


def test_remove_bridges(monkeypatch, tmp_path):
    monkeypatch.setattr(tor, "CONFIG", str(tmp_path / "torrc"))
    with open(tor.CONFIG, "w") as f:
        f.write("SocksPort 40003\nUseBridges 1\nBridge obfs4 1.2.3.4:443 cert=abc\n")
    class R:
        returncode = 0
        stdout = ""
    monkeypatch.setattr(tor.shell, "run", lambda *a, **k: R())
    tor.remove_bridges()
    with open(tor.CONFIG) as f:
        content = f.read()
    assert "UseBridges" not in content
    assert "Bridge" not in content


def test_bridge_status_in_config(monkeypatch, tmp_path):
    monkeypatch.setattr(tor.shell, "service_active", lambda s: True)
    monkeypatch.setattr(tor, "CONFIG", str(tmp_path / "torrc"))
    with open(tor.CONFIG, "w") as f:
        f.write("UseBridges 1\nBridge obfs4 1.2.3.4:443\nBridge obfs4 5.6.7.8:443\n")
    s = tor.status()
    assert s["bridges"] is True
    assert s["bridge_count"] == 2


# ── Domains (Split) ──────────────────────────────────────────

def test_add_domain(monkeypatch, tmp_path):
    monkeypatch.setattr(tor, "DOMAINS_FILE", str(tmp_path / "domains.txt"))
    tor.add_domain("example.com")
    assert tor.list_domains() == ["example.com"]


def test_add_domain_multi(monkeypatch, tmp_path):
    monkeypatch.setattr(tor, "DOMAINS_FILE", str(tmp_path / "domains.txt"))
    tor.add_domain("b.com")
    tor.add_domain("a.com")
    tor.add_domain("b.com")
    assert tor.list_domains() == ["a.com", "b.com"]


def test_remove_domain(monkeypatch, tmp_path):
    monkeypatch.setattr(tor, "DOMAINS_FILE", str(tmp_path / "domains.txt"))
    tor.add_domain("x.com")
    tor.add_domain("y.com")
    tor.remove_domain(0)
    assert tor.list_domains() == ["y.com"]


def test_add_domain_blocked_in_global(monkeypatch, tmp_path):
    """Global guard — tor.add_domain() возвращает False при Global rule."""
    from vwn.modules._outbound import _paths
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(tor, "DOMAINS_FILE", str(tmp_path / "domains.txt"))

    cfg = {"routing": {"rules": [
        {"type": "field", "port": "0-65535", "outboundTag": "tor"},
    ]}, "outbounds": [{"tag": "tor", "protocol": "socks"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        import json
        json.dump(cfg, f)

    ok = tor.add_domain("example.com")
    assert ok is False
    assert not os.path.isfile(str(tmp_path / "domains.txt"))


def test_apply_domains_skips_global(monkeypatch, tmp_path):
    """_apply_domains() не патчит规则 если есть Global rule."""
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(tor, "DOMAINS_FILE", str(tmp_path / "domains.txt"))
    (tmp_path / "domains.txt").write_text("example.com\n", encoding="utf-8")

    import json
    cfg = {"routing": {"rules": [
        {"type": "field", "port": "0-65535", "outboundTag": "tor"},
    ]}, "outbounds": [{"tag": "tor", "protocol": "socks"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    tor._apply_domains()

    with open(p) as f:
        result = json.load(f)
    rules = result["routing"]["rules"]
    assert rules[0].get("port") == "0-65535"
    assert rules[0].get("domain") is None


def test_reapply_routing_global(monkeypatch, tmp_path):
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(tor, "DOMAINS_FILE", str(tmp_path / "domains.txt"))
    vc.vwn_conf_set("TOR_TUNNEL_MODE", "Global")

    import json
    cfg = {"routing": {"rules": []}, "outbounds": [
        {"tag": "tor", "protocol": "socks"},
        {"tag": "free"},
    ]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    tor.reapply_routing()

    with open(p) as f:
        result = json.load(f)
    port_rules = [r for r in result["routing"]["rules"]
                  if r.get("outboundTag") == "tor" and r.get("port") == "0-65535"]
    assert len(port_rules) == 1
