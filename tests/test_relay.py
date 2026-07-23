"""Tests for relay module."""

import json
import os

from vwn.modules import relay


def test_parse_vless_url():
    url = ("vless://uuid@example.com:443?security=reality"
           "&sni=example.com&pbk=pubkey&sid=123&type=tcp&path=/")
    r = relay._parse_url(url)
    assert r["protocol"] == "vless"
    assert r["host"] == "example.com"
    assert r["port"] == 443
    assert r["uuid"] == "uuid"
    assert r["security"] == "reality"
    assert r["sni"] == "example.com"
    assert r["pbk"] == "pubkey"
    assert r["sid"] == "123"


def test_parse_socks_url():
    r = relay._parse_url("socks5://1.2.3.4:1080")
    assert r["protocol"] == "socks"
    assert r["host"] == "1.2.3.4"
    assert r["port"] == 1080


def test_parse_vmess_url():
    import base64, json
    v = {"add": "vmess.example.com", "port": 443, "id": "uuid",
         "tls": "tls", "net": "ws", "path": "/ws", "host": "fake.com"}
    b64 = base64.b64encode(json.dumps(v).encode()).decode()
    url = f"vmess://{b64}"
    r = relay._parse_url(url)
    assert r["protocol"] == "vmess"
    assert r["host"] == "vmess.example.com"
    assert r["uuid"] == "uuid"


def test_build_outbound_socks():
    ob = relay._build_outbound({"protocol": "socks", "host": "1.2.3.4", "port": 1080})
    assert ob["tag"] == "relay"
    assert ob["protocol"] == "socks"
    assert ob["settings"]["servers"][0]["address"] == "1.2.3.4"


def test_build_outbound_vless_reality():
    cfg = {"protocol": "vless", "host": "ex.com", "port": 443, "uuid": "u",
           "security": "reality", "sni": "ex.com", "pbk": "pk", "sid": "s",
           "net": "tcp", "path": "/", "ws_host": "ex.com"}
    ob = relay._build_outbound(cfg)
    assert ob["tag"] == "relay"
    assert ob["protocol"] == "vless"
    assert ob["streamSettings"]["security"] == "reality"
    assert ob["streamSettings"]["realitySettings"]["serverName"] == "ex.com"


def test_configure(monkeypatch, tmp_path):
    monkeypatch.setattr(relay, "CONFIG", str(tmp_path / "relay.json"))
    monkeypatch.setattr(relay, "_apply_outbound", lambda ob: None)
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(relay.shell, "run", fake_run)

    r = relay.configure("socks5://1.2.3.4:1080")

    assert r["protocol"] == "socks"
    assert r["host"] == "1.2.3.4"
    assert os.path.isfile(relay.CONFIG)
    with open(relay.CONFIG) as f:
        saved = json.load(f)
    assert saved["host"] == "1.2.3.4"


def test_status_not_configured():
    assert relay.status() == {"configured": False}


def test_status_configured(monkeypatch, tmp_path):
    monkeypatch.setattr(relay, "CONFIG", str(tmp_path / "relay.json"))
    with open(relay.CONFIG, "w") as f:
        json.dump({"protocol": "socks", "host": "1.2.3.4", "port": 1080}, f)
    s = relay.status()
    assert s["configured"] is True
    assert s["host"] == "1.2.3.4"


def test_remove(monkeypatch, tmp_path):
    monkeypatch.setattr(relay, "CONFIG", str(tmp_path / "relay.json"))
    with open(relay.CONFIG, "w") as f:
        f.write("{}")
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(relay.shell, "run", fake_run)

    relay.remove()

    assert not os.path.isfile(relay.CONFIG)
