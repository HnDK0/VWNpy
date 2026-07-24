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


def test_add_domain(monkeypatch, tmp_path):
    from vwn.modules import _domains
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))

    cfg = {"routing": {"rules": []}, "outbounds": [{"tag": "relay"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    ok = relay.add_domain("example.com")
    assert ok is True
    assert relay.list_domains() == ["example.com"]


def test_remove_domain(monkeypatch, tmp_path):
    from vwn.modules import _domains
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))

    cfg = {"routing": {"rules": [
        {"type": "field", "domain": ["domain:example.com"], "outboundTag": "relay"},
    ]}, "outbounds": [{"tag": "relay"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)
    (tmp_path / "relay_domains.txt").write_text("example.com\n", encoding="utf-8")

    relay.remove_domain(0)
    assert relay.list_domains() == []


def test_reapply_routing_global(monkeypatch, tmp_path):
    from vwn.modules import _domains
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(vc, "VWN_CONF", str(tmp_path / "vwn.conf"))
    monkeypatch.setattr(relay, "CONFIG", str(tmp_path / "relay.json"))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))
    vc.vwn_conf_set("RELAY_TUNNEL_MODE", "Global")

    with open(tmp_path / "relay.json", "w") as f:
        json.dump({"protocol": "socks", "host": "1.2.3.4", "port": 1080}, f)

    cfg = {"routing": {"rules": []}, "outbounds": [
        {"tag": "free"},
        {"tag": "block", "protocol": "blackhole"},
    ]}
    for name in ("config.json", "xhttp.json", "xray-reality.json"):
        with open(tmp_path / name, "w") as f:
            json.dump(cfg, f)

    relay.reapply_routing()

    with open(tmp_path / "config.json") as f:
        result = json.load(f)
    tags = [o["tag"] for o in result["outbounds"]]
    assert "relay" in tags
    port_rules = [r for r in result["routing"]["rules"]
                  if r.get("outboundTag") == "relay" and r.get("port") == "0-65535"]
    assert len(port_rules) == 1


def test_reapply_routing_split(monkeypatch, tmp_path):
    from vwn.modules import _domains
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(vc, "VWN_CONF", str(tmp_path / "vwn.conf"))
    monkeypatch.setattr(relay, "CONFIG", str(tmp_path / "relay.json"))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))
    vc.vwn_conf_set("RELAY_TUNNEL_MODE", "Split")

    with open(tmp_path / "relay.json", "w") as f:
        json.dump({"protocol": "socks", "host": "1.2.3.4", "port": 1080}, f)
    (tmp_path / "relay_domains.txt").write_text("google.com\n", encoding="utf-8")

    cfg = {"routing": {"rules": []}, "outbounds": [
        {"tag": "free"},
        {"tag": "block", "protocol": "blackhole"},
    ]}
    with open(tmp_path / "config.json", "w") as f:
        json.dump(cfg, f)

    relay.reapply_routing()

    with open(tmp_path / "config.json") as f:
        result = json.load(f)
    split_rules = [r for r in result["routing"]["rules"]
                   if r.get("outboundTag") == "relay" and r.get("domain")]
    assert len(split_rules) == 1
    assert "domain:google.com" in split_rules[0]["domain"]
