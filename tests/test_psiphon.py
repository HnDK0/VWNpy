"""Tests for psiphon module."""

import base64
import hashlib
import json
import os

import pytest

from vwn.modules import psiphon


def test_server_list_key_valid():
    # Ключ обязан быть полным (732 симв.) и совпадать с signingPublicKeyDigest
    # актуального server_list_compressed (sha256 строки ключа). Если Psiphon
    # в логе падает с "illegal base64 data at input byte N" — ломается здесь.
    k = psiphon.SERVER_LIST_KEY
    assert len(k) == 732
    assert base64.b64decode(k)
    digest = hashlib.sha256(k.encode()).hexdigest().upper()
    assert digest == "57DD879214D9A9E4519609883EEC96A687799C99BBC4BCF5E015D8C3A06368F7"


def test_status_inactive(monkeypatch):
    monkeypatch.setattr(psiphon.shell, "service_active", lambda s: False)
    assert psiphon.status() == {"active": False, "country": "", "mode": "plain", "port": 40002}


def test_status_active(monkeypatch, tmp_path):
    monkeypatch.setattr(psiphon.shell, "service_active", lambda s: True)
    monkeypatch.setattr(psiphon, "COUNTRY_FILE", str(tmp_path / "psiphon_country"))
    monkeypatch.setattr(psiphon, "MODE_FILE", str(tmp_path / "psiphon_mode"))
    with open(psiphon.COUNTRY_FILE, "w") as f:
        f.write("DE\n")
    with open(psiphon.MODE_FILE, "w") as f:
        f.write("warp")
    s = psiphon.status()
    assert s["active"] is True
    assert s["country"] == "DE"
    assert s["mode"] == "warp"


def test_install_downloads_binary(monkeypatch, tmp_path):
    monkeypatch.setattr(psiphon, "BIN", str(tmp_path / "psiphon-tunnel-core"))
    monkeypatch.setattr(psiphon, "CONFIG", str(tmp_path / "psiphon.json"))
    monkeypatch.setattr(psiphon, "SERVICE", str(tmp_path / "psiphon.service"))
    monkeypatch.setattr(psiphon, "MODE_FILE", str(tmp_path / "psiphon_mode"))
    monkeypatch.setattr(psiphon, "COUNTRY_FILE", str(tmp_path / "psiphon_country"))
    monkeypatch.setattr(psiphon, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(psiphon, "LOG_DIR", str(tmp_path / "log"))
    monkeypatch.setattr(psiphon.config, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(psiphon.time, "sleep", lambda s: None)

    calls = []
    class R:
        returncode = 0
        stdout = "x86_64"
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return R()
    monkeypatch.setattr(psiphon.shell, "run", fake_run)

    psiphon.install()

    # verify binary was downloaded
    dl = [c for c in calls if "curl" in str(c) and "psiphon-tunnel-core" in str(c)]
    assert len(dl) == 1
    assert "x86_64" in str(dl[0])

    # verify config written
    assert os.path.isfile(psiphon.CONFIG)
    with open(psiphon.CONFIG) as f:
        cfg = json.load(f)
    assert cfg["LocalSocksProxyPort"] == 40002
    assert "UpstreamProxyURL" not in cfg
    assert "RemoteServerListURLs" in cfg
    assert cfg["RemoteServerListURLs"][0]["OnlyAfterAttempts"] == 0
    assert "RemoteServerListUrl" not in cfg
    assert cfg["RemoteServerListDownloadFilename"] == "remote_server_list"
    assert cfg["EmitDiagnosticNotices"] is True

    # verify mode file
    assert open(psiphon.MODE_FILE).read().strip() == "plain"

    # verify country file
    assert open(psiphon.COUNTRY_FILE).read().strip() == ""

    # verify service written
    assert os.path.isfile(psiphon.SERVICE)


def test_install_warp_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(psiphon, "BIN", str(tmp_path / "psiphon-tunnel-core"))
    monkeypatch.setattr(psiphon, "CONFIG", str(tmp_path / "psiphon.json"))
    monkeypatch.setattr(psiphon, "SERVICE", str(tmp_path / "psiphon.service"))
    monkeypatch.setattr(psiphon, "MODE_FILE", str(tmp_path / "psiphon_mode"))
    monkeypatch.setattr(psiphon, "COUNTRY_FILE", str(tmp_path / "psiphon_country"))
    monkeypatch.setattr(psiphon, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(psiphon, "LOG_DIR", str(tmp_path / "log"))
    monkeypatch.setattr(psiphon.config, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(psiphon.time, "sleep", lambda s: None)

    calls = []
    class R:
        returncode = 0
        stdout = "x86_64"
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return R()
    monkeypatch.setattr(psiphon.shell, "run", fake_run)

    psiphon.install(country="DE", tunnel_mode="warp")

    with open(psiphon.CONFIG) as f:
        cfg = json.load(f)
    assert cfg["EgressRegion"] == "DE"
    assert cfg["UpstreamProxyURL"] == "socks5://127.0.0.1:40000"
    assert "RemoteServerListURLs" in cfg
    assert "RemoteServerListUrl" not in cfg
    assert open(psiphon.MODE_FILE).read().strip() == "warp"
    assert open(psiphon.COUNTRY_FILE).read().strip() == "DE"


def test_add_xray_outbound(monkeypatch, tmp_path):
    from vwn.modules import _outbound as ob
    monkeypatch.setattr(psiphon.config, "XRAY_DIR", str(tmp_path))
    cfg_path = tmp_path / "config.json"
    cfg = {"outbounds": [{"tag": "free", "protocol": "freedom"},
                          {"tag": "block", "protocol": "blackhole"}]}
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)

    ob.add_outbound("psiphon", "socks", 40002)

    with open(cfg_path) as f:
        cfg2 = json.load(f)
    tags = [o["tag"] for o in cfg2["outbounds"]]
    assert "psiphon" in tags
    assert tags.index("psiphon") < tags.index("block")


def test_remove_xray_outbound(monkeypatch, tmp_path):
    from vwn.modules import _outbound as ob
    monkeypatch.setattr(psiphon.config, "XRAY_DIR", str(tmp_path))
    cfg_path = tmp_path / "config.json"
    cfg = {"outbounds": [{"tag": "free"}, {"tag": "psiphon"}, {"tag": "block"}],
           "routing": {"rules": [{"outboundTag": "psiphon"}]}}
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)

    ob.remove_outbound("psiphon")

    with open(cfg_path) as f:
        cfg2 = json.load(f)
    tags = [o["tag"] for o in cfg2["outbounds"]]
    assert "psiphon" not in tags
    assert not any(r.get("outboundTag") == "psiphon" for r in cfg2["routing"]["rules"])


def test_remove(monkeypatch, tmp_path):
    monkeypatch.setattr(psiphon, "SERVICE", str(tmp_path / "psiphon.service"))
    monkeypatch.setattr(psiphon, "BIN", str(tmp_path / "psiphon-tunnel-core"))
    monkeypatch.setattr(psiphon, "CONFIG", str(tmp_path / "psiphon.json"))
    monkeypatch.setattr(psiphon, "MODE_FILE", str(tmp_path / "psiphon_mode"))
    monkeypatch.setattr(psiphon, "COUNTRY_FILE", str(tmp_path / "psiphon_country"))
    monkeypatch.setattr(psiphon, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(psiphon, "LOG_DIR", str(tmp_path / "log"))
    monkeypatch.setattr(psiphon.config, "XRAY_DIR", str(tmp_path))
    # create dummy files to remove
    for p in [psiphon.SERVICE, psiphon.BIN, psiphon.CONFIG, psiphon.MODE_FILE, psiphon.COUNTRY_FILE]:
        with open(p, "w") as f:
            f.write("x")
    os.makedirs(psiphon.DATA_DIR, exist_ok=True)
    os.makedirs(psiphon.LOG_DIR, exist_ok=True)

    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(psiphon.shell, "run", fake_run)

    psiphon.remove()

    assert not os.path.isfile(psiphon.SERVICE)
    assert not os.path.isfile(psiphon.BIN)
    assert not os.path.isfile(psiphon.COUNTRY_FILE)
    flat = [" ".join(c) for c in calls]
    assert any("stop" in c for c in flat)
    assert any("daemon-reload" in c for c in flat)


def test_add_domain(monkeypatch, tmp_path):
    from vwn.modules import _domains
    monkeypatch.setattr(psiphon.config, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))

    cfg = {"routing": {"rules": []}, "outbounds": [{"tag": "psiphon"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    ok = psiphon.add_domain("example.com")
    assert ok is True
    assert psiphon.list_domains() == ["example.com"]


def test_remove_domain(monkeypatch, tmp_path):
    from vwn.modules import _domains
    monkeypatch.setattr(psiphon.config, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))

    cfg = {"routing": {"rules": [
        {"type": "field", "domain": ["domain:example.com"], "outboundTag": "psiphon"},
    ]}, "outbounds": [{"tag": "psiphon"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)
    (tmp_path / "psiphon_domains.txt").write_text("example.com\n", encoding="utf-8")

    psiphon.remove_domain(0)
    assert psiphon.list_domains() == []


def test_reapply_routing_global(monkeypatch, tmp_path):
    from vwn.modules import _domains
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))
    vc.vwn_conf_set("PSIPHON_TUNNEL_MODE", "Global")

    cfg = {"routing": {"rules": []}, "outbounds": [
        {"tag": "psiphon", "protocol": "socks"},
        {"tag": "free"},
    ]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    psiphon.reapply_routing()

    with open(p) as f:
        result = json.load(f)
    port_rules = [r for r in result["routing"]["rules"]
                  if r.get("outboundTag") == "psiphon" and r.get("port") == "0-65535"]
    assert len(port_rules) == 1


def test_reapply_routing_split(monkeypatch, tmp_path):
    from vwn.modules import _domains
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))
    vc.vwn_conf_set("PSIPHON_TUNNEL_MODE", "Split")

    cfg = {"routing": {"rules": []}, "outbounds": [
        {"tag": "psiphon", "protocol": "socks"},
        {"tag": "free"},
    ]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)
    (tmp_path / "psiphon_domains.txt").write_text("google.com\n", encoding="utf-8")

    psiphon.reapply_routing()

    with open(p) as f:
        result = json.load(f)
    split_rules = [r for r in result["routing"]["rules"]
                   if r.get("outboundTag") == "psiphon" and r.get("domain")]
    assert len(split_rules) == 1
    assert "domain:google.com" in split_rules[0]["domain"]


def test_reapply_routing_no_mode(monkeypatch, tmp_path):
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    if os.path.isfile(vc.vwn_conf_path()):
        os.remove(vc.vwn_conf_path())

    cfg = {"routing": {"rules": []}, "outbounds": [{"tag": "psiphon"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    psiphon.reapply_routing()

    with open(p) as f:
        result = json.load(f)
    assert len(result["routing"]["rules"]) == 0
