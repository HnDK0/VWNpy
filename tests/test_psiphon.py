"""Tests for psiphon module."""

import json
import os

import pytest

from vwn.modules import psiphon


def test_status_inactive(monkeypatch):
    monkeypatch.setattr(psiphon.shell, "service_active", lambda s: False)
    assert psiphon.status() == {"active": False, "country": "", "mode": "plain", "port": 40002}


def test_status_active(monkeypatch, tmp_path):
    monkeypatch.setattr(psiphon.shell, "service_active", lambda s: True)
    monkeypatch.setattr(psiphon, "CONFIG", str(tmp_path / "psiphon.json"))
    monkeypatch.setattr(psiphon, "MODE_FILE", str(tmp_path / "psiphon_mode"))
    with open(psiphon.CONFIG, "w") as f:
        json.dump({"EgressRegion": "DE"}, f)
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

    # verify mode file
    assert open(psiphon.MODE_FILE).read().strip() == "plain"

    # verify service written
    assert os.path.isfile(psiphon.SERVICE)


def test_install_warp_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(psiphon, "BIN", str(tmp_path / "psiphon-tunnel-core"))
    monkeypatch.setattr(psiphon, "CONFIG", str(tmp_path / "psiphon.json"))
    monkeypatch.setattr(psiphon, "SERVICE", str(tmp_path / "psiphon.service"))
    monkeypatch.setattr(psiphon, "MODE_FILE", str(tmp_path / "psiphon_mode"))
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
    assert open(psiphon.MODE_FILE).read().strip() == "warp"


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
    monkeypatch.setattr(psiphon, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(psiphon, "LOG_DIR", str(tmp_path / "log"))
    monkeypatch.setattr(psiphon.config, "XRAY_DIR", str(tmp_path))
    # create dummy files to remove
    for p in [psiphon.SERVICE, psiphon.BIN, psiphon.CONFIG, psiphon.MODE_FILE]:
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
    flat = [" ".join(c) for c in calls]
    assert any("stop" in c for c in flat)
    assert any("daemon-reload" in c for c in flat)
