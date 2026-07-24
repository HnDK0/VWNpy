"""Tests for warp module."""

import json
import subprocess

from vwn.core import config
from vwn.modules import warp


class _R:
    returncode = 0
    stdout = ""
    stderr = ""


def test_check_ip_direct_only(monkeypatch):
    monkeypatch.setattr(warp.config, "vwn_conf_get", lambda k: "")

    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        r = _R()
        if "api.ipify.org" in str(cmd) and "socks5" not in str(cmd) and "-x" not in str(cmd):
            r.stdout = "1.2.3.4\n"
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = warp.check_ip()

    assert result["direct"] == "1.2.3.4"
    assert result["warp"] == ""
    assert result["country"] == ""


def test_check_ip_native(monkeypatch):
    monkeypatch.setattr(warp.config, "vwn_conf_get", lambda k: "native")

    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        r = _R()
        s = " ".join(str(c) for c in cmd) if isinstance(cmd, list) else str(cmd)
        if "api.ipify.org" in s and "--socks5" not in s:
            r.stdout = "1.2.3.4\n"
        if "--socks5-hostname" in s and "127.0.0.1:10808" in s:
            r.stdout = "100.100.1.1\n"
        if "mmdblookup" in s:
            r.stdout = '  { "country": { "iso_code": "DE" <packets> } }\n'
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = warp.check_ip()

    assert result["direct"] == "1.2.3.4"
    assert result["warp"] == "100.100.1.1"
    assert result["country"] == "DE"


# ── Bug 3: _add_routing_rule_if_missing не удаляет socks-warp rule ─

def test_add_routing_preserves_socks_warp(monkeypatch, tmp_path):
    """_add_routing_rule_if_missing() не должен удалять socks-warp routing rule."""
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path))
    cfg = {"routing": {"rules": [
        {"type": "field", "inboundTag": ["socks-warp"], "outboundTag": "warp-native"},
    ]}, "outbounds": [{"tag": "warp-native", "protocol": "wireguard"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    warp._add_routing_rule_if_missing("warp-native", "Global")

    with open(p) as f:
        result = json.load(f)
    rules = result["routing"]["rules"]
    socks_rules = [r for r in rules if r.get("inboundTag") == ["socks-warp"]]
    assert len(socks_rules) == 1, "socks-warp rule must survive _add_routing_rule_if_missing"
    assert socks_rules[0]["outboundTag"] == "warp-native"


def test_add_routing_correct_position(monkeypatch, tmp_path):
    """Global rule должен быть перед catch-all, после dns/block."""
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path))
    cfg = {"routing": {"rules": [
        {"type": "field", "ip": ["127.0.0.53"], "outboundTag": "dns-out"},
        {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
        {"type": "field", "port": "0-65535", "outboundTag": "free"},
    ]}, "outbounds": []}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    warp._add_routing_rule_if_missing("warp-native", "Global")

    with open(p) as f:
        result = json.load(f)
    rules = result["routing"]["rules"]
    tags = [r.get("outboundTag") for r in rules]
    assert tags.index("warp-native") > tags.index("dns-out"), \
        "warp must be after dns-out"
    assert tags.index("warp-native") < tags.index("free"), \
        "warp must be before catch-all free"
