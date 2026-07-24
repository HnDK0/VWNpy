import json

import pytest

from vwn.modules import tunnels


def _cfg(rules):
    return {"routing": {"rules": rules}}


def test_mode_global():
    cfg = _cfg([{"outboundTag": "warp", "port": "0-65535"}])
    assert tunnels.get_tunnel_mode(cfg, "warp") == "Global"


def test_mode_split():
    cfg = _cfg([{"outboundTag": "warp", "domain": ["geosite:ru"]}])
    assert tunnels.get_tunnel_mode(cfg, "warp") == "Split"


def test_mode_off_no_rule():
    cfg = _cfg([{"outboundTag": "warp", "domain": []}])
    assert tunnels.get_tunnel_mode(cfg, "warp") == "OFF"


def test_mode_off_no_matching_tag():
    cfg = _cfg([{"outboundTag": "psiphon", "port": "0-65535"}])
    assert tunnels.get_tunnel_mode(cfg, "warp") == "OFF"


def test_inbound_tag_ignored():
    # правило с inboundTag не относится к глобальному режиму туннеля
    cfg = _cfg([{"outboundTag": "warp", "port": "0-65535", "inboundTag": ["x"]}])
    assert tunnels.get_tunnel_mode(cfg, "warp") == "OFF"


def test_from_file(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps(_cfg([{"outboundTag": "tor", "domain": ["a"]}])), encoding="utf-8")
    assert tunnels.get_tunnel_mode_from_file(str(p), "tor") == "Split"
    assert tunnels.get_tunnel_mode_from_file(str(tmp_path / "missing.json"), "tor") == "OFF"


# ── Warp method-specific tags ──────────────────────────────

@pytest.mark.parametrize("method_tag", ["warp-native", "warp-amnezia", "warp-svc"])
def test_warp_method_tags_global(method_tag):
    cfg = _cfg([{"outboundTag": method_tag, "port": "0-65535"}])
    assert tunnels.get_tunnel_mode(cfg, "warp") == "Global"


@pytest.mark.parametrize("method_tag", ["warp-native", "warp-amnezia", "warp-svc"])
def test_warp_method_tags_split(method_tag):
    cfg = _cfg([{"outboundTag": method_tag, "domain": ["geosite:ru"]}])
    assert tunnels.get_tunnel_mode(cfg, "warp") == "Split"


def test_warp_method_tags_ignore_inbound():
    cfg = _cfg([{"outboundTag": "warp-native", "port": "0-65535", "inboundTag": ["x"]}])
    assert tunnels.get_tunnel_mode(cfg, "warp") == "OFF"


def test_render_status():
    out = tunnels.render_tunnel_status("WARP", "Global", True)
    assert "Global" in out
    assert "WARP" in out


# ── Guard: only one tunnel Global ─────────────────────────────────

def test_global_guard_removes_other_global(monkeypatch, tmp_path):
    from vwn.tui import tunnel_menu
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    cfg = {"routing": {"rules": [
        {"type": "field", "port": "0-65535", "outboundTag": "warp"},
        {"type": "field", "domain": ["geosite:netflix"], "outboundTag": "psiphon"},
    ]}, "outbounds": []}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)
    with open(tmp_path / "xhttp.json", "w") as f:
        json.dump({"routing": {"rules": []}, "outbounds": []}, f)

    tunnel_menu._switch_tunnel_mode("psiphon", "Global")

    with open(p) as f:
        result = json.load(f)
    rules = result["routing"]["rules"]
    warp_global = [r for r in rules
                   if r.get("outboundTag") == "warp"
                   and r.get("port") == "0-65535"]
    psiphon_global = [r for r in rules
                      if r.get("outboundTag") == "psiphon"
                      and r.get("port") == "0-65535"]
    assert len(psiphon_global) == 1, "psiphon should be Global"
    assert len(warp_global) == 0, "warp Global should be removed"


def test_global_guard_allows_split(monkeypatch, tmp_path):
    """Split mode should not be affected by guard."""
    from vwn.tui import tunnel_menu
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    cfg = {"routing": {"rules": [
        {"type": "field", "port": "0-65535", "outboundTag": "warp"},
    ]}, "outbounds": []}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)
    with open(tmp_path / "xhttp.json", "w") as f:
        json.dump({"routing": {"rules": []}, "outbounds": []}, f)

    tunnel_menu._switch_tunnel_mode("psiphon", "Split")

    with open(p) as f:
        result = json.load(f)
    rules = result["routing"]["rules"]
    warp_global = [r for r in rules
                   if r.get("outboundTag") == "warp"
                   and r.get("port") == "0-65535"]
    assert len(warp_global) == 1, "warp Global should survive Split switch"


# ── Split fallback: whoer.net when no domains configured ────

def test_switch_split_uses_whoer_net_when_no_domains(monkeypatch, tmp_path):
    from vwn.tui import tunnel_menu
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    cfg = {"routing": {"rules": []}, "outbounds": []}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)
    with open(tmp_path / "xhttp.json", "w") as f:
        json.dump({"routing": {"rules": []}, "outbounds": []}, f)

    tunnel_menu._switch_tunnel_mode("psiphon", "Split")

    with open(p) as f:
        result = json.load(f)
    rules = result["routing"]["rules"]
    split_rules = [r for r in rules
                   if r.get("outboundTag") == "psiphon"
                   and r.get("domain")]
    assert len(split_rules) == 1, "should have psiphon Split rule"
    assert split_rules[0]["domain"] == ["domain:whoer.net"]


def test_switch_split_uses_saved_domains(monkeypatch, tmp_path):
    from vwn.tui import tunnel_menu
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    cfg = {"routing": {"rules": []}, "outbounds": []}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)
    with open(tmp_path / "xhttp.json", "w") as f:
        json.dump({"routing": {"rules": []}, "outbounds": []}, f)

    from vwn.modules import _domains
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))
    domains_file = tmp_path / "psiphon_domains.txt"
    domains_file.write_text("google.com\nyoutube.com\n", encoding="utf-8")

    tunnel_menu._switch_tunnel_mode("psiphon", "Split")

    with open(p) as f:
        result = json.load(f)
    rules = result["routing"]["rules"]
    split_rules = [r for r in rules
                   if r.get("outboundTag") == "psiphon"
                   and r.get("domain")]
    assert len(split_rules) == 1
    assert split_rules[0]["domain"] == ["domain:google.com", "domain:youtube.com"]
