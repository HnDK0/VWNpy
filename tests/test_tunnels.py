import json

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


def test_render_status():
    out = tunnels.render_tunnel_status("WARP", "Global", True)
    assert "Global" in out
    assert "WARP" in out


# ── Guard: only one tunnel Global ─────────────────────────────────

def test_global_guard_removes_other_global(monkeypatch, tmp_path):
    from vwn.tui import menu
    monkeypatch.setattr(menu.config, "XRAY_DIR", str(tmp_path))
    cfg = {"routing": {"rules": [
        {"type": "field", "port": "0-65535", "outboundTag": "warp"},
        {"type": "field", "domain": ["geosite:netflix"], "outboundTag": "psiphon"},
    ]}, "outbounds": []}
    p = tmp_path / "config.json"
    import json
    with open(p, "w") as f:
        json.dump(cfg, f)
    # also create empty xhttp.json
    with open(tmp_path / "xhttp.json", "w") as f:
        json.dump({"routing": {"rules": []}, "outbounds": []}, f)

    menu._switch_tunnel_mode("psiphon", "Global")

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
    from vwn.tui import menu
    monkeypatch.setattr(menu.config, "XRAY_DIR", str(tmp_path))
    cfg = {"routing": {"rules": [
        {"type": "field", "port": "0-65535", "outboundTag": "warp"},
    ]}, "outbounds": []}
    import json
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)
    with open(tmp_path / "xhttp.json", "w") as f:
        json.dump({"routing": {"rules": []}, "outbounds": []}, f)

    menu._switch_tunnel_mode("psiphon", "Split")

    with open(p) as f:
        result = json.load(f)
    rules = result["routing"]["rules"]
    warp_global = [r for r in rules
                   if r.get("outboundTag") == "warp"
                   and r.get("port") == "0-65535"]
    assert len(warp_global) == 1, "warp Global should survive Split switch"
