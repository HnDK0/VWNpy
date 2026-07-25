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


# ── Bug 1: insert_before_catchall не ломает routing порядок ────────

def test_insert_before_catchall_preserves_order():
    """WARP Global rule должен быть ПЕРЕД catch-all, НО ПОСЛЕ dns/block."""
    from vwn.modules.tunnels import insert_before_catchall
    rules = [
        {"type": "field", "ip": ["127.0.0.53"], "outboundTag": "dns-out"},
        {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
        {"type": "field", "port": "0-65535", "outboundTag": "free"},
    ]
    insert_before_catchall(rules, {"type": "field", "port": "0-65535", "outboundTag": "warp-native"})
    assert rules[0]["outboundTag"] == "dns-out"
    assert rules[1]["outboundTag"] == "block"
    assert rules[2]["outboundTag"] == "block"
    assert rules[3]["outboundTag"] == "warp-native"
    assert rules[4]["outboundTag"] == "free"


def test_insert_before_catchall_no_catchall_appends():
    """Нет catch-all правила — rule добавляется в конец."""
    from vwn.modules.tunnels import insert_before_catchall
    rules = [
        {"type": "field", "ip": ["127.0.0.53"], "outboundTag": "dns-out"},
    ]
    insert_before_catchall(rules, {"type": "field", "port": "0-65535", "outboundTag": "warp-native"})
    assert rules[-1]["outboundTag"] == "warp-native"
    assert len(rules) == 2


def test_insert_before_catchall_skips_tunnel_rules():
    """Tunnel rules (port 0-65535, outboundTag=warp/psiphon) не являются catch-all."""
    from vwn.modules.tunnels import insert_before_catchall
    rules = [
        {"type": "field", "port": "0-65535", "outboundTag": "psiphon"},
        {"type": "field", "port": "0-65535", "outboundTag": "free"},
    ]
    insert_before_catchall(rules, {"type": "field", "port": "0-65535", "outboundTag": "warp-native"})
    assert rules[0]["outboundTag"] == "psiphon"
    assert rules[1]["outboundTag"] == "warp-native"
    assert rules[2]["outboundTag"] == "free"


# ── Bug 4: _domains._apply не удаляет outbound при пустых доменах ──

def test_domains_apply_empty_preserves_outbound(monkeypatch, tmp_path):
    """Удаление всех доменов НЕ должно удалять outbound из конфига."""
    from vwn.modules import _domains
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))

    cfg = {"routing": {"rules": [
        {"type": "field", "domain": ["domain:example.com"], "outboundTag": "warp-native"},
    ]}, "outbounds": [{"tag": "warp-native", "protocol": "wireguard"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    domains_file = tmp_path / "warp_domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")
    _domains.remove_domain("warp", 0, routing_tag="warp-native")

    with open(p) as f:
        result = json.load(f)
    tags = [o["tag"] for o in result["outbounds"]]
    assert "warp-native" in tags, "outbound must survive empty domain list"
    warp_rules = [r for r in result["routing"]["rules"]
                  if r.get("outboundTag") == "warp-native"
                  and "domain" in r]
    assert len(warp_rules) == 0, "Split routing rule should be removed"


def test_add_domain_blocked_in_global(monkeypatch, tmp_path):
    """add_domain() возвращает False и не пишет файл если режим Global."""
    from vwn.modules import _domains
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))

    cfg = {"routing": {"rules": [
        {"type": "field", "port": "0-65535", "outboundTag": "warp-native"},
    ]}, "outbounds": [{"tag": "warp-native", "protocol": "wireguard"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    ok = _domains.add_domain("warp", "example.com", routing_tag="warp-native")
    assert ok is False, "should reject domain in Global mode"
    assert not (tmp_path / "warp_domains.txt").exists(), "no domain file created"


def test_add_domain_allowed_in_split(monkeypatch, tmp_path):
    """add_domain() работает если нет Global rule (Split или нет правила)."""
    from vwn.modules import _domains
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))

    cfg = {"routing": {"rules": [
        {"type": "field", "domain": ["domain:existing.com"], "outboundTag": "warp-native"},
    ]}, "outbounds": [{"tag": "warp-native", "protocol": "wireguard"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    ok = _domains.add_domain("warp", "example.com", routing_tag="warp-native")
    assert ok is True, "should allow domain in Split mode"
    assert (tmp_path / "warp_domains.txt").exists()


def test_add_domain_blocked_in_global_psiphon(monkeypatch, tmp_path):
    """Global guard работает для psiphon тега."""
    from vwn.modules import _domains
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))

    cfg = {"routing": {"rules": [
        {"type": "field", "port": "0-65535", "outboundTag": "psiphon"},
    ]}, "outbounds": [{"tag": "psiphon", "protocol": "socks"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    ok = _domains.add_domain("psiphon", "example.com")
    assert ok is False


def test_add_domain_blocked_in_global_relay(monkeypatch, tmp_path):
    """Global guard работает для relay тега."""
    from vwn.modules import _domains
    from vwn.core import config as vc
    monkeypatch.setattr(vc, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(_domains, "XRAY_DIR", str(tmp_path))

    cfg = {"routing": {"rules": [
        {"type": "field", "port": "0-65535", "outboundTag": "relay"},
    ]}, "outbounds": [{"tag": "relay", "protocol": "socks"}]}
    p = tmp_path / "config.json"
    with open(p, "w") as f:
        json.dump(cfg, f)

    ok = _domains.add_domain("relay", "example.com")
    assert ok is False


def test_insert_before_catchall_psiphon_global():
    """Psiphon Global rule вставляется перед catch-all."""
    rules = [
        {"type": "field", "outboundTag": "dns-out", "inboundTag": ["dns-in"]},
        {"type": "field", "port": "0-65535", "outboundTag": "free"},
    ]
    tunnels.insert_before_catchall(rules, {"type": "field", "port": "0-65535", "outboundTag": "psiphon"})
    tags = [r.get("outboundTag") for r in rules]
    assert tags == ["dns-out", "psiphon", "free"]


def test_insert_before_catchall_relay_split():
    """Relay Split rule вставляется перед catch-all."""
    rules = [
        {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
        {"type": "field", "port": "0-65535", "outboundTag": "free"},
    ]
    tunnels.insert_before_catchall(rules, {"type": "field", "domain": ["domain:example.com"], "outboundTag": "relay"})
    tags = [r.get("outboundTag") for r in rules]
    assert tags == ["block", "relay", "free"]


def test_insert_before_catchall_tor_global():
    """Tor Global rule вставляется перед catch-all."""
    rules = [
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
        {"type": "field", "port": "0-65535", "outboundTag": "free"},
    ]
    tunnels.insert_before_catchall(rules, {"type": "field", "port": "0-65535", "outboundTag": "tor"})
    tags = [r.get("outboundTag") for r in rules]
    assert tags == ["block", "tor", "free"]
