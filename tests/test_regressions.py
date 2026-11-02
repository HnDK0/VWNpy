"""Регрессии: CDN-меню, DNS без systemd-resolved, команда cdn-watch."""

import builtins

import pytest
from click.testing import CliRunner

from vwn.core import config, system
from vwn.modules import xray


# ── DNS: локальный резолвер 127.0.0.53 в Xray не используется ──────

@pytest.mark.parametrize("resolver_active", [False, True])
def test_dns_ignores_local_resolver(monkeypatch, resolver_active):
    # 127.0.0.53 не добавляется в DNS Xray независимо от состояния резолвера
    monkeypatch.setattr(system, "local_resolver_active", lambda: resolver_active)
    monkeypatch.setattr(config, "vwn_conf_get", lambda k: None)
    d = xray._dns()
    assert "127.0.0.53" not in d["servers"]
    assert d["servers"][:2] == ["1.1.1.1", "9.9.9.9"]


@pytest.mark.parametrize("resolver_active", [False, True])
def test_routing_has_no_local_dns_rule(monkeypatch, resolver_active):
    monkeypatch.setattr(system, "local_resolver_active", lambda: resolver_active)
    r = xray._routing_base()
    assert r["domainStrategy"] == "IPIfNonMatch"
    assert all(x.get("ip") != ["127.0.0.53"] for x in r["rules"])
    assert r["rules"][-1]["outboundTag"] == "free"


def test_local_resolver_active_false_when_nothing_listens(monkeypatch):
    class _Sock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def connect(self, a): raise ConnectionRefusedError
    monkeypatch.setattr(system.socket, "socket", lambda *a, **k: _Sock())
    assert system.local_resolver_active() is False


# ── CDN-меню ───────────────────────────────────────────────────────

def _run_menu(monkeypatch, inputs, conf=None):
    from vwn.modules import cdn
    from vwn.tui import cdn_menu

    conf = conf or {}
    # реальная сигнатура: vwn_conf_get(key) — ровно один аргумент
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: conf.get(key))
    monkeypatch.setattr(cdn, "init_sources", lambda: None)
    monkeypatch.setattr(cdn, "status", lambda: {
        "mode": "auto_scan", "ip": "1.2.3.4", "ping_ms": "", "watcher": True,
        "found_count": 3})
    calls = {}
    monkeypatch.setattr(cdn, "find_best", lambda mode, cur="": calls.setdefault("best", (mode, cur)) and "5.6.7.8")
    monkeypatch.setattr(cdn, "apply_ip", lambda ip: calls.__setitem__("applied", ip) or True)
    monkeypatch.setattr(cdn_menu, "wait_key", lambda: None)
    it = iter(inputs)
    monkeypatch.setattr(builtins, "input", lambda *a: next(it))
    cdn_menu.manage_cdn()
    return calls


def test_cdn_menu_best_from_cache_does_not_crash(monkeypatch):
    calls = _run_menu(monkeypatch, ["6", "0"], {"CDN_MODE": "auto_scan"})
    assert calls["best"] == ("auto_scan", "")
    assert calls["applied"] == "5.6.7.8"


def test_cdn_menu_survives_garbage_numeric_config(monkeypatch):
    _run_menu(monkeypatch, ["0"], {"CDN_AUTOSCAN_COUNT": "abc", "CDN_SCAN_TIMEOUT": "-5"})


def test_scanner_settings_reject_garbage(monkeypatch):
    from vwn.tui import cdn_menu
    saved = []
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: None)
    monkeypatch.setattr(config, "vwn_conf_set", lambda k, v: saved.append((k, v)))
    it = iter(["1", "abc", "1", "250", "0"])
    monkeypatch.setattr(builtins, "input", lambda *a: next(it))
    cdn_menu._cdn_menu_scanner_settings()
    assert saved == [("CDN_AUTOSCAN_COUNT", "250")]


def test_cdn_conf_int_fallback(monkeypatch):
    from vwn.modules import cdn
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: "x1")
    assert cdn._conf_int("CDN_SCAN_TIMEOUT", 3) == 3
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: "7")
    assert cdn._conf_int("CDN_SCAN_TIMEOUT", 3) == 7


# ── CLI ────────────────────────────────────────────────────────────

def test_cdn_watch_command_registered():
    from vwn.cli import cli
    r = CliRunner().invoke(cli, ["cdn-watch", "--help"])
    assert r.exit_code == 0


# ── Главное меню не падает с traceback ─────────────────────────────

def test_main_menu_returns_after_submenu_error(monkeypatch):
    from vwn.tui import menu
    monkeypatch.setattr(menu, "dashboard", lambda: None)
    monkeypatch.setattr(menu.console, "clear", lambda: None)
    monkeypatch.setattr(menu, "wait_key", lambda: None)
    monkeypatch.setattr(menu, "manage_users",
                        lambda: (_ for _ in ()).throw(TypeError("boom")))
    monkeypatch.setattr(menu.time, "sleep", lambda s: None)
    it = iter(["###", "1", "0"])
    monkeypatch.setattr(builtins, "input", lambda *a: next(it))
    menu.run_menu()  # не должно бросить исключение


def test_main_menu_exits_on_eof(monkeypatch):
    from vwn.tui import menu
    monkeypatch.setattr(menu, "dashboard", lambda: None)
    monkeypatch.setattr(menu.console, "clear", lambda: None)
    def _eof(*a):
        raise EOFError
    monkeypatch.setattr(builtins, "input", _eof)
    menu.run_menu()  # раньше — бесконечный цикл


def test_nginx_resolver_follows_local_resolver(monkeypatch, tmp_path):
    out = tmp_path / "n" / "loop.conf"
    tpl = tmp_path / "t.conf"
    tpl.write_text("resolver __RESOLVER__ valid=300s;")
    monkeypatch.setattr(system, "local_resolver_active", lambda: False)
    xray.write_nginx_loopback_config(str(tpl), str(out))
    assert "127.0.0.53" not in out.read_text()
    monkeypatch.setattr(system, "local_resolver_active", lambda: True)
    xray.write_nginx_loopback_config(str(tpl), str(out))
    assert "127.0.0.53" in out.read_text()
