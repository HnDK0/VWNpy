import json
import os

import pytest

from vwn.core import config
from vwn.modules import xray, relay


@pytest.fixture
def paths(tmp_path, monkeypatch):
    xray_dir = tmp_path / "xray"
    monkeypatch.setattr(config, "XRAY_DIR", str(xray_dir))
    monkeypatch.setattr(config, "NGINX_LOOPBACK_CONF", str(tmp_path / "xray_loopback.conf"))
    monkeypatch.setattr(config, "SYSTEMD_DIR", str(tmp_path / "systemd"))
    monkeypatch.setattr(config, "REALITY_PUBLIC_PORT", 443)
    monkeypatch.setattr(config, "NGINX_LOOPBACK_PORT", 8443)
    monkeypatch.setattr(config, "XRAY_GRPC_PORT", 50001)
    monkeypatch.setattr(config, "XRAY_XHTTP_PORT", 50002)
    return tmp_path


def test_generate_uuid_format():
    import uuid as _uuid
    assert _uuid.UUID(xray.generate_uuid())


def test_reality_config_shape(monkeypatch):
    monkeypatch.setattr(xray, "_bbr_available", lambda: True)
    monkeypatch.setattr(xray, "_tfo_server_ok", lambda: True)
    c = xray.reality_config("uuid-1", "vpn.example.com",
                            "PRIV", "SHORT", port=443, fallback_port=8443)
    ib = c["inbounds"][0]
    assert ib["port"] == 443
    assert ib["streamSettings"]["security"] == "reality"
    assert ib["streamSettings"]["realitySettings"]["privateKey"] == "PRIV"
    # Fallback dest → nginx loopback
    assert ib["streamSettings"]["realitySettings"]["dest"] == "127.0.0.1:8443"
    assert ib["streamSettings"]["realitySettings"]["serverNames"] == ["vpn.example.com"]
    # min/max client ver очищены (любая версия клиента)
    assert ib["settings"]["clients"][0].get("minClientVer") == ""
    assert ib["settings"]["clients"][0].get("maxClientVer") == ""
    assert c["outbounds"][-1]["protocol"] == "blackhole"   # общие outbounds
    tags = [o["tag"] for o in c["outbounds"]]
    assert "dns-out" in tags
    assert "free" in tags
    assert "block" in tags
    # ponytail: outbound'ы туннелей добавляются модулями, не в дефолте
    assert "warp-svc" not in tags
    assert ib["sniffing"]["routeOnly"] is True
    assert ib["streamSettings"]["sockopt"]["tcpCongestion"] == "bbr"
    assert ib["streamSettings"]["sockopt"]["tcpFastOpen"] is True


def test_grpc_config_shape():
    c = xray.grpc_config("uuid-1", 50001, "svcabc123")
    ib = c["inbounds"][0]
    assert ib["listen"] == "127.0.0.1"
    assert ib["port"] == 50001
    assert ib["tag"] == "grpc-inbound"
    assert ib["streamSettings"]["network"] == "grpc"
    assert ib["streamSettings"]["security"] == "none"      # TLS терминирует nginx
    assert ib["streamSettings"]["grpcSettings"]["serviceName"] == "svcabc123"
    assert "wsSettings" not in ib["streamSettings"]
    # loopback-inbound: только keepalive, без BBR/TFO (не зависит от ядра)
    assert "tcpCongestion" not in ib["streamSettings"]["sockopt"]
    assert "tcpFastOpen" not in ib["streamSettings"]["sockopt"]
    assert ib["streamSettings"]["sockopt"]["tcpKeepAliveIdle"] == 60
    assert ib["sniffing"]["routeOnly"] is True


def test_xhttp_config_shape():
    c = xray.xhttp_config("uuid-1", 50002, "/v2/api/xyz", "vpn.example.com", mode="stream")
    ib = c["inbounds"][0]
    assert ib["port"] == 50002
    assert ib["streamSettings"]["network"] == "xhttp"
    xs = ib["streamSettings"]["xhttpSettings"]
    # серверный режим всегда auto (принимает stream-one/stream-up/packet-up),
    # режим клиента задаётся в ссылке; версионно-зависимые поля не пишем
    assert xs["mode"] == "auto"
    assert xs["path"] == "/v2/api/xyz"
    assert "xmux" not in xs
    assert "scMaxConcurrentPosts" not in xs and "scMaxEachPostBytes" not in xs


def test_provision_writes_valid_configs(paths):
    params = xray.provision_configs(
        "vpn.example.com", "https://www.openstreetmap.org/",
        "microsoft.com:443", private_key="PRIV",
    )
    rc = json.loads((paths / "xray" / "xray-reality.json").read_text(encoding="utf-8"))
    assert rc["inbounds"][0]["port"] == 443
    # serverNames = SNI-домен (microsoft.com), а не домен сервера
    assert rc["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"] == ["microsoft.com"]
    # Fallback dest → nginx loopback (не-Reality трафик)
    assert rc["inbounds"][0]["streamSettings"]["realitySettings"]["dest"] == "127.0.0.1:8443"

    gc = json.loads((paths / "xray" / "grpc.json").read_text(encoding="utf-8"))
    assert gc["inbounds"][0]["port"] == 50001
    svc = gc["inbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"]
    assert svc == params["grpc_service"] == config.vwn_conf_get("GRPC_SERVICE")
    assert svc.startswith("svc") and "/" not in svc
    assert config.vwn_conf_get("WS_PATH") is None

    xc = json.loads((paths / "xray" / "xhttp.json").read_text(encoding="utf-8"))
    assert xc["inbounds"][0]["port"] == 50002

    ng = (paths / "xray_loopback.conf").read_text(encoding="utf-8")
    assert "127.0.0.1:8443" in ng                          # nginx loopback (через Reality fallback)
    assert "log_format main_safe" in ng                  # иначе nginx -t падает
    # gRPC: grpc_pass (h2c) на префикс serviceName БЕЗ хвостового "/" (иначе 301
    # на "/<service>" выдаёт путь), не-gRPC → 404, длинные таймауты для простоя
    assert f"location ^~ /{svc} {{" in ng
    assert "grpc_pass grpc://127.0.0.1:50001" in ng
    assert 'if ($content_type !~ "^application/grpc")' in ng
    assert "grpc_read_timeout 1w" in ng and "client_body_timeout 1w" in ng
    assert "grpc_socket_keepalive on" in ng    # proxy_pass/WebSocket для loopback-inbound'ов больше нет
    assert "proxy_pass http://127.0.0.1:50001" not in ng
    assert "Upgrade" not in ng and "connection_upgrade" not in ng
    # X-Forwarded-For в gRPC-location даёт warning в Xray на каждое соединение
    grpc_loc = ng[ng.index(f"location ^~ /{svc} {{"):]
    grpc_loc = grpc_loc[:grpc_loc.index("\n    }")]
    assert "X-Forwarded-For" not in grpc_loc
    assert "grpc_pass grpc://127.0.0.1:50002" in ng     # XHTTP только grpc_pass (h2c)
    assert "proxy_pass http://127.0.0.1:50002" not in ng  # HTTP/1.1 ломает stream-up/one
    assert "grpc_buffer_size 64k" in ng
    assert "grpc_read_timeout 1w" in ng
    assert "client_body_timeout 1w" in ng
    assert "keepalive_timeout 30m" in ng
    assert "root /usr/local/etc/xray" in ng              # подписки (root, файлы в sub/)
    # yaml-подписки для mihomo (regex должен совпадать с именем файла)
    assert "location ~ ^/sub/[A-Za-z0-9_-]+_[A-Za-z0-9]+\\.yaml$" in ng
    assert "proxy_pass https://www.openstreetmap.org/" in ng
    assert "Strict-Transport-Security" in ng
    # 3 независимых unit-файла (reality/grpc/xhttp)
    sd = paths / "systemd"
    for unit, cfg in (("xray-reality.service", "xray-reality.json"),
                      ("xray-grpc.service", "grpc.json"),
                      ("xray-xhttp.service", "xhttp.json")):
        u = (sd / unit).read_text(encoding="utf-8")
        assert f"run -config {paths / 'xray' / cfg}" in u
        assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE" in u
        assert "WantedBy=multi-user.target" in u

    assert config.vwn_conf_get("DOMAIN") == "vpn.example.com"
    assert config.vwn_conf_get("UUID") == params["uuid"]


def test_provision_rejects_bad_domain(paths):
    with pytest.raises(ValueError):
        xray.provision_configs("bad domain", "https://x.com/", "microsoft.com:443",
                               private_key="PRIV", server_name="x.com")


def test_reapply_warp_restores_outbound(paths):
    """reapply_warp() is a no-op when no WARP is active; provision leaves clean outbounds."""
    xray.provision_configs(
        "vpn.example.com", "https://www.openstreetmap.org/",
        "microsoft.com:443", private_key="PRIV",
    )
    rc = json.loads((paths / "xray" / "xray-reality.json").read_text(encoding="utf-8"))
    # ponytail: outbound'ы тунней не в дефолте — только базовые
    tags = [o["tag"] for o in rc["outbounds"]]
    assert "warp-svc" not in tags
    assert "block" in tags

    # Reapply with no active WARP → no-op
    from vwn.modules.warp import reapply_warp
    reapply_warp()
    rc2 = json.loads((paths / "xray" / "xray-reality.json").read_text(encoding="utf-8"))
    tags2 = [o["tag"] for o in rc2["outbounds"]]
    assert "warp-svc" not in tags2


def test_rebuild_preserves_psiphon_routing(paths):
    """rebuild_configs() восстанавливает psiphon routing после перезаписи."""
    xray.provision_configs(
        "vpn.example.com", "https://www.openstreetmap.org/",
        "microsoft.com:443", private_key="PRIV",
    )
    config.vwn_conf_set("PSIPHON_TUNNEL_MODE", "Global")

    xray.rebuild_configs()

    rc = json.loads((paths / "xray" / "xray-reality.json").read_text(encoding="utf-8"))
    port_rules = [r for r in rc["routing"]["rules"]
                  if r.get("outboundTag") == "psiphon" and r.get("port") == "0-65535"]
    assert len(port_rules) == 1, "psiphon Global rule must survive rebuild"


def test_rebuild_preserves_tor_routing(paths):
    """rebuild_configs() восстанавливает tor routing после перезаписи."""
    xray.provision_configs(
        "vpn.example.com", "https://www.openstreetmap.org/",
        "microsoft.com:443", private_key="PRIV",
    )
    config.vwn_conf_set("TOR_TUNNEL_MODE", "Global")

    xray.rebuild_configs()

    rc = json.loads((paths / "xray" / "xray-reality.json").read_text(encoding="utf-8"))
    port_rules = [r for r in rc["routing"]["rules"]
                  if r.get("outboundTag") == "tor" and r.get("port") == "0-65535"]
    assert len(port_rules) == 1, "tor Global rule must survive rebuild"


def test_rebuild_preserves_relay_routing(paths, monkeypatch):
    """rebuild_configs() восстанавливает relay outbound + routing после перезаписи."""
    monkeypatch.setattr(relay, "CONFIG", str(paths / "xray" / "relay.json"))
    xray.provision_configs(
        "vpn.example.com", "https://www.openstreetmap.org/",
        "microsoft.com:443", private_key="PRIV",
    )
    config.vwn_conf_set("RELAY_TUNNEL_MODE", "Global")
    relay_cfg = paths / "xray" / "relay.json"
    with open(relay_cfg, "w") as f:
        json.dump({"protocol": "socks", "host": "1.2.3.4", "port": 1080}, f)

    xray.rebuild_configs()

    rc = json.loads((paths / "xray" / "xray-reality.json").read_text(encoding="utf-8"))
    tags = [o["tag"] for o in rc["outbounds"]]
    assert "relay" in tags, "relay outbound must survive rebuild"
    port_rules = [r for r in rc["routing"]["rules"]
                  if r.get("outboundTag") == "relay" and r.get("port") == "0-65535"]
    assert len(port_rules) == 1, "relay Global rule must survive rebuild"


# ── sockopt: зависит от возможностей ядра сервера ───────────────────

def test_sockopt_public_without_kernel_support(monkeypatch):
    monkeypatch.setattr(xray, "_bbr_available", lambda: False)
    monkeypatch.setattr(xray, "_tfo_server_ok", lambda: False)
    so = xray._sockopt(public=True)
    assert "tcpCongestion" not in so and "tcpFastOpen" not in so


def test_sockopt_public_with_kernel_support(monkeypatch):
    monkeypatch.setattr(xray, "_bbr_available", lambda: True)
    monkeypatch.setattr(xray, "_tfo_server_ok", lambda: True)
    so = xray._sockopt(public=True)
    assert so["tcpCongestion"] == "bbr" and so["tcpFastOpen"] is True


def test_sockopt_loopback_never_has_bbr(monkeypatch):
    monkeypatch.setattr(xray, "_bbr_available", lambda: True)
    monkeypatch.setattr(xray, "_tfo_server_ok", lambda: True)
    assert "tcpCongestion" not in xray._sockopt(public=False)


@pytest.mark.parametrize("m", ["auto", "stream-one", "stream-up", "packet-up", "stream"])
def test_xhttp_server_mode_always_auto(m):
    c = xray.xhttp_config("u", 50002, "/x", "d.example.com", mode=m)
    assert c["inbounds"][0]["streamSettings"]["xhttpSettings"]["mode"] == "auto"


def test_dns_has_system_resolver_last(monkeypatch):
    monkeypatch.setattr(config, "vwn_conf_get", lambda k: None)
    assert xray._dns()["servers"][-1] == "localhost"


def test_set_xhttp_mode_does_not_pin_server(paths, monkeypatch):
    """Смена режима меняет только клиентские ссылки; серверный inbound остаётся auto."""
    xray.provision_configs("vpn.example.com", "https://www.openstreetmap.org/",
                           "microsoft.com:443", private_key="PRIV")
    calls = []
    monkeypatch.setattr(xray.shell, "run", lambda *a, **k: calls.append(a))
    import vwn.modules.sub as _sub
    monkeypatch.setattr(_sub, "rebuild_all_sub_files", lambda: None)
    xray.set_xhttp_mode("stream-one")
    xc = json.loads((paths / "xray" / "xhttp.json").read_text(encoding="utf-8"))
    assert xc["inbounds"][0]["streamSettings"]["xhttpSettings"]["mode"] == "auto"
    assert config.vwn_conf_get("XHTTP_MODE") == "stream-one"
    assert calls == []          # перезапуск xray не нужен


# ── gRPC: управление (serviceName / mode / отключение) ──────────────

def _provisioned(paths, monkeypatch):
    params = xray.provision_configs("vpn.example.com", "https://www.openstreetmap.org/",
                                    "microsoft.com:443", private_key="PRIV")
    calls = []
    monkeypatch.setattr(xray.shell, "run", lambda cmd, *a, **k: calls.append(list(cmd)))
    import vwn.modules.sub as _sub
    rebuilt = []
    monkeypatch.setattr(_sub, "rebuild_all_sub_files", lambda *a, **k: rebuilt.append(1) or 0)
    return params, calls, rebuilt


def test_update_grpc_service(paths, monkeypatch):
    params, calls, rebuilt = _provisioned(paths, monkeypatch)
    xray.update_grpc_service("/My.Svc-2/")          # "/" по краям срезаются
    gc = json.loads((paths / "xray" / "grpc.json").read_text(encoding="utf-8"))
    assert gc["inbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"] == "My.Svc-2"
    assert config.vwn_conf_get("GRPC_SERVICE") == "My.Svc-2"
    ng = (paths / "xray_loopback.conf").read_text(encoding="utf-8")
    assert "location ^~ /My.Svc-2 {" in ng and params["grpc_service"] not in ng
    assert rebuilt                                   # подписки пересобраны
    assert ["systemctl", "restart", "xray-grpc"] in calls
    assert ["systemctl", "reload", "nginx"] in calls


@pytest.mark.parametrize("bad", ["", "a/b", "a b", "a;b"])
def test_update_grpc_service_rejects_bad_name(paths, monkeypatch, bad):
    params, calls, _ = _provisioned(paths, monkeypatch)
    with pytest.raises(ValueError):
        xray.update_grpc_service(bad)
    assert config.vwn_conf_get("GRPC_SERVICE") == params["grpc_service"]
    assert calls == []


def test_set_grpc_mode_only_client_side(paths, monkeypatch):
    _, calls, rebuilt = _provisioned(paths, monkeypatch)
    before = (paths / "xray" / "grpc.json").read_text(encoding="utf-8")
    xray.set_grpc_mode("multi")
    assert config.vwn_conf_get("GRPC_MODE") == "multi"
    assert (paths / "xray" / "grpc.json").read_text(encoding="utf-8") == before
    assert rebuilt and calls == []                   # сервер принимает оба режима
    with pytest.raises(ValueError):
        xray.set_grpc_mode("auto")


def test_disable_enable_grpc(paths, monkeypatch):
    _, calls, _ = _provisioned(paths, monkeypatch)
    xray.disable_grpc()
    assert not (paths / "xray" / "grpc.json").exists()
    assert (paths / "xray" / "grpc.json.disabled").exists()
    assert config.vwn_conf_get("DISABLED_PROTOCOLS") == "grpc"
    assert ["systemctl", "stop", "xray-grpc"] in calls
    xray.enable_grpc()
    assert (paths / "xray" / "grpc.json").exists()
    assert config.vwn_conf_get("DISABLED_PROTOCOLS") is None
    assert ["systemctl", "start", "xray-grpc"] in calls


def test_read_grpc_xhttp_info(paths, monkeypatch):
    params, _, _ = _provisioned(paths, monkeypatch)
    info = xray.read_grpc_xhttp_info()
    assert info["grpc_active"] is True
    assert info["grpc_service"] == params["grpc_service"]
    assert info["grpc_port"] == 50001 and info["grpc_mode"] == "gun"
    assert "ws_path" not in info


# ── Миграция WebSocket → gRPC ───────────────────────────────────────

def _make_legacy(paths, monkeypatch, disabled_ws=False):
    """Состояние сервера ДО перехода: WS_PATH, xray-ws.service, config.json (ws)."""
    params, calls, rebuilt = _provisioned(paths, monkeypatch)
    xd, sd = paths / "xray", paths / "systemd"
    config.vwn_conf_del("GRPC_SERVICE")
    config.vwn_conf_set("WS_PATH", "/v2/api/oldws")
    (xd / "grpc.json").unlink()
    (sd / "xray-grpc.service").unlink()
    (xd / "config.json").write_text(json.dumps({"inbounds": [{
        "port": 50001, "streamSettings": {"network": "ws",
                                          "wsSettings": {"path": "/v2/api/oldws"}}}]}),
        encoding="utf-8")
    (sd / "xray-ws.service").write_text("[Unit]\n", encoding="utf-8")
    (sd / "xray-ws.service.d").mkdir()
    (sd / "xray-ws.service.d" / "cpuguard.conf").write_text("[Service]\n", encoding="utf-8")
    if disabled_ws:
        config.vwn_conf_set("DISABLED_PROTOCOLS", "ws")
    calls.clear()
    return calls


def test_legacy_detection(paths, monkeypatch):
    _provisioned(paths, monkeypatch)
    assert xray.legacy_ws_present() is False
    assert xray.migrate_ws_to_grpc() is False


def test_migrate_ws_to_grpc(paths, monkeypatch):
    calls = _make_legacy(paths, monkeypatch)
    assert xray.legacy_ws_present() is True
    assert xray.migrate_ws_to_grpc() is True

    xd, sd = paths / "xray", paths / "systemd"
    svc = config.vwn_conf_get("GRPC_SERVICE")
    assert svc and svc.startswith("svc")
    assert config.vwn_conf_get("WS_PATH") is None
    assert not (xd / "config.json").exists()
    assert not (sd / "xray-ws.service").exists()
    assert not (sd / "xray-ws.service.d").exists()
    assert (sd / "xray-grpc.service").exists()
    assert f"run -config {xd / 'grpc.json'}" in (sd / "xray-grpc.service").read_text(encoding="utf-8")
    assert ["systemctl", "stop", "xray-ws"] in calls
    assert ["systemctl", "disable", "xray-ws"] in calls
    assert ["systemctl", "daemon-reload"] in calls
    assert ["systemctl", "enable", "xray-grpc"] in calls
    assert xray.legacy_ws_present() is False
    assert xray.migrate_ws_to_grpc() is False        # идемпотентно


def test_migrate_keeps_disabled_state(paths, monkeypatch):
    calls = _make_legacy(paths, monkeypatch, disabled_ws=True)
    xray.migrate_ws_to_grpc()
    assert config.vwn_conf_get("DISABLED_PROTOCOLS") == "grpc"
    assert ["systemctl", "enable", "xray-grpc"] not in calls   # отключённый не включаем


def test_migrate_keeps_existing_grpc_service(paths, monkeypatch):
    _make_legacy(paths, monkeypatch)
    config.vwn_conf_set("GRPC_SERVICE", "keepme")             # оборванная миграция
    xray.migrate_ws_to_grpc()
    assert config.vwn_conf_get("GRPC_SERVICE") == "keepme"


def test_rebuild_migrates_ws_install(paths, monkeypatch):
    """vwn rebuild на старой установке: gRPC-конфиг, nginx и подписки без WS."""
    _make_legacy(paths, monkeypatch)
    config.vwn_conf_set("SERVER_IP", "1.2.3.4")
    import vwn.modules.sub as _sub
    monkeypatch.setattr(_sub, "rebuild_all_sub_files", lambda *a, **k: 0)
    xray.rebuild_configs()

    svc = config.vwn_conf_get("GRPC_SERVICE")
    gc = json.loads((paths / "xray" / "grpc.json").read_text(encoding="utf-8"))
    assert gc["inbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"] == svc
    assert gc["inbounds"][0]["streamSettings"]["network"] == "grpc"
    assert not (paths / "xray" / "config.json").exists()
    ng = (paths / "xray_loopback.conf").read_text(encoding="utf-8")
    assert f"location ^~ /{svc} {{" in ng
    assert "oldws" not in ng and "Upgrade" not in ng
    assert config.vwn_conf_get("WS_PATH") is None
