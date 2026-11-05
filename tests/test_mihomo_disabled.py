from vwn.core import config
from vwn.cores import mihomo as mm
from vwn.cores import mihomo_tunnels
from vwn.cores.base import ProvisionParams
from vwn.modules import sub


def _params():
    return ProvisionParams(
        domain="test.local", stub="https://httpbin.org/",
        uuid="u", grpc_service="GunService", xhttp_path="/xhttp",
        ws_path="/ws", short_id="abcd1234", private_key="priv",
    )


def test_write_units_skips_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SYSTEMD_DIR", str(tmp_path / "systemd"))
    monkeypatch.setattr(config, "MIHOMO_DIR", str(tmp_path / "mihomo"))
    monkeypatch.setattr(sub, "get_disabled_protocols", lambda: {"ws"})
    sd = tmp_path / "systemd"
    sd.mkdir()
    (sd / "mihomo-ws.service").write_text("old", encoding="utf-8")
    (sd / "mihomo-ws.service.d").mkdir()
    units = mm.MihomoBackend().write_units(include_ws=True)
    names = {u.rsplit("/", 1)[-1] for u in units}
    assert names == {"mihomo-reality.service", "mihomo-grpc.service",
                     "mihomo-xhttp.service"}
    assert not (sd / "mihomo-ws.service").exists()
    assert not (sd / "mihomo-ws.service.d").exists()


def test_render_nginx_binds_public_443_when_reality_off(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(config, "NGINX_LOOPBACK_CONF", str(tmp_path / "nginx.conf"))
    monkeypatch.setattr(config, "vwn_conf_get",
                        lambda key: "reality" if key == "DISABLED_PROTOCOLS" else None)
    monkeypatch.setattr(sub, "get_disabled_protocols", lambda: {"reality"})
    monkeypatch.setattr("vwn.core.system._write_nginx_main_conf", lambda: None)

    def fake_render(template, output, **kw):
        captured.update(kw)
    monkeypatch.setattr("vwn.modules.xray.write_nginx_loopback_config", fake_render)
    mm._render_nginx(_params())
    assert captured["NGINX_BIND"] == "0.0.0.0"
    assert captured["NGINX_LOOPBACK_PORT"] == 443


def test_socks_listeners_move_to_enabled_service(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MIHOMO_DIR", str(tmp_path / "mihomo"))
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: None)
    monkeypatch.setattr(sub, "get_disabled_protocols", lambda: {"reality"})
    monkeypatch.setattr(
        mihomo_tunnels, "state",
        lambda: ([], [], [{"name": "socks-warp", "type": "socks",
                           "listen": "127.0.0.1", "port": 10808}]),
    )
    paths = mm._render_all(_params(), [{"uuid": "u", "label": "alice"}])
    assert "socks-warp" not in open(paths["reality"], encoding="utf-8").read()
    assert "socks-warp" in open(paths["grpc"], encoding="utf-8").read()


def test_render_nginx_omits_disabled_transports(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(config, "NGINX_LOOPBACK_CONF", str(tmp_path / "nginx.conf"))
    monkeypatch.setattr(sub, "get_disabled_protocols", lambda: {"grpc", "xhttp"})
    monkeypatch.setattr("vwn.core.system._write_nginx_main_conf", lambda: None)

    def fake_render(template, output, **kw):
        captured.update(kw)
    monkeypatch.setattr("vwn.modules.xray.write_nginx_loopback_config", fake_render)
    mm._render_nginx(_params())
    assert captured["GRPC_LOCATION"] == ""
    assert captured["XHTTP_LOCATION"] == ""


def test_render_nginx_loopback_when_reality_on(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(config, "NGINX_LOOPBACK_CONF", str(tmp_path / "nginx.conf"))
    monkeypatch.setattr(sub, "get_disabled_protocols", lambda: set())
    monkeypatch.setattr("vwn.core.system._write_nginx_main_conf", lambda: None)

    def fake_render(template, output, **kw):
        captured.update(kw)
    monkeypatch.setattr("vwn.modules.xray.write_nginx_loopback_config", fake_render)
    mm._render_nginx(_params())
    assert captured["NGINX_BIND"] == "127.0.0.1"
    assert captured["NGINX_LOOPBACK_PORT"] == config.NGINX_LOOPBACK_PORT
