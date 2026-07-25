import vwn.core.config as config
from vwn.core.validate import validate_port, validate_domain, validate_url
from vwn.core.render import render_config
from vwn.core.system import find_free_port, generate_random_path, \
    parse_nginx_version, version_ge, NGINX_TARGET_VER, \
    _xray_arch_tag, _parse_xray_version


def test_validate_port_ok():
    assert validate_port(443) == 443
    assert validate_port("8443", 443, 65535) == 8443


def test_validate_port_out_of_range():
    import pytest
    with pytest.raises(ValueError):
        validate_port(70000)
    with pytest.raises(ValueError):
        validate_port("abc")


def test_validate_domain():
    assert validate_domain("vpn.example.com") == "vpn.example.com"
    import pytest
    with pytest.raises(ValueError):
        validate_domain("not a domain")
    with pytest.raises(ValueError):
        validate_domain("http://x.com")


def test_validate_url_fixed_bug():
    # ИСПРАВЛЕНИЕ бага 2.1: раньше всегда падало
    assert validate_url("https://www.openstreetmap.org/") == "https://www.openstreetmap.org/"
    assert validate_url("https://a.b/c_d-e") == "https://a.b/c_d-e"
    import pytest
    with pytest.raises(ValueError):
        validate_url("https://a b")          # пробел недопустим
    with pytest.raises(ValueError):
        validate_url("http://example.com")  # только https


def test_render_config(tmp_path):
    tpl = tmp_path / "t.txt"
    tpl.write_text("port=__PORT__\npath=__PATH__\nx=__PORT__", encoding="utf-8")
    out = tmp_path / "o.txt"
    render_config(str(tpl), str(out), {"PORT": "50001", "PATH": "/v2/api/ab&cd"})
    assert out.read_text(encoding="utf-8") == "port=50001\npath=/v2/api/ab&cd\nx=50001"


def test_find_free_port():
    p = find_free_port(50001, 50001)
    assert p == 50001


def test_generate_random_path():
    p = generate_random_path()
    assert p.startswith("/v2/api/")
    assert len(p) == len("/v2/api/") + 32  # secrets.token_hex(16) -> 32 hex


def test_parse_nginx_version():
    assert parse_nginx_version("nginx version: nginx/1.30.0") == (1, 30, 0)
    assert parse_nginx_version("nginx/1.29.4 (built from src)") == (1, 29, 4)
    assert parse_nginx_version("no version here") is None


def test_version_ge():
    assert version_ge((1, 30, 0), (1, 30, 0)) is True
    assert version_ge((1, 30, 1), (1, 30, 0)) is True
    assert version_ge((1, 29, 9), (1, 30, 0)) is False
    assert version_ge(None, (1, 30, 0)) is False
    assert version_ge(parse_nginx_version(f"nginx/{NGINX_TARGET_VER}"),
                      (1, 30, 0)) is True


def test_xray_arch_tag():
    assert _xray_arch_tag("x86_64") == "64"
    assert _xray_arch_tag("aarch64") == "arm64-v8a"
    assert _xray_arch_tag("armv7l") == "arm32-v7a"
    assert _xray_arch_tag("riscv64") == ""


def test_parse_xray_version():
    assert _parse_xray_version('{"tag_name": "v25.3.1"}') == "v25.3.1"
    assert _parse_xray_version("no version") == ""


def test_config_crud(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path))
    assert config.vwn_conf_get("DOMAIN") is None
    config.vwn_conf_set("DOMAIN", "vpn.example.com")
    assert config.vwn_conf_get("DOMAIN") == "vpn.example.com"
    # перезапись
    config.vwn_conf_set("DOMAIN", "new.example.com")
    assert config.vwn_conf_get("DOMAIN") == "new.example.com"
    config.vwn_conf_del("DOMAIN")
    assert config.vwn_conf_get("DOMAIN") is None


def test_config_b64_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path))
    # значение с спецсимволами кодируется в @b64
    config.vwn_conf_set("TOKEN", "ab@c/d e")
    assert config.vwn_conf_get("TOKEN") == "ab@c/d e"
    raw = (tmp_path / "vwn.conf").read_text(encoding="utf-8")
    assert "@b64:" in raw
    assert "ab@c/d e" not in raw.splitlines()[0]


def test_config_invalid_key(tmp_path, monkeypatch):
    import pytest
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path))
    with pytest.raises(ValueError):
        config.vwn_conf_set("bad key", "x")
