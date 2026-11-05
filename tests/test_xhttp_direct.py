from vwn.modules import sub


def test_xhttp_direct_default_on(monkeypatch):
    monkeypatch.setattr(sub.config, "vwn_conf_get", lambda key: None)
    assert sub.xhttp_direct_enabled() is True


def test_xhttp_direct_off(monkeypatch):
    monkeypatch.setattr(
        sub.config, "vwn_conf_get",
        lambda key: "off" if key == "XHTTP_DIRECT" else None,
    )
    assert sub.xhttp_direct_enabled() is False


def test_qr_xhttp_off_exits_nonzero(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from vwn import cli as vcli
    from vwn.core import config
    from vwn.modules import users

    values = {
        "UUID": "u", "SERVER_IP": "1.2.3.4", "DOMAIN": "vpn.example.com",
        "REALITY_PUBKEY": "pub", "SHORT_ID": "sid",
        "GRPC_SERVICE": "GunService", "XHTTP_PATH": "/xhttp",
    }
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: values.get(key))
    monkeypatch.setattr(users, "init_users_file", lambda: None)
    monkeypatch.setattr(users, "list_users", lambda: [])
    monkeypatch.setattr(sub, "xhttp_direct_enabled", lambda: False)
    r = CliRunner().invoke(vcli.cli, ["qr", "--type", "xhttp"])
    assert r.exit_code != 0


def test_qr_xhttp_uses_server_ip(monkeypatch):
    from click.testing import CliRunner
    from vwn import cli as vcli
    from vwn.core import config
    from vwn.modules import users, xray

    values = {
        "UUID": "u", "SERVER_IP": "1.2.3.4", "DOMAIN": "vpn.example.com",
        "REALITY_PUBKEY": "pub", "SHORT_ID": "sid",
        "GRPC_SERVICE": "GunService", "XHTTP_PATH": "/xhttp",
    }
    captured = {}

    def fake_generate(uuid, ip, port, path, domain, name, **kw):
        captured["ip"] = ip
        return "vless://example"

    monkeypatch.setattr(config, "vwn_conf_get", lambda key: values.get(key))
    monkeypatch.setattr(users, "init_users_file", lambda: None)
    monkeypatch.setattr(users, "list_users",
                        lambda: [{"uuid": "u", "label": "default"}])
    monkeypatch.setattr(sub, "xhttp_direct_enabled", lambda: True)
    monkeypatch.setattr(sub, "generate_xhttp_url", fake_generate)
    monkeypatch.setattr(xray, "read_vless_encryption",
                        lambda: {"enabled": False, "encryption": "none"})

    r = CliRunner().invoke(vcli.cli, ["qr", "--type", "xhttp"])

    assert r.exit_code == 0, r.output
    assert captured["ip"] == "1.2.3.4"


def test_xhttp_direct_explicit_on(monkeypatch):
    monkeypatch.setattr(
        sub.config, "vwn_conf_get",
        lambda key: "on" if key == "XHTTP_DIRECT" else None,
    )
    assert sub.xhttp_direct_enabled() is True
