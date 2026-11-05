from click.testing import CliRunner

from vwn.core import config
from vwn.cores import versions
from vwn.cores.mihomo import MihomoBackend
from vwn.install import InstallOptions, _provision_core
from vwn.modules import users


def test_provision_mihomo_writes_configs_and_keys(tmp_path, monkeypatch):
    root = tmp_path
    monkeypatch.setattr(config, "XRAY_DIR", str(root / "xray"))
    monkeypatch.setattr(config, "MIHOMO_DIR", str(root / "mihomo"))
    monkeypatch.setattr(config, "MIHOMO_BIN", str(root / "bin" / "mihomo"))
    monkeypatch.setattr(config, "SYSTEMD_DIR", str(root / "systemd"))
    monkeypatch.setattr(config, "NGINX_LOOPBACK_CONF", str(root / "xray.conf"))
    monkeypatch.setattr(config, "KEYSTORE", str(root / "xray" / "keys.env"))
    monkeypatch.setattr(users, "USERS_FILE", str(root / "xray" / "users.conf"))
    monkeypatch.setattr(MihomoBackend, "generate_reality_keypair",
                        lambda self: ("priv", "pub"))
    monkeypatch.setattr(MihomoBackend, "generate_vless_keypair",
                        lambda self, strict=False: ("dec", "enc"))
    monkeypatch.setattr("vwn.core.system.generate_grpc_service", lambda: "GunService")
    monkeypatch.setattr("vwn.core.system.generate_random_path", lambda: "rand")

    opts = InstallOptions(domain="test.local", stub="https://httpbin.org/",
                          core="mihomo")
    _provision_core(opts)

    assert config.core_name() == "mihomo"
    assert config.vwn_conf_get("REALITY_PRIVKEY") == "priv"
    assert config.vwn_conf_get("VLESS_DECRYPTION") == "dec"


def test_update_mihomo_command_installs_latest(monkeypatch):
    from vwn import cli as vcli

    calls = {}
    monkeypatch.setattr(versions, "latest_version", lambda: "v9.9.9")
    monkeypatch.setattr(versions, "current_version", lambda: "v9.9.8")
    monkeypatch.setattr(versions, "install_mihomo",
                        lambda v: calls.setdefault("version", v) or v)
    monkeypatch.setattr(config, "core_name", lambda: "xray")
    r = CliRunner().invoke(vcli.cli, ["update-mihomo"])
    assert r.exit_code == 0, r.output
    assert calls["version"] == "v9.9.9"


def test_provision_mihomo_overwrites_stale_private_key(tmp_path, monkeypatch):
    root = tmp_path
    monkeypatch.setattr(config, "XRAY_DIR", str(root / "xray"))
    monkeypatch.setattr(config, "MIHOMO_DIR", str(root / "mihomo"))
    monkeypatch.setattr(config, "MIHOMO_BIN", str(root / "bin" / "mihomo"))
    monkeypatch.setattr(config, "SYSTEMD_DIR", str(root / "systemd"))
    monkeypatch.setattr(config, "NGINX_LOOPBACK_CONF", str(root / "xray.conf"))
    monkeypatch.setattr(config, "KEYSTORE", str(root / "xray" / "keys.env"))
    monkeypatch.setattr(users, "USERS_FILE", str(root / "xray" / "users.conf"))
    config.vwn_conf_set("REALITY_PRIVKEY", "old-priv")
    config.vwn_conf_set("REALITY_PUBKEY", "old-pub")
    monkeypatch.setattr(MihomoBackend, "generate_reality_keypair",
                        lambda self: ("new-priv", "new-pub"))
    monkeypatch.setattr(MihomoBackend, "generate_vless_keypair",
                        lambda self, strict=False: ("dec", "enc"))
    monkeypatch.setattr("vwn.core.system.generate_grpc_service", lambda: "GunService")
    monkeypatch.setattr("vwn.core.system.generate_random_path", lambda: "rand")

    _provision_core(InstallOptions(domain="test.local", stub="https://httpbin.org/",
                                   core="mihomo"))
    assert config.vwn_conf_get("REALITY_PRIVKEY") == "new-priv"
    assert config.vwn_conf_get("REALITY_PUBKEY") == "new-pub"
    for key in ("reality", "grpc", "xhttp", "ws"):
        assert (root / "mihomo" / key / f"{key}.yaml").is_file()
    assert (root / "systemd" / "mihomo-reality.service").is_file()
    assert (root / "xray.conf").is_file()
