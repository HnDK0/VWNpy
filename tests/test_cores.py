import json
import os

from vwn.core import config
from vwn.cores import keystore, registry, versions
from vwn.cores.base import ProvisionParams
from vwn.cores import mihomo as mihomo_mod


def test_registry_default_is_xray(monkeypatch):
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: None)
    assert config.core_name() == "xray"
    backend = registry.get_core()
    assert backend.name == "xray"
    assert "reality-tcp" in backend.capabilities
    assert "bt-rule" in backend.capabilities


def test_registry_mihomo_capabilities():
    backend = registry.get_core("mihomo")
    assert backend.name == "mihomo"
    assert "xhttp" in backend.capabilities
    assert "vless-enc" in backend.capabilities
    assert "bt-rule" not in backend.capabilities


def test_keystore_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "KEYSTORE", str(tmp_path / "keys.env"))
    keystore.set("REALITY_PRIVKEY", "priv")
    keystore.set("SHORT_ID", "abcd")
    assert keystore.get("REALITY_PRIVKEY") == "priv"
    assert keystore.get("SHORT_ID") == "abcd"
    assert config.vwn_conf_get("REALITY_PRIVKEY") == "priv"


def test_keystore_migrates_private_key(tmp_path, monkeypatch):
    xray_dir = tmp_path / "xray"
    xray_dir.mkdir()
    monkeypatch.setattr(config, "XRAY_DIR", str(xray_dir))
    monkeypatch.setattr(config, "KEYSTORE", str(xray_dir / "keys.env"))
    cfg = {
        "inbounds": [{
            "streamSettings": {"realitySettings": {"privateKey": "from-json"}}
        }]
    }
    (xray_dir / "xray-reality.json").write_text(json.dumps(cfg), encoding="utf-8")
    keystore.migrate_from_xray_configs()
    assert config.vwn_conf_get("REALITY_PRIVKEY") == "from-json"


def test_repair_reality_pubkey(monkeypatch):
    config.vwn_conf_set("REALITY_PRIVKEY", "priv")
    config.vwn_conf_set("REALITY_PUBKEY", "old")
    monkeypatch.setattr("vwn.modules.xray.derive_reality_public",
                        lambda priv: "new")
    assert keystore.repair_reality_pubkey() == "new"
    assert config.vwn_conf_get("REALITY_PUBKEY") == "new"


def test_bad_core_falls_back_to_default(monkeypatch):
    monkeypatch.setattr(config, "vwn_conf_get",
                        lambda key: "weird" if key == "CORE" else None)
    assert config.core_name() == "xray"
    assert "CORE=weird" in registry.sanitize()


def test_versions_asset_names():
    assert versions.asset_name("v1.19.33", "amd64-compatible") == \
        "mihomo-linux-amd64-compatible-v1.19.33.gz"
    assert versions.asset_name("v1.19.33", "arm64") == \
        "mihomo-linux-arm64-v1.19.33.gz"


def _params():
    return ProvisionParams(
        domain="test.local",
        stub="https://httpbin.org/",
        uuid="11111111-1111-1111-1111-111111111111",
        grpc_service="GunService",
        xhttp_path="/xhttp",
        reality_xhttp_path="/reality-xhttp",
        ws_path="/ws",
        short_id="abcd1234",
        private_key="priv",
        decryption="mlkem768x25519plus.native.600s." + "a" * 24,
        reality_mode="tcp",
    )


def test_mihomo_renders_four_configs(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MIHOMO_DIR", str(tmp_path / "mihomo"))
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path / "xray"))
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: None)
    users = [{"uuid": "u-1", "label": "alice"}]
    paths = mihomo_mod._render_all(_params(), users)
    assert set(paths) == {"reality", "grpc", "xhttp", "ws"}
    reality = open(paths["reality"], encoding="utf-8").read()
    assert "reality-config:" in reality
    assert "dest: \"127.0.0.1:8443\"" in reality
    assert "proxy: \"DIRECT\"" in reality
    assert "flow: \"xtls-rprx-vision\"" in reality
    xhttp = open(paths["xhttp"], encoding="utf-8").read()
    assert "allow-insecure:" not in xhttp
    assert "decryption:" in xhttp
    assert "xhttp-config:" in xhttp
    assert "direct-nameserver:" in xhttp
    assert "- \"system\"" in xhttp
    grpc = open(paths["grpc"], encoding="utf-8").read()
    assert "grpc-service-name: \"GunService\"" in grpc


def test_mihomo_allows_insecure_only_without_vless_encryption(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MIHOMO_DIR", str(tmp_path / "mihomo"))
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: None)
    p = ProvisionParams(**{**_params().__dict__, "decryption": "none"})
    paths = mihomo_mod._render_all(p, [{"uuid": "u-1", "label": "alice"}])
    xhttp = open(paths["xhttp"], encoding="utf-8").read()
    assert "allow-insecure: true" in xhttp
    assert "decryption:" not in xhttp


def test_mihomo_reality_xhttp_has_no_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MIHOMO_DIR", str(tmp_path / "mihomo"))
    monkeypatch.setattr(config, "vwn_conf_get", lambda key: None)
    p = ProvisionParams(**{**_params().__dict__, "reality_mode": "xhttp"})
    paths = mihomo_mod._render_all(p, [{"uuid": "u-1", "label": "alice"}])
    text = open(paths["reality"], encoding="utf-8").read()
    assert "flow:" not in text
    assert "xhttp-config:" in text
    assert "path: \"/reality-xhttp\"" in text
    assert "path: \"/xhttp\"" not in text


def test_manage_configs_opens_active_core_files(tmp_path, monkeypatch):
    import vwn.tui.menu as menu
    from vwn.cores import registry as core_registry

    class Backend:
        name = "mihomo"

    mihomo_dir = tmp_path / "mihomo"
    for key in ("reality", "grpc", "xhttp", "ws"):
        path = mihomo_dir / key / f"{key}.yaml"
        path.parent.mkdir(parents=True)
        path.write_text("test: true\n", encoding="utf-8")

    calls = []
    monkeypatch.setattr(config, "MIHOMO_DIR", str(mihomo_dir))
    monkeypatch.setattr(core_registry, "get_core", lambda: Backend())
    monkeypatch.setattr(menu, "wait_key", lambda: None)
    monkeypatch.setattr(menu.subprocess, "run",
                        lambda argv, *a, **k: calls.append(argv))
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    answers = iter(["1", "0"])

    menu._manage_configs()

    assert calls
    assert calls[0][-1].endswith("mihomo/reality/reality.yaml")


def test_mihomo_units(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SYSTEMD_DIR", str(tmp_path / "systemd"))
    monkeypatch.setattr(config, "MIHOMO_DIR", str(tmp_path / "mihomo"))
    backend = mihomo_mod.MihomoBackend()
    units = backend.write_units(include_ws=True)
    assert len(units) == 4
    text = open(units[0], encoding="utf-8").read()
    assert "User=mihomo" in text
    assert "ExecStartPre=" in text
    assert units[0].endswith("mihomo-reality.service")


def test_rollback_mihomo(tmp_path, monkeypatch):
    dest = tmp_path / "bin" / "mihomo"
    prev = tmp_path / "bin" / "mihomo.prev"
    prev.mkdir(parents=True)
    (prev / "mihomo.v1.19.32").write_text("old-binary", encoding="utf-8")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("new-binary", encoding="utf-8")
    version = versions.rollback_mihomo(str(dest))
    assert version == "v1.19.32"
    assert dest.read_text(encoding="utf-8") == "old-binary"
    assert config.vwn_conf_get("MIHOMO_VERSION") == "v1.19.32"
