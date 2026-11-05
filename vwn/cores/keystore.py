"""Единый key store VWNpy.

Основной источник — vwn.conf (0600, @b64). keys.env читается только для
обратной совместимости; новые ключи туда не пишутся.
"""

from __future__ import annotations

import json
import os

from vwn.core import config

_KEYS = (
    "REALITY_PRIVKEY",
    "REALITY_PUBKEY",
    "SHORT_ID",
    "VLESS_DECRYPTION",
    "VLESS_ENCRYPTION",
)


def _legacy_path() -> str:
    return getattr(config, "KEYSTORE", "") or os.path.join(config.XRAY_DIR, "keys.env")


def _read_legacy() -> dict[str, str]:
    path = _legacy_path()
    data: dict[str, str] = {}
    if not os.path.isfile(path):
        return data
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            data[key.strip()] = value
    return data


def get(key: str) -> "str | None":
    value = config.vwn_conf_get(key)
    if value:
        return value
    return _read_legacy().get(key) or None


def set(key: str, value: "str | None", overwrite: bool = False) -> None:
    if not value:
        return
    if not overwrite and config.vwn_conf_get(key):
        return
    config.vwn_conf_set(key, value)


def _read_json(path: str) -> "dict | None":
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def migrate_from_xray_configs() -> None:
    """Перенести Reality private key из xray-reality.json в vwn.conf."""
    if not config.vwn_conf_get("REALITY_PRIVKEY"):
        reality_path = os.path.join(config.XRAY_DIR, "xray-reality.json")
        cfg = _read_json(reality_path) or _read_json(reality_path + ".disabled")
        if cfg:
            try:
                key = cfg["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
            except (KeyError, IndexError, TypeError):
                key = ""
            if key:
                config.vwn_conf_set("REALITY_PRIVKEY", key)
    for key in ("REALITY_PUBKEY", "SHORT_ID", "VLESS_DECRYPTION", "VLESS_ENCRYPTION"):
        if not config.vwn_conf_get(key):
            value = _read_legacy().get(key)
            if value:
                config.vwn_conf_set(key, value)
    legacy = _legacy_path()
    if os.path.isfile(legacy):
        try:
            os.replace(legacy, legacy + ".migrated")
        except OSError:
            pass


def repair_reality_pubkey() -> "str | None":
    """Сверить public key с private и починить vwn.conf при расхождении."""
    migrate_from_xray_configs()
    private = get("REALITY_PRIVKEY")
    if not private:
        return None
    from vwn.modules import xray
    derived = xray.derive_reality_public(private)
    if derived and derived != config.vwn_conf_get("REALITY_PUBKEY"):
        config.vwn_conf_set("REALITY_PUBKEY", derived)
        return derived
    return None


def reality_private_key() -> "str | None":
    migrate_from_xray_configs()
    return get("REALITY_PRIVKEY")


def vless_decryption() -> str:
    return get("VLESS_DECRYPTION") or "none"


def vless_encryption() -> str:
    return get("VLESS_ENCRYPTION") or "none"
