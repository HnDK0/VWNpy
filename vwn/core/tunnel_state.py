"""Состояние туннелей в vwn.conf.

Старые модули (WARP/Relay/Tor/Psiphon/_domains) умеют работать только с
Xray-JSON. Для mihomo-only установки держим это состояние в vwn.conf
(TUNNELS_STATE), а модулям даём runtime-файл, который синхронизируется обратно.
"""

from __future__ import annotations

import json
import os
import tempfile

from vwn.core import config

_KEY = "TUNNELS_STATE"
_RUNTIME_NAME = "vwn-tunnels.json"
_runtime_file: "str | None" = None


def _empty() -> dict:
    return {"outbounds": [], "routing": {"rules": []}}


def load() -> dict:
    raw = config.vwn_conf_get(_KEY)
    if not raw:
        return _empty()
    try:
        data = json.loads(raw)
    except ValueError:
        return _empty()
    if not isinstance(data, dict):
        return _empty()
    data.setdefault("outbounds", [])
    data.setdefault("routing", {}).setdefault("rules", [])
    return data


def save(data: dict) -> None:
    global _runtime_file
    config.vwn_conf_set(_KEY, json.dumps(data, separators=(",", ":"), ensure_ascii=False))
    _runtime_file = None


def _runtime_path() -> str:
    os.makedirs(config.XRAY_DIR, mode=0o700, exist_ok=True)
    return os.path.join(config.XRAY_DIR, _RUNTIME_NAME)


def _write_runtime(path: str, data: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".vwn-tunnels-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def runtime_path() -> str:
    global _runtime_file
    path = _runtime_path()
    if path != _runtime_file:
        _write_runtime(path, load())
        _runtime_file = path
    return path


def _from_xray_configs() -> dict:
    outbounds: list = []
    rules: list = []
    for name in config.XRAY_CONFIG_FILES:
        path = os.path.join(config.XRAY_DIR, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError):
            continue
        outbounds.extend(cfg.get("outbounds", []))
        rules.extend(cfg.get("routing", {}).get("rules", []))
    return {"outbounds": outbounds, "routing": {"rules": rules}}


def sync() -> None:
    path = _runtime_path()
    if _runtime_file == path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
    else:
        data = _from_xray_configs()
    save(data)
