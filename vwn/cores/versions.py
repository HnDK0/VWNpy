"""Установка и версионирование mihomo."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import platform
import shutil
import tempfile
from urllib.request import Request, urlopen

from vwn.core import config

MIHOMO_DEFAULT_VERSION = "v1.19.33"
MIHOMO_REPO = "MetaCubeX/mihomo"
API_URL = f"https://api.github.com/repos/{MIHOMO_REPO}/releases"


def current_version() -> str:
    return config.vwn_conf_get("MIHOMO_VERSION") or MIHOMO_DEFAULT_VERSION


def _arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64", "i686", "i386"):
        if machine in ("i686", "i386"):
            return "386"
        try:
            cpuinfo = open("/proc/cpuinfo", encoding="utf-8").read()
        except OSError:
            cpuinfo = ""
        return "amd64" if "avx2" in cpuinfo else "amd64-compatible"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    if machine.startswith("armv7"):
        return "armv7"
    if machine.startswith("armv6"):
        return "armv6"
    if machine.startswith("riscv64"):
        return "riscv64"
    raise RuntimeError(f"mihomo: неподдерживаемая архитектура {machine}")


def asset_name(version: str, arch: "str | None" = None) -> str:
    return f"mihomo-linux-{arch or _arch()}-{version}.gz"


def _release(version: str) -> dict:
    req = Request(f"{API_URL}/tags/{version}",
                  headers={"User-Agent": "vwnpy"})
    with urlopen(req, timeout=30) as resp:
        return json.load(resp)


def latest_version() -> str:
    req = Request(f"{API_URL}/latest", headers={"User-Agent": "vwnpy"})
    with urlopen(req, timeout=30) as resp:
        return json.load(resp)["tag_name"]


def _pick_asset(release: dict, name: str) -> dict:
    for asset in release.get("assets", []):
        if asset.get("name") == name:
            return asset
    raise RuntimeError(f"mihomo: ассет {name} не найден в релизе {release.get('tag_name')}")


def install_mihomo(version: "str | None" = None, dest: "str | None" = None) -> str:
    """Скачать пиннингованную версию, проверить sha256 и установить."""
    version = version or current_version()
    dest = dest or config.MIHOMO_BIN
    name = asset_name(version)
    release = _release(version)
    asset = _pick_asset(release, name)
    digest = asset.get("digest") or ""
    if not digest.startswith("sha256:"):
        raise RuntimeError(f"mihomo: у ассета {name} нет sha256 digest — установка отменена")
    expected = digest.split(":", 1)[1].lower()

    req = Request(asset["browser_download_url"],
                  headers={"User-Agent": "vwnpy"})
    with urlopen(req, timeout=120) as resp:
        raw = resp.read()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise RuntimeError(f"mihomo: sha256 mismatch ({actual} != {expected})")

    binary = gzip.decompress(raw)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.isfile(dest):
        prev_dir = os.path.join(os.path.dirname(dest), "mihomo.prev")
        os.makedirs(prev_dir, exist_ok=True)
        prev_version = current_version()
        shutil.copy2(dest, os.path.join(prev_dir,
                                        os.path.basename(dest) + "." + prev_version))
    fd, tmp = tempfile.mkstemp(prefix="mihomo.", dir=os.path.dirname(dest))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(binary)
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

    config.vwn_conf_set("MIHOMO_VERSION", version)
    return version


def rollback_mihomo(dest: "str | None" = None) -> str:
    """Вернуть предыдущий бинарь mihomo из mihomo.prev."""
    dest = dest or config.MIHOMO_BIN
    prev_dir = os.path.join(os.path.dirname(dest), "mihomo.prev")
    if not os.path.isdir(prev_dir):
        raise RuntimeError("mihomo.prev не найден — откатывать нечего")
    candidates = [
        os.path.join(prev_dir, name)
        for name in os.listdir(prev_dir)
        if name.startswith("mihomo.") and os.path.isfile(os.path.join(prev_dir, name))
    ]
    if not candidates:
        raise RuntimeError("mihomo.prev пуст — откатывать нечего")
    latest = max(candidates, key=os.path.getmtime)
    version = os.path.basename(latest).split(".", 1)[1]
    shutil.copy2(latest, dest)
    os.chmod(dest, 0o755)
    config.vwn_conf_set("MIHOMO_VERSION", version)
    return version
