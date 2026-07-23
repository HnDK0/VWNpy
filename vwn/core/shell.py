"""Обёртки subprocess, systemctl-хелперы, индикаторы задач."""

import os
import re
import shlex
import subprocess
import sys

from vwn.core.color import C


def run(cmd, *args, check: bool = True, capture: bool = False, **kw) -> subprocess.CompletedProcess:
    """Безопасный запуск внешней команды (список аргументов, без shell=True)."""
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    if args:
        cmd = list(cmd) + list(args)
    try:
        return subprocess.run(cmd, capture_output=capture, text=True, **kw)
    except FileNotFoundError as exc:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


def systemctl(action: str, service: str) -> bool:
    return run(["systemctl", action, service], check=False).returncode == 0


def service_active(service: str) -> bool:
    return run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0


def nginx_reload() -> None:
    """Единая точка перезагрузки nginx (вместо ~12 разбросанных блоков)."""
    run(["nginx", "-t"], check=True)
    run(["systemctl", "reload", "nginx"], check=False)


def _visible_len(text: str) -> int:
    return len(re.sub(r"\x1b\[[0-9;]*[mABCDJKHf]", "", text))


def pad(text: str, width: int) -> str:
    """Дополнить строку пробелами до width с учётом ANSI-кодов."""
    return text + " " * max(0, width - _visible_len(text))


def run_task(desc: str, func, *args, **kw) -> bool:
    """Запустить func с индикатором >>> [ DONE ] / [ FAIL ]."""
    print(f"\n{C['yellow']}>>> {desc}{C['reset']}")
    try:
        func(*args, **kw)
    except Exception as exc:  # noqa: BLE001 — намеренно ловим всё для индикации
        print(f"[{C['red']} FAIL {C['reset']}] {desc}: {exc}")
        return False
    print(f"[{C['green']} DONE {C['reset']}] {desc}")
    return True


def is_root() -> bool:
    return os.geteuid() == 0


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"{C['red']}ОШИБКА: {msg}{C['reset']}", file=sys.stderr)
    sys.exit(1)
