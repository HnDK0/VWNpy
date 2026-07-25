"""Обёртки subprocess, systemctl-хелперы, индикаторы задач."""

import os
import re
import shlex
import subprocess
import sys

from vwn.core.color import C, console, _err


def run(cmd, *args, check: bool = True, capture: bool = False, **kw) -> subprocess.CompletedProcess:
    """Безопасный запуск внешней команды (список аргументов, без shell=True)."""
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    if args:
        cmd = list(cmd) + list(args)
    try:
        if capture and "stdout" not in kw:
            kw["stdout"] = subprocess.PIPE
        if capture and "stderr" not in kw:
            kw["stderr"] = subprocess.PIPE
        r = subprocess.run(cmd, text=True, **kw)
        if r.returncode != 0 and capture and r.stderr:
            _err.print(f"{C['red']}stderr: {r.stderr[:500]}{C['reset']}")
        return r
    except FileNotFoundError as exc:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        if check:
            raise
        return subprocess.CompletedProcess(cmd, -1, exc.stdout or "", exc.stderr or "")


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
    console.print(f"\n{C['yellow']}>>> {desc}{C['reset']}")
    try:
        func(*args, **kw)
    except Exception as exc:  # noqa: BLE001 — намерено ловим всё для индикации
        console.print(f"[{C['red']} FAIL {C['reset']}] {desc}: {exc}")
        return False
    console.print(f"[{C['green']} DONE {C['reset']}] {desc}")
    return True


def is_root() -> bool:
    return os.geteuid() == 0


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    _err.print(f"{C['red']}ОШИБКА: {msg}{C['reset']}")
    sys.exit(1)
