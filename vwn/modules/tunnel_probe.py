"""Проверка живости SOCKS-туннелей (Psiphon, Tor) после применения страны.

Туннель обычно поднимается за 10-15 секунд, поэтому пингуем с нарастающей
паузой (3, 4, 5, 6, 6… с) и считаем туннель живым после первого же успеха.
Если за отведённое время ответа нет — туннель мёртв.

Ожидание «неблокирующее»: прогресс обновляется несколько раз в секунду, а
отменить можно в любой момент (Enter или Ctrl+C), в том числе посреди curl.
"""

import select
import subprocess
import sys
import time
from dataclasses import dataclass

PROBE_URL = "https://www.gstatic.com/generate_204"
DELAYS = (3, 4, 5, 6)  # паузы между попытками, дальше повторяется последняя
STEP = 0.2             # шаг опроса: так часто обновляется прогресс и проверяется отмена


@dataclass
class ProbeResult:
    alive: bool
    attempts: int
    latency_ms: int = 0
    elapsed: float = 0.0
    cancelled: bool = False


def enter_pressed() -> bool:
    """True, если пользователь нажал Enter (строка из stdin прочитана и сброшена)."""
    try:
        if not sys.stdin.isatty():
            return False
        ready, _, _ = select.select([sys.stdin], [], [], 0)
        if ready:
            sys.stdin.readline()
            return True
    except (OSError, ValueError):
        pass
    return False


def _parse(out: str, returncode: int) -> int | None:
    parts = (out or "").split()
    if returncode != 0 or len(parts) != 2 or parts[0] not in ("200", "204"):
        return None
    try:
        return int(float(parts[1]) * 1000)
    except ValueError:
        return None


def probe_once(port: int, timeout: int = 5, should_stop=None, tick=None) -> int | None:
    """Один запрос через SOCKS5 127.0.0.1:port. Возвращает мс или None при неудаче/отмене."""
    try:
        p = subprocess.Popen(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
             "--max-time", str(timeout), "--socks5-hostname", f"127.0.0.1:{port}",
             PROBE_URL],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except OSError:
        return None
    deadline = time.monotonic() + timeout + 2
    while p.poll() is None:
        if (should_stop and should_stop()) or time.monotonic() > deadline:
            p.kill()
            p.wait()
            return None
        if tick:
            tick()
        time.sleep(STEP)
    return _parse(p.stdout.read() if p.stdout else "", p.returncode)


def wait_alive(port: int, timeout: int = 30, try_timeout: int = 5,
               progress=None, should_stop=None) -> ProbeResult:
    """Пинговать туннель, пока не ответит (живой), не выйдет timeout с (мёртв) или не отменят.

    progress(msg) — вызывается несколько раз в секунду с текстом текущего состояния.
    should_stop() — True отменяет проверку сразу. Ctrl+C тоже отменяет.
    """
    say = progress or (lambda m: None)
    start = time.monotonic()
    attempts = 0
    stopped = False

    def stop() -> bool:
        nonlocal stopped
        if not stopped and should_stop and should_stop():
            stopped = True
        return stopped

    def status(what: str) -> None:
        say(f"{what} · прошло {time.monotonic() - start:.0f} из {timeout} с")

    def result(alive: bool, ms: int = 0) -> ProbeResult:
        return ProbeResult(alive, attempts, ms, time.monotonic() - start, cancelled=stopped)

    try:
        while True:
            attempts += 1
            ms = probe_once(port, try_timeout, should_stop=stop,
                            tick=lambda: status(f"попытка {attempts}: пингуем"))
            if ms is not None:
                return result(True, ms)
            if stop() or time.monotonic() - start >= timeout:
                return result(False)
            delay = min(DELAYS[min(attempts - 1, len(DELAYS) - 1)],
                        timeout - (time.monotonic() - start))
            end = time.monotonic() + delay
            while time.monotonic() < end:
                if stop():
                    return result(False)
                status(f"попытка {attempts}: нет ответа, следующая через "
                       f"{max(end - time.monotonic(), 0):.0f} с")
                time.sleep(min(STEP, max(end - time.monotonic(), 0.001)))
    except KeyboardInterrupt:
        stopped = True
        return result(False)
