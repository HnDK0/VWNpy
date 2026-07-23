"""ANSI-цвета (без i18n — только русский вывод)."""

import os

_COLORS = {
    "red": "\033[1;31m",
    "green": "\033[1;32m",
    "yellow": "\033[1;33m",
    "cyan": "\033[1;36m",
    "reset": "\033[0m",
}


def init_colors() -> dict:
    """Вернуть словарь цветов; вне терминала — пустые строки."""
    if os.isatty(1) and os.environ.get("TERM"):
        return dict(_COLORS)
    return {k: "" for k in _COLORS}


C = init_colors()


def color(text: str, name: str) -> str:
    """Обрамить text цветом name (red/green/yellow/cyan/reset)."""
    return f"{C.get(name, '')}{text}{C['reset']}"
