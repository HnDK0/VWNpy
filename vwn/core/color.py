"""Цветной вывод через Rich Console."""

from rich.console import Console

console = Console()
_err = Console(stderr=True)

_COLORS = {
    "red": "[red]",
    "green": "[green]",
    "yellow": "[yellow]",
    "cyan": "[cyan]",
    "reset": "[/]",
}

C = dict(_COLORS)


def color(text: str, name: str) -> str:
    """Обрамить text тегом Rich-разметки name."""
    return f"{C.get(name, '')}{text}{C['reset']}"
