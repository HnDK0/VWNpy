"""Подменю приватности."""

from vwn.core.color import console
from vwn.tui.helpers import run_task, wait_key


def manage_privacy() -> None:
    from vwn.modules.privacy import status, enable, disable, shred
    while True:
        s = status()
        console.print(f"\n[bold]Приватность[/]")
        console.print(f"  Режим: {'[bright_green]ВКЛ[/]' if s['enabled'] else '[red]ВЫКЛ[/]'} (компонентов: {s['score']}/4)")
        console.print("  1. Включить (откл. логи, tmpfs, shred)")
        console.print("  2. Выключить (восстановить логи)")
        console.print("  3. Уничтожить логи сейчас")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            run_task("Включение приватности", enable)
        elif val == "2":
            run_task("Выключение приватности", disable)
        elif val == "3":
            run_task("Уничтожение логов", shred)
        wait_key()
