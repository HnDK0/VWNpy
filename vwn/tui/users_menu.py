"""Подменю управления пользователями."""

from vwn.core import config, shell
from vwn.core.color import console
from vwn.tui.helpers import run_task, wait_key


def manage_users() -> None:
    from vwn.modules import users as usr
    from vwn.modules.sub import rebuild_all_sub_files, build_user_sub_file
    usr.init_users_file()
    while True:
        users_list = usr.list_users()
        console.print(f"\n[bold]Пользователи[/]  ({len(users_list)})")
        if users_list:
            for i, u in enumerate(users_list, 1):
                uuid_short = u["uuid"][:8]
                tok_short = u["token"][:8] if u["token"] else "?"
                console.print(f"  {i:2d}. {usr.get_cached_flag()} {u['label']:20s}  {uuid_short}...  tok={tok_short}")
        console.print("")
        console.print("  1. Добавить пользователя")
        console.print("  2. Удалить пользователя")
        console.print("  3. Переименовать")
        console.print("  4. Сменить UUID (rekey)")
        console.print("  5. Сменить токен подписки")
        console.print("  6. QR + URL подписки")
        console.print("  7. Пересобрать все подписки")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            label = input("  Имя пользователя (пусто=авто): ").strip() or None
            r = run_task("Добавление", lambda: usr.add_user(label))
            if r:
                console.print(f"  [bright_green]{r['label']} — {r['uuid']}[/]")
        elif val == "2":
            if len(users_list) <= 1:
                console.print("  [red]Нельзя удалить последнего пользователя[/]")
                wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]")
                wait_key(); continue
            u = users_list[n - 1]
            if input(f"  Удалить '{u['label']}'? (y/N): ").strip().lower() != "y":
                continue
            run_task("Удаление", lambda: usr.remove_user(n))
        elif val == "3":
            if not users_list:
                console.print("  [yellow]Нет пользователей[/]"); wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]"); wait_key(); continue
            new_label = input(f"  Новое имя [{users_list[n-1]['label']}]: ").strip()
            if new_label:
                run_task("Переименование", lambda: usr.rename_user(n, new_label))
        elif val == "4":
            if not users_list:
                console.print("  [yellow]Нет пользователей[/]"); wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]"); wait_key(); continue
            if input(f"  Сменить UUID для '{users_list[n-1]['label']}'? (y/N): ").strip().lower() == "y":
                new_uuid = usr.rekey_user(n)
                if new_uuid:
                    console.print(f"  [bright_green]Новый UUID: {new_uuid}[/]")
        elif val == "5":
            if not users_list:
                console.print("  [yellow]Нет пользователей[/]"); wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]"); wait_key(); continue
            new_token = usr.reissue_token(n)
            if new_token:
                console.print(f"  [bright_green]Новый токен: {new_token}[/]")
        elif val == "6":
            if not users_list:
                console.print("  [yellow]Нет пользователей[/]"); wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]"); wait_key(); continue
            u = users_list[n - 1]
            dom = config.vwn_conf_get("DOMAIN") or "?"
            server_ip = config.vwn_conf_get("SERVER_IP") or "?"
            build_user_sub_file(u["uuid"], u["label"], u["token"], dom, server_ip)
            sub_url = usr.get_sub_url(u["label"], u["token"]) or f"https://{dom}/sub/{usr.sub_filename(u['label'], u['token'])}"
            safe = usr.safe_label(u["label"])
            html_url = f"https://{dom}/sub/{safe}_{u['token']}.html"
            console.print(f"\n  {usr.get_cached_flag()} [bold]{u['label']}[/]")
            console.print(f"  UUID: {u['uuid']}")
            console.print(f"  Sub URL: [bright_green]{sub_url}[/]")
            console.print(f"  HTML:    [bright_green]{html_url}[/]")
            r = shell.run(["qrencode", "-t", "ANSIUTF8"], input=sub_url,
                          capture=True, check=False)
            if r.stdout:
                console.print(r.stdout)
        elif val == "7":
            run_task("Пересборка подписок", rebuild_all_sub_files)
        wait_key()
