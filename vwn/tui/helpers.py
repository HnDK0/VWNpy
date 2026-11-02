"""Общие хелперы для TUI-меню (форматеры, ввод, исполнение, утилиты)."""

import datetime
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from vwn.core import config, shell
from vwn.core.color import console


def b(success: bool, text: str = "") -> str:
    mark = "[bright_green]✓[/]" if success else "[red]✗[/]"
    return f"{mark} {text}"


def service_status(svc: str) -> str:
    active = shell.service_active(svc)
    return b(active, svc.replace(".service", ""))


def cert_days() -> str:
    cert = os.path.join(config.CERT_DIR, "cert.pem")
    if not os.path.exists(cert):
        return "[red]MISSING[/]"
    try:
        r = subprocess.run(["openssl", "x509", "-in", cert, "-noout",
                            "-enddate"], capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return "[red]ERR[/]"
        end_date = r.stdout.strip().replace("notAfter=", "")
        expire = datetime.datetime.strptime(end_date, "%b %d %H:%M:%S %Y %Z")
        days = (expire - datetime.datetime.now()).days
        if days <= 0:
            return f"[red]EXPIRED ({-days}d ago)[/]"
        if days < 15:
            return f"[red]{days}d[/]"
        return f"[bright_green]OK ({days}d)[/]"
    except Exception:
        return "[yellow]?[/]"


def sub_status() -> str:
    sub_dir = "/usr/local/etc/xray/sub"
    if not os.path.isdir(sub_dir):
        return "[red]НЕТ ПОДП[/]"
    txts = [f for f in os.listdir(sub_dir) if f.endswith(".txt")]
    return f"[bright_green]{len(txts)} подп[/]" if txts else "[yellow]0 подп[/]"


def onoff(active: bool) -> str:
    return "[bright_green]ON[/]" if active else "[red]OFF[/]"


def ask_list(title: str, choices: list[str]) -> str:
    console.print(f"\n[bold]{title}[/]")
    for i, c in enumerate(choices):
        console.print(f"  {i}. {c}")
    while True:
        try:
            val = input("> ").strip()
            idx = int(val)
            if 0 <= idx < len(choices):
                return choices[idx]
        except (ValueError, IndexError):
            pass
        console.print("[red]Invalid choice[/]")


def wait_key() -> None:
    input("\nНажмите Enter для продолжения...")


def run_task(title: str, fn) -> None:
    try:
        return fn()
    except subprocess.CalledProcessError as e:
        console.print(f"[red]{title}: {e}[/]")
        if e.stderr:
            console.print(f"[red]{e.stderr[:500]}[/]")
        elif e.output:
            console.print(f"[red]{e.output[:500]}[/]")
    except Exception as e:
        console.print(f"[red]{title}: ошибка — {e}[/]")
    return None


def run_cmd(cmd: str) -> None:
    console.print(f"\n[dim]> {cmd}[/]")
    r = shell.run(cmd, capture=True, check=False)
    if r.stdout:
        console.print(r.stdout[:2000])
    if r.stderr:
        console.print(f"[red]{r.stderr[:500]}[/]")


def parse_ssh_port() -> int:
    import re
    path = "/etc/ssh/sshd_config"
    try:
        with open(path) as f:
            for line in f:
                m = re.match(r"^\s*Port\s+(\d+)\s*$", line)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return 22


def ask_port(prompt: str = "Порт") -> "int | None":
    try:
        return int(input(f"  {prompt}: ").strip())
    except (ValueError, EOFError):
        return None


def show_ufw_status(ufw: dict) -> None:
    if not ufw.get("installed"):
        console.print("  UFW не установлен")
        return
    console.print(f"  Активен: {ufw['active']}")
    for r in ufw.get("rules", []):
        console.print(f"    {r}")


def pick_country(countries: list[tuple[str, str]]) -> str:
    for i, (code, name) in enumerate(countries, 1):
        console.print(f"    {i:>2}. {code} — {name}")
    console.print("  Номер страны (пусто=авто):")
    cn = input("> ").strip()
    country = ""
    if cn.isdigit() and 1 <= int(cn) <= len(countries):
        country = countries[int(cn) - 1][0]
    elif cn:
        import re
        if re.fullmatch(r"[A-Za-z]{2}", cn) and cn.upper() in {c[0] for c in countries}:
            country = cn.upper()
        else:
            console.print("[red]Invalid country code[/]")
            print("Invalid country code")
            return ""
    return country


def ensure_working_country(name: str, countries: list[tuple[str, str]], port: int,
                           apply_fn, current: str, timeout: int = 30) -> str:
    """Пингануть туннель; если за timeout секунд не ответил — предложить другую страну.

    Достаточно одного успешного пинга. Во время ожидания виден спиннер и счётчик,
    отменить можно в любой момент: Enter или Ctrl+C. current — уже применённая
    страна; apply_fn(country) применяет новую. Возвращает итоговую страну ('' = авто).
    """
    from vwn.modules.tunnel_probe import enter_pressed, wait_alive
    country = current
    while True:
        label = country or "авто"
        console.print(f"\n  Проверка {name} (страна: {label}) — Enter или Ctrl+C: отмена")
        with console.status(f"{name}: подключаемся…", spinner="dots") as st:
            res = wait_alive(port, timeout=timeout, progress=st.update,
                             should_stop=enter_pressed)
        if res.alive:
            console.print(f"  [bright_green]{name} жив[/]: ответ за {res.latency_ms} мс "
                          f"(через {res.elapsed:.0f} с)")
            return country
        if res.cancelled:
            console.print(f"  [yellow]Проверка прервана[/] через {res.elapsed:.0f} с "
                          f"(страна: {label}, туннель пока не ответил)")
        else:
            console.print(f"  [red]{name} не отвечает[/] {timeout} с (страна: {label})")
        console.print("  Enter — выбрать другую страну, 1 — оставить эту, 0 — отмена")
        ans = input("> ").strip()
        if ans in ("1", "0"):
            return country
        country = pick_country(countries)
        run_task(f"Применение страны {country or 'авто'}", lambda c=country: apply_fn(c))


def add_domain_flow(tag: str) -> None:
    console.print("  Домен для добавления:")
    d = input("> ").strip()
    if d:
        from vwn.modules._domains import add_domain
        ok = add_domain(tag, d)
        if ok:
            console.print(f"  [bright_green]Добавлен: {d}[/]")
        else:
            console.print("  [yellow]Туннель в режиме Global — домены не применяются. Переключитесь на Split.[/]")


def remove_domain_flow(tag: str) -> None:
    from vwn.modules._domains import list_domains, remove_domain
    doms = list_domains(tag)
    if not doms:
        console.print("  [yellow]Нет доменов[/]")
        return
    for i, d in enumerate(doms, 1):
        console.print(f"  {i}. {d}")
    n = input("> ").strip()
    if n.isdigit() and 1 <= int(n) <= len(doms):
        remove_domain(tag, int(n) - 1)
        console.print("  [bright_green]Удалён[/]")


def restart_xray_services() -> None:
    run_cmd("systemctl restart xray-reality xray-grpc xray-xhttp")


def edit_list_in_editor(file_path: str) -> bool:
    """Открыть файл списка в $EDITOR. Возвращает True если файл был изменён."""
    if not os.path.isfile(file_path):
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        Path(file_path).write_text("")
    editor = os.environ.get("EDITOR") or "nano"
    tmp_path = None
    try:
        with open(file_path) as f:
            content = f.read()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        console.print(f"  Открываю {editor}...")
        result = subprocess.run([editor, tmp_path])
        if result.returncode == 0:
            new_content = Path(tmp_path).read_text()
            shutil.move(tmp_path, file_path)
            tmp_path = None
            return new_content != content
        console.print("  [yellow]Редактирование отменено[/]")
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
