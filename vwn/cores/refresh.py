"""Обновление активного mihomo после изменения Xray-состояния туннелей."""

from __future__ import annotations


def refresh_if_mihomo() -> bool:
    from vwn.core import config

    if config.core_name() != "mihomo":
        return False
    from vwn.cores import registry

    registry.get_core("mihomo").refresh()
    return True


def after_xray_config_change() -> bool:
    """Сохранить состояние туннелей и обновить mihomo, если он активен."""
    from vwn.core import tunnel_state

    tunnel_state.sync()
    return refresh_if_mihomo()


def restart_active_services() -> None:
    """Перезапустить сервисы только активного ядра.

    systemctl restart поднимает и остановленный юнит, поэтому нельзя
    перезапускать юниты неактивного ядра: под mihomo проснётся Xray и
    займёт loopback-порты 50001-50003, а mihomo потеряет свои listeners.
    """
    from vwn.core import shell
    from . import registry

    backend = registry.get_core()
    for svc in registry.active_services(backend):
        shell.run(["systemctl", "restart", svc], check=False)


def apply_tunnel_change() -> None:
    """Сохранить туннели и перезапустить сервисы активного ядра."""
    if not after_xray_config_change():
        restart_active_services()
