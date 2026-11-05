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
