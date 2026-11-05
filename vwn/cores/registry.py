"""Реестр ядер: активное ядро и доступные backend'ы."""

from __future__ import annotations

from vwn.core import config

CORE_NAMES = config.CORE_NAMES

_BACKENDS: dict[str, object] = {}


def _build(name: str):
    if name == "xray":
        from .xray_backend import XrayBackend

        return XrayBackend()
    if name == "mihomo":
        from .mihomo import MihomoBackend

        return MihomoBackend()
    raise ValueError(f"Неизвестное ядро: {name}")


def get_core(name: "str | None" = None):
    """Вернуть backend активного (или указанного) ядра."""
    key = (name or config.core_name()).strip().lower()
    if key not in CORE_NAMES:
        raise ValueError(f"Неизвестное ядро: {key}")
    if key not in _BACKENDS:
        _BACKENDS[key] = _build(key)
    return _BACKENDS[key]


def available_cores() -> dict[str, object]:
    return {name: get_core(name) for name in CORE_NAMES}


def active_services(backend, disabled: "set[str] | None" = None) -> tuple[str, ...]:
    if disabled is None:
        from vwn.modules.sub import get_disabled_protocols
        disabled = get_disabled_protocols()
    return tuple(
        svc for svc in backend.services
        if svc.rsplit("-", 1)[-1] not in disabled
    )


def sanitize() -> "str | None":
    """Починить CORE, если он указывает на отсутствующее ядро.

    Возвращает текст предупреждения или None. Используется при restore.
    """
    current = config.vwn_conf_get("CORE") or config.CORE_DEFAULT
    if current not in CORE_NAMES:
        config.vwn_conf_set("CORE", config.CORE_DEFAULT)
        return f"CORE={current} неизвестен, переключено на {config.CORE_DEFAULT}"
    if current != config.CORE_DEFAULT and not get_core(current).available():
        if get_core(config.CORE_DEFAULT).available():
            config.vwn_conf_set("CORE", config.CORE_DEFAULT)
            return f"Ядро {current} не установлено, переключено на {config.CORE_DEFAULT}"
    return None
