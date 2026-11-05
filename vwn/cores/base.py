"""Ядро-независимые контракты VWNpy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ProvisionParams:
    """Параметры, нужные любому backend'у для генерации конфигов."""

    domain: str
    stub: str
    uuid: str
    grpc_service: str
    xhttp_path: str
    ws_path: str
    short_id: str
    private_key: str
    grpc_mode: str = "gun"
    xhttp_mode: str = "auto"
    xhttp_cdn_mode: str = "auto"
    reality_mode: str = "tcp"
    reality_port: int = 443
    fallback_port: int = 8443
    reality_decryption: str = "none"
    decryption: str = "none"
    server_ip: str = ""
    sniffer: bool = True
    vless_encryption: "bool | None" = None


@runtime_checkable
class CoreBackend(Protocol):
    """Минимальный контракт ядра. Реализации могут расширять его."""

    name: str
    bin: str
    config_dir: str
    config_files: tuple[str, ...]
    services: tuple[str, ...]
    capabilities: frozenset[str]

    def available(self) -> bool: ...

    def install(self, version: "str | None" = None) -> None: ...

    def validate(self, config_path: str) -> None: ...

    def provision(self, params: ProvisionParams) -> list[str]: ...

    def rebuild(self, refresh_ip: bool = False) -> None: ...

    def write_units(self, include_ws: bool = True) -> list[str]: ...

    def apply_users(self, users: list[dict]) -> None: ...

    def generate_reality_keypair(self) -> tuple[str, str]: ...

    def generate_vless_keypair(self, strict: bool = False) -> "tuple[str | None, str | None]": ...
