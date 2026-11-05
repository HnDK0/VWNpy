"""Xray backend — адаптер над существующим vwn.modules.xray."""

from __future__ import annotations

import os

from vwn.core import config, shell

from .base import ProvisionParams


class XrayBackend:
    name = "xray"
    bin = config.XRAY_BIN
    config_dir = config.XRAY_DIR
    config_files = config.XRAY_CONFIG_FILES
    services = config.XRAY_SERVICES
    capabilities = frozenset({
        "reality-tcp", "reality-xhttp", "xhttp", "grpc", "ws",
        "vless-enc", "mptcp-in", "mptcp-out", "bt-rule", "tfo",
        "bbr-sockopt",
    })

    def available(self) -> bool:
        return os.path.isfile(self.bin)

    def install(self, version: "str | None" = None) -> None:
        from vwn.core import system

        system.install_xray(version)

    def validate(self, config_path: str) -> None:
        if not os.path.isfile(self.bin):
            return
        r = shell.run([self.bin, "-test", "-config", config_path],
                      capture=True, check=False, timeout=20)
        if r is not None and r.returncode != 0:
            raise RuntimeError(
                f"Xray config invalid: {config_path}\n"
                + (r.stdout or r.stderr or "").strip()[-500:]
            )

    def provision(self, params: ProvisionParams) -> list[str]:
        from vwn.modules import xray

        out = xray.provision_configs(
            params.domain,
            params.stub,
            reality_port=params.reality_port,
            xhttp_mode=params.xhttp_mode,
            private_key=params.private_key,
            vless_encryption=params.vless_encryption,
            reality_mode=params.reality_mode,
        )
        return list(out.get("units", []))

    def rebuild(self, refresh_ip: bool = False) -> None:
        from vwn.modules import xray

        xray.rebuild_configs(refresh_ip=refresh_ip)

    def write_units(self, include_ws: bool = True) -> list[str]:
        from vwn.modules import xray

        return xray.write_xray_units(include_ws=include_ws)

    def apply_users(self, users: list[dict]) -> None:
        from vwn.modules import users as users_mod

        users_mod.apply_users_to_configs()

    def generate_reality_keypair(self) -> tuple[str, str]:
        from vwn.modules import xray

        return xray.generate_reality_keypair()

    def generate_vless_keypair(self, strict: bool = False):
        from vwn.modules import xray

        return xray.generate_vless_keypair(strict=strict)
