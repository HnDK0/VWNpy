"""Валидация ввода (порт / домен / URL)."""

import re

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,}$"
)
# ИСПРАВЛЕНИЕ бага 2.1: оригинал требовал пробел после 1-го символа хоста
# (^https://[a-zA-Z0-9] ) и всегда падал. Корректный шаблон без пробела.
URL_RE = re.compile(r"^https://[A-Za-z0-9._/-]+$")
PORT_RE = re.compile(r"^[0-9]+$")


def validate_port(value, min_v: int = 1, max_v: int = 65535) -> int:
    if not PORT_RE.match(str(value)):
        raise ValueError(f"Порт должен быть числом: {value!r}")
    v = int(value)
    if not (min_v <= v <= max_v):
        raise ValueError(f"Порт {v} вне диапазона {min_v}-{max_v}")
    return v


def validate_domain(value: str) -> str:
    if not DOMAIN_RE.match(value or ""):
        raise ValueError(f"Некорректный домен: {value!r}")
    return value


def validate_url(value: str) -> str:
    if not URL_RE.match(value or ""):
        raise ValueError(f"URL должен быть https://... : {value!r}")
    return value


if __name__ == "__main__":
    assert validate_port(443) == 443
    assert validate_port("8443", 443, 65535) == 8443
    try:
        validate_port(70000)
        raise SystemExit("BUG: порт вне диапазона принят")
    except ValueError:
        pass
    assert validate_domain("vpn.example.com") == "vpn.example.com"
    assert validate_url("https://www.openstreetmap.org/") == "https://www.openstreetmap.org/"
    try:
        validate_url("https://a b")  # пробел недопустим
        raise SystemExit("BUG: URL с пробелом принят")
    except ValueError:
        pass
    print("validate: OK")
