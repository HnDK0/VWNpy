import pytest

from vwn.core import system
from vwn.install import InstallOptions, parse_auto_args, validate_auto_options


def test_nginx_has_grpc_module(monkeypatch):
    # nginx 1.30+: grpc включён по умолчанию и не имеет --with- формы,
    # поэтому в -V его нет — модуль считаем присутствующим.
    class R:  # stdout пуст, nginx -V пишет в stderr
        stdout = ""
        stderr = "configure arguments: --with-http_v2_module --with-http_ssl_module"

    monkeypatch.setattr(system.shell, "run", lambda *a, **k: R())
    assert system.nginx_has_grpc_module() is True

    # явно отключённый grpc
    class R2:
        stdout = ""
        stderr = "configure arguments: --with-http_v2_module --without-http_grpc_module"

    monkeypatch.setattr(system.shell, "run", lambda *a, **k: R2())
    assert system.nginx_has_grpc_module() is False


def test_parse_basic():
    opts = parse_auto_args(["--domain", "vpn.example.com", "--bbr", "--no-warp"])
    assert opts.domain == "vpn.example.com"
    assert opts.bbr is True
    assert opts.no_warp is True
    assert opts.reality_port == 443  # умолчание новой архитектуры


def test_parse_int_flags():
    opts = parse_auto_args(["--domain", "x.com", "--reality-port", "8443",
                            "--ssh-port", "2222"])
    assert opts.reality_port == 8443
    assert opts.ssh_port == 2222


def test_parse_unknown_collected():
    opts = parse_auto_args(["--domain", "x.com", "--foo", "bar"])
    assert "--foo" in opts.unknown


def test_validate_ok_minimal():
    validate_auto_options(parse_auto_args(["--domain", "vpn.example.com"]))


def test_validate_domain_required():
    with pytest.raises(ValueError):
        validate_auto_options(InstallOptions())


def test_validate_cf_requires_email_and_key():
    with pytest.raises(ValueError):
        validate_auto_options(parse_auto_args(
            ["--domain", "x.com", "--cert-method", "cf"]))


def test_validate_cf_ok():
    validate_auto_options(parse_auto_args(
        ["--domain", "x.com", "--cert-method", "cf",
         "--cf-email", "a@b.com", "--cf-key", "KEY"]))


def test_validate_psiphon_warp_conflict():
    with pytest.raises(ValueError):
        validate_auto_options(parse_auto_args(
            ["--domain", "x.com", "--psiphon-warp", "--no-warp"]))


def test_validate_psiphon_country_uppercased():
    opts = parse_auto_args(["--domain", "x.com", "--psiphon", "--psiphon-country", "de"])
    validate_auto_options(opts)
    assert opts.psiphon_country == "DE"


def test_validate_psiphon_country_bad():
    with pytest.raises(ValueError):
        validate_auto_options(parse_auto_args(
            ["--domain", "x.com", "--psiphon-country", "XYZ"]))


def test_validate_reality_port_range():
    with pytest.raises(ValueError):
        validate_auto_options(parse_auto_args(
            ["--domain", "x.com", "--reality-port", "80"]))
