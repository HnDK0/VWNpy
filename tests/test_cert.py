import os

import pytest

from vwn.core import cert, config, system


def test_cert_self_signed(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CERT_DIR", str(tmp_path / "cert"))

    captured = {}

    def fake_run(cmd, *a, **k):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        captured["cmd"] = list(cmd)
        # эмулируем openssl: создаём выходные файлы, чтобы os.chmod не упал
        if "req" in cmd:
            for i, tok in enumerate(cmd):
                if tok in ("-keyout", "-out") and i + 1 < len(cmd):
                    open(cmd[i + 1], "w").close()
        return R()

    monkeypatch.setattr(cert.shell, "run", fake_run)
    monkeypatch.setattr(cert.shell, "die", lambda m: (_ for _ in ()).throw(SystemExit(m)))

    cert.provision_cert("vpn.example.com", "self")

    cmd = captured["cmd"]
    assert cmd[0] == "openssl" and "req" in cmd
    assert "-subj" in cmd and "/CN=vpn.example.com" in cmd
    key_path = str(tmp_path / "cert" / "cert.key")
    assert os.path.exists(key_path)
    if os.name == "posix":  # на Windows os.chmod не задаёт Unix-права
        assert oct(os.stat(key_path).st_mode & 0o777) == "0o600"


def test_cert_unknown_method(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CERT_DIR", str(tmp_path / "cert"))
    with pytest.raises(ValueError):
        cert.provision_cert("x.com", "bogus")


def test_preflight_ok(monkeypatch):
    monkeypatch.setattr(system, "identify_os", lambda: "apt")
    monkeypatch.setattr(system.shell, "is_root", lambda: True)
    assert system.preflight() is True
