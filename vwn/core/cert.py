"""Выпуск SSL-сертификата для loopback-nginx (WS/XHTTP клиенты валидируют TLS).

Reality на 443 сертификат НЕ требует (TLS без сертификата), поэтому
сертификат нужен только nginx-у на 127.0.0.1:8443.

Методы:
  self       — самоподписанный (openssl, без сети; для тестов/быстрого старта)
  standalone — acme.sh --issue --standalone (нужен свободный 80-й порт)
  cf         — acme.sh --issue --dns dns_cf (нужны CF_Email + CF_Key)
"""

import os

from vwn.core import config, shell


def provision_cert(domain: str, method: str = "self",
                   cf_email: str = "", cf_key: str = "") -> None:
    """Выпустить/обновить сертификат в CERT_DIR (cert.pem + cert.key)."""
    os.makedirs(config.CERT_DIR, exist_ok=True)
    cert = os.path.join(config.CERT_DIR, "cert.pem")
    key = os.path.join(config.CERT_DIR, "cert.key")

    if method == "self":
        _self_signed(domain, cert, key)
    elif method in ("standalone", "cf"):
        _acme_issue(domain, method, cert, key, cf_email, cf_key)
    else:
        raise ValueError(f"Неизвестный cert-method: {method}")


def _self_signed(domain: str, cert: str, key: str) -> None:
    # SAN обязателен: Go/xray отвергает сертификаты только с CN (legacy Common Name)
    shell.run(["openssl", "req", "-x509", "-nodes", "-days", "3650",
               "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
               "-subj", f"/CN={domain}",
               "-addext", f"subjectAltName=DNS:{domain}"], check=True)
    os.chmod(key, 0o600)
    # для self-signed цепочка доверия == сам сертификат
    chain = os.path.join(config.CERT_DIR, "chain.pem")
    with open(cert, "rb") as fh:
        data = fh.read()
    with open(chain, "wb") as fh:
        fh.write(data)
    os.chmod(chain, 0o644)


def _acme_issue(domain: str, method: str, cert: str, key: str,
                cf_email: str, cf_key: str) -> None:
    home = os.path.expanduser("~")
    acme = os.path.join(home, ".acme.sh", "acme.sh")
    if not os.path.exists(acme):
        _ensure_acme(home)

    issue = [acme, "--issue", "-d", domain, "--server", "letsencrypt"]
    if method == "cf":
        if not (cf_email and cf_key):
            shell.die("Для cert-method=cf нужны --cf-email и --cf-key")
        env = dict(os.environ, CF_Email=cf_email, CF_Key=cf_key)
        issue += ["--dns", "dns_cf"]
    else:  # standalone
        from vwn.modules.security import ufw_allow, ufw_deny
        ufw_allow(80, "tcp", "acme.sh standalone")
        env = os.environ
        issue += ["--standalone"]
    try:
        shell.run(issue, check=True, env=env)
    finally:
        if method == "standalone":
            from vwn.modules.security import ufw_deny
            ufw_deny(80, "tcp")

    shell.run([acme, "--install-cert", "-d", domain,
               "--fullchain-file", cert, "--key-file", key,
               "--ca-file", os.path.join(config.CERT_DIR, "chain.pem")],
              check=True)
    os.chmod(key, 0o600)
    os.chmod(os.path.join(config.CERT_DIR, "chain.pem"), 0o644)


def _ensure_acme(home: str) -> None:
    acme = os.path.join(home, ".acme.sh", "acme.sh")
    if os.path.exists(acme):
        return
    # fallback: git clone если curl https://get.acme.sh не работает (DNS хостера)
    installer = os.path.join(home, "acme.sh-install.sh")
    ok = shell.run(["curl", "-fsSL", "--connect-timeout", "10",
                    "https://get.acme.sh", "-o", installer], check=False)
    if ok.returncode == 0:
        shell.run(["sh", installer], check=True)
        if os.path.exists(installer):
            os.remove(installer)
    else:
        if not shell.run(["which", "git"], check=False).returncode == 0:
            from vwn.core import system
            system.install_package("git")
        shell.run(["git", "clone", "--depth=1",
                    "https://github.com/acmesh-official/acme.sh.git",
                    os.path.join(home, "acme.sh")], check=True)
        shell.run(["sh", os.path.join(home, "acme.sh", "acme.sh"), "--install"],
                  check=True)
    if not os.path.exists(acme):
        shell.die("acme.sh не установился: ни curl, ни git не сработали")
    # acme.sh defaults to ZeroSSL; switch to Let's Encrypt
    shell.run([acme, "--set-default-ca", "--server", "letsencrypt"],
              check=False)
