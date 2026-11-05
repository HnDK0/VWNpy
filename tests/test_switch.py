from vwn.cores import switch


class FakeBackend:
    def __init__(self, name, services):
        self.name = name
        self.services = services

    def available(self):
        return True

    def rebuild(self, refresh_ip=False):
        self.rebuilt = True

    def write_units(self, include_ws=True):
        return []

    def install(self, version=None):
        pass


def test_switch_sets_core_before_rebuild_and_starts_target(monkeypatch):
    state = {"core": "xray"}
    events = []
    old = FakeBackend("xray", ("xray-reality",))
    new = FakeBackend("mihomo", ("mihomo-reality",))

    def get_core(name=None):
        return new if (name or state["core"]) == "mihomo" else old

    monkeypatch.setattr(switch.registry, "get_core", get_core)
    monkeypatch.setattr(switch.config, "core_name", lambda: state["core"])
    monkeypatch.setattr(switch.config, "vwn_conf_set",
                        lambda k, v: state.__setitem__("core", v) if k == "CORE" else None)
    monkeypatch.setattr(switch.config, "vwn_conf_del", lambda k: None)
    monkeypatch.setattr(switch.keystore, "migrate_from_xray_configs", lambda: None)
    monkeypatch.setattr(switch.time, "sleep", lambda *_: None)
    monkeypatch.setattr(switch.shell, "service_active", lambda svc: True)
    monkeypatch.setattr(switch.shell, "run",
                        lambda *a, **k: events.append(tuple(a[0]) if a else ()))

    orig_rebuild = new.rebuild
    def rebuild(refresh_ip=False):
        assert state["core"] == "mihomo"
        orig_rebuild(refresh_ip)
    monkeypatch.setattr(new, "rebuild", rebuild)

    switch.switch_to("mihomo")
    assert state["core"] == "mihomo"
    assert new.rebuilt is True
    assert ("systemctl", "start", "mihomo-reality") in events
    assert ("systemctl", "daemon-reload") in events


def test_switch_rolls_back_when_target_service_fails(monkeypatch):
    state = {"core": "xray"}
    events = []
    old = FakeBackend("xray", ("xray-reality",))
    new = FakeBackend("mihomo", ("mihomo-reality",))

    def get_core(name=None):
        return new if (name or state["core"]) == "mihomo" else old

    monkeypatch.setattr(switch.registry, "get_core", get_core)
    monkeypatch.setattr(switch.config, "core_name", lambda: state["core"])
    monkeypatch.setattr(switch.config, "vwn_conf_set",
                        lambda k, v: state.__setitem__("core", v) if k == "CORE" else None)
    monkeypatch.setattr(switch.config, "vwn_conf_del", lambda k: None)
    monkeypatch.setattr(switch.keystore, "migrate_from_xray_configs", lambda: None)
    monkeypatch.setattr(switch.time, "sleep", lambda *_: None)
    monkeypatch.setattr(switch.shell, "service_active", lambda svc: False)
    monkeypatch.setattr(switch.shell, "run",
                        lambda *a, **k: events.append(tuple(a[0]) if a else ()))

    try:
        switch.switch_to("mihomo")
    except RuntimeError as exc:
        assert "откат" in str(exc)
    else:
        raise AssertionError("должен быть откат")
    assert state["core"] == "xray"
    assert old.rebuilt is True
    assert ("systemctl", "start", "xray-reality") in events


def test_switch_blocks_mihomo_when_mptcp_on(monkeypatch):
    old = FakeBackend("xray", ("xray-reality",))
    new = FakeBackend("mihomo", ("mihomo-reality",))
    monkeypatch.setattr(switch.registry, "get_core",
                        lambda name=None: new if (name or "xray") == "mihomo" else old)
    monkeypatch.setattr(switch.config, "vwn_conf_get",
                        lambda key: "on" if key == "MPTCP" else None)

    try:
        switch.switch_to("mihomo")
    except RuntimeError as exc:
        assert "MPTCP" in str(exc)
    else:
        raise AssertionError("mihomo должен блокироваться при MPTCP=on")


def test_recover_pending_does_not_accept_partial_start(monkeypatch):
    state = {"core": "mihomo"}
    values = {"CORE_SWITCH_PENDING": "mihomo", "CORE_SWITCH_FROM": "xray"}
    old = FakeBackend("xray", ("xray-reality",))
    new = FakeBackend("mihomo", ("mihomo-reality", "mihomo-grpc"))
    monkeypatch.setattr(switch.registry, "get_core",
                        lambda name=None: new if (name or state["core"]) == "mihomo" else old)
    monkeypatch.setattr(switch.config, "vwn_conf_get", lambda k: values.get(k))
    monkeypatch.setattr(switch.config, "vwn_conf_set",
                        lambda k, v: state.__setitem__("core", v) if k == "CORE" else None)
    monkeypatch.setattr(switch.config, "vwn_conf_del", lambda k: values.pop(k, None))
    monkeypatch.setattr(switch.shell, "service_active",
                        lambda svc: svc == "mihomo-reality")
    monkeypatch.setattr(switch.shell, "run", lambda *a, **k: None)
    switch.recover_pending()
    assert state["core"] == "xray"
    assert old.rebuilt is True


def test_recover_pending_restores_old(monkeypatch):
    state = {"core": "mihomo"}
    values = {"CORE_SWITCH_PENDING": "mihomo", "CORE_SWITCH_FROM": "xray"}
    events = []
    old = FakeBackend("xray", ("xray-reality",))
    new = FakeBackend("mihomo", ("mihomo-reality",))

    def get_core(name=None):
        return new if (name or state["core"]) == "mihomo" else old

    monkeypatch.setattr(switch.registry, "get_core", get_core)
    monkeypatch.setattr(switch.config, "vwn_conf_get", lambda k: values.get(k))
    monkeypatch.setattr(switch.config, "vwn_conf_set",
                        lambda k, v: state.__setitem__("core", v) if k == "CORE" else None)
    monkeypatch.setattr(switch.config, "vwn_conf_del",
                        lambda k: values.pop(k, None))
    monkeypatch.setattr(switch.shell, "service_active", lambda svc: False)
    monkeypatch.setattr(switch.shell, "run",
                        lambda *a, **k: events.append(tuple(a[0]) if a else ()))

    switch.recover_pending()
    assert state["core"] == "xray"
    assert old.rebuilt is True
    assert "CORE_SWITCH_PENDING" not in values
    assert ("systemctl", "start", "xray-reality") in events


def test_switch_restores_old_when_units_fail(monkeypatch):
    state = {"core": "xray"}
    events = []
    old = FakeBackend("xray", ("xray-reality",))
    new = FakeBackend("mihomo", ("mihomo-reality",))

    def get_core(name=None):
        return new if (name or state["core"]) == "mihomo" else old

    def fail_units(include_ws=True):
        raise OSError("read-only /etc/systemd/system")

    monkeypatch.setattr(switch.registry, "get_core", get_core)
    monkeypatch.setattr(switch.config, "core_name", lambda: state["core"])
    monkeypatch.setattr(switch.config, "vwn_conf_set",
                        lambda k, v: state.__setitem__("core", v) if k == "CORE" else None)
    monkeypatch.setattr(switch.config, "vwn_conf_del", lambda k: None)
    monkeypatch.setattr(switch.keystore, "migrate_from_xray_configs", lambda: None)
    monkeypatch.setattr(switch.shell, "service_active", lambda svc: True)
    monkeypatch.setattr(switch.shell, "run",
                        lambda *a, **k: events.append(tuple(a[0]) if a else ()))
    monkeypatch.setattr(new, "write_units", fail_units)

    try:
        switch.switch_to("mihomo")
    except OSError:
        pass
    else:
        raise AssertionError("должна быть ошибка записи unit")
    assert state["core"] == "xray"
    assert old.rebuilt is True
    assert not any(e[:2] == ("systemctl", "start") and e[2] == "mihomo-reality"
                   for e in events)
