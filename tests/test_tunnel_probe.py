"""Проверка живости туннелей: первый успешный пинг — туннель жив."""

import builtins

from vwn.modules import tunnel_probe as tp
from vwn.tui import helpers


class _Clock:
    def __init__(self, mp):
        self.t = 0.0
        self.sleeps = []
        mp.setattr(tp.time, "monotonic", lambda: self.t)
        mp.setattr(tp.time, "sleep", self._sleep)

    def _sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def _results(mp, seq):
    it = iter(seq)
    mp.setattr(tp, "probe_once", lambda port, timeout=5, **kw: next(it))


def test_alive_on_first_ping(monkeypatch):
    clk = _Clock(monkeypatch)
    _results(monkeypatch, [120])
    r = tp.wait_alive(40002)
    assert r.alive and r.attempts == 1 and r.latency_ms == 120 and clk.sleeps == []


def test_alive_after_growing_delays(monkeypatch):
    clk = _Clock(monkeypatch)
    _results(monkeypatch, [None, None, None, 200])
    r = tp.wait_alive(40002, timeout=60)
    assert r.alive and r.attempts == 4
    assert round(sum(clk.sleeps)) == 12  # паузы 3 + 4 + 5, растут


def test_dead_after_timeout(monkeypatch):
    clk = _Clock(monkeypatch)
    monkeypatch.setattr(tp, "probe_once", lambda port, timeout=5, **kw: None)
    r = tp.wait_alive(40002, timeout=20)
    assert not r.alive and not r.cancelled and 19.5 <= r.elapsed <= 21
    assert round(sum(clk.sleeps)) == 20


def test_probe_once_parses_curl(monkeypatch):
    import io

    def fake(out, rc):
        class P:
            returncode = rc
            stdout = io.StringIO(out)
            def poll(self): return rc
        return lambda *a, **k: P()
    monkeypatch.setattr(tp.subprocess, "Popen", fake("204 0.350", 0))
    assert tp.probe_once(1) == 350
    monkeypatch.setattr(tp.subprocess, "Popen", fake("000 0.0", 7))
    assert tp.probe_once(1) is None


def test_cancel_by_key_stops_immediately(monkeypatch):
    _Clock(monkeypatch)
    monkeypatch.setattr(tp, "probe_once", lambda port, timeout=5, **kw: None)
    pressed = iter([False] * 10 + [True])
    r = tp.wait_alive(40002, timeout=60, should_stop=lambda: next(pressed, True))
    assert r.cancelled and not r.alive and r.elapsed < 5


def test_cancel_by_ctrl_c(monkeypatch):
    _Clock(monkeypatch)
    def boom(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(tp, "probe_once", boom)
    r = tp.wait_alive(40002)
    assert r.cancelled and not r.alive


def test_progress_updates_during_wait(monkeypatch):
    _Clock(monkeypatch)
    _results(monkeypatch, [None, 100])
    msgs = []
    tp.wait_alive(40002, timeout=30, progress=msgs.append)
    assert len(msgs) > 5 and all("из 30 с" in m for m in msgs)
    assert any("следующая через" in m for m in msgs)


def test_flow_offers_another_country_when_dead(monkeypatch):
    results = iter([tp.ProbeResult(False, 6, 0, 30), tp.ProbeResult(True, 2, 90, 4)])
    monkeypatch.setattr(tp, "wait_alive", lambda *a, **k: next(results))
    applied = []
    answers = iter(["", "2"])  # Enter -> другая страна; затем номер страны
    monkeypatch.setattr(builtins, "input", lambda *a: next(answers))
    monkeypatch.setattr(helpers, "pick_country",
                        lambda countries: (input("> ") and countries[1][0]))
    country = helpers.ensure_working_country(
        "Psiphon", [("DE", "Germany"), ("NL", "Netherlands")], 40002,
        applied.append, "DE")
    assert country == "NL" and applied == ["NL"]


def test_flow_cancel_goes_to_prompt(monkeypatch):
    monkeypatch.setattr(tp, "wait_alive",
                        lambda *a, **k: tp.ProbeResult(False, 2, 0, 7, cancelled=True))
    monkeypatch.setattr(builtins, "input", lambda *a: "0")
    assert helpers.ensure_working_country("Tor", [("DE", "Germany")], 40003,
                                          lambda c: None, "DE") == "DE"


def test_flow_keep_current_on_choice_1(monkeypatch):
    monkeypatch.setattr(tp, "wait_alive", lambda *a, **k: tp.ProbeResult(False, 6, 0, 30))
    monkeypatch.setattr(builtins, "input", lambda *a: "1")
    assert helpers.ensure_working_country("Tor", [("DE", "Germany")], 40003,
                                          lambda c: None, "DE") == "DE"


def test_flow_alive_returns_without_prompt(monkeypatch):
    monkeypatch.setattr(tp, "wait_alive", lambda *a, **k: tp.ProbeResult(True, 1, 80, 0))
    def _no_input(*a):
        raise AssertionError("не должно спрашивать")
    monkeypatch.setattr(builtins, "input", _no_input)
    assert helpers.ensure_working_country("Tor", [("DE", "Germany")], 40003,
                                          lambda c: None, "DE") == "DE"
