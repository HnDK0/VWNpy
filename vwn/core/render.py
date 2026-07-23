"""Рендер шаблонов конфигов (замена __KEY__ на значение)."""

from pathlib import Path


def render_config(template: str, output: str, mapping: dict) -> None:
    """Подставить пары KEY→VALUE в шаблон, записать в output.

    В шаблоне плейсхолдеры вида __PORT__, __UUID__ и т.п.
    Работает с любым содержимым (слэши, '&', переносы строк) — без shell-экранирования.
    """
    content = Path(template).read_text(encoding="utf-8")
    for key, val in mapping.items():
        content = content.replace(f"__{key}__", str(val))
    Path(output).write_text(content, encoding="utf-8")


if __name__ == "__main__":
    from pathlib import Path as _P
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        tpl = _P(d) / "t.txt"
        tpl.write_text("port=__PORT__\npath=__PATH__\nx=__PORT__", encoding="utf-8")
        out = _P(d) / "o.txt"
        render_config(str(tpl), str(out), {"PORT": "50001", "PATH": "/v2/api/ab&cd"})
        res = out.read_text(encoding="utf-8")
        assert res == "port=50001\npath=/v2/api/ab&cd\nx=50001", res
    print("render_config: OK")
