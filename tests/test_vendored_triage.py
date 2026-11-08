"""The bundled AI triage engine (triage/VENDORED.md) is the released version, and complete."""

import triage
from triage import engine, guards


def test_bundled_engine_is_the_pinned_release():
    assert triage.__version__ == "0.2.3"
    assert triage.__file__.replace("\\", "/").endswith("triage/__init__.py")


def test_bundled_engine_has_what_soar_lite_uses():
    assert engine.MODES == ("naive", "hardened", "guarded", "strict")
    assert callable(engine.triage) and callable(guards.apply_strict)
