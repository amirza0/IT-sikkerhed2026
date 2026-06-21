import pytest


def test_leg_passer():
    assert "zealand".upper() == "ZEALAND"


@pytest.mark.skip(reason="Leg: fjern skip for at se testen fejle")
def test_leg_fejler_med_vilje():
    assert 2 + 2 == 5


@pytest.mark.skip(reason="Leg: fjern skip for at se testen crashe")
def test_leg_crasher_med_vilje():
    raise RuntimeError("Test crasher med vilje")
