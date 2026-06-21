# IT-sikkerhed2026
Skoleprojekt

UNIT-TESTS
## Screenshot af unit-tests

Dette screenshot viser den endelige testkørsel, hvor unit-testene kører korrekt. Resultatet er `6 passed, 2 skipped`.

![Screenshot af unit-tests](images/pytest-resultat.png)

## Screenshot af leg med tests

Dette screenshot viser leg-opgaven, hvor jeg midlertidigt fjernede `@pytest.mark.skip` fra to tests. Resultatet er `2 failed, 6 passed`. Den ene test fejler på en forkert assertion, og den anden crasher med en `RuntimeError`.

![Screenshot af failed og crashed tests](images/pytest-fail-crash.png)