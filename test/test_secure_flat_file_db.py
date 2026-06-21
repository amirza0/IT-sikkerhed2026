from src.secure_flat_file_db import SecureFlatFileDB, generate_key


def create_test_db(tmp_path):
    return SecureFlatFileDB(tmp_path / "users.json", generate_key())


def test_create_user_encrypts_personal_data_and_hashes_password(tmp_path):
    # Given: En tom flat file database.
    # Risiko hvis testen fejler: Persondata eller passwords kan blive gemt i klartekst.
    db = create_test_db(tmp_path)

    # When: En bruger oprettes.
    db.create_user(1, "Amir", "Khan", "Testvej", "12", "MitKode123", True)

    # Then: Persondata er krypteret, og passwordet er hashed.
    raw_file_content = (tmp_path / "users.json").read_text(encoding="utf-8")

    assert "Amir" not in raw_file_content
    assert "Khan" not in raw_file_content
    assert "Testvej" not in raw_file_content
    assert "MitKode123" not in raw_file_content
    assert "password" in raw_file_content


def test_read_user_decrypts_data_when_needed(tmp_path):
    # Given: En bruger er gemt krypteret i databasen.
    # Risiko hvis testen fejler: Systemet kan ikke bruge data korrekt efter kryptering.
    db = create_test_db(tmp_path)
    db.create_user(1, "Amir", "Khan", "Testvej", "12", "MitKode123")

    # When: Brugeren læses fra databasen.
    user = db.read_user(1)

    # Then: Data dekrypteres kun ved læsning.
    assert user["first_name"] == "Amir"
    assert user["last_name"] == "Khan"
    assert user["address"] == "Testvej"
    assert user["password"] == "<hashed>"


def test_authenticate_user_with_correct_password(tmp_path):
    # Given: En bruger findes med et hashed password.
    # Risiko hvis testen fejler: Login kan afvise korrekte brugere.
    db = create_test_db(tmp_path)
    db.create_user(1, "Amir", "Khan", "Testvej", "12", "MitKode123")

    # When: Brugeren logger ind med korrekt password.
    result = db.authenticate(1, "MitKode123")

    # Then: Login godkendes.
    assert result is True


def test_authenticate_user_with_wrong_password_fails(tmp_path):
    # Given: En bruger findes med et hashed password.
    # Risiko hvis testen fejler: En angriber kan få adgang med forkert password.
    db = create_test_db(tmp_path)
    db.create_user(1, "Amir", "Khan", "Testvej", "12", "MitKode123")

    # When: Brugeren logger ind med forkert password.
    result = db.authenticate(1, "ForkertKode")

    # Then: Login afvises.
    assert result is False


def test_update_password_changes_login_credentials(tmp_path):
    # Given: En bruger har et eksisterende password.
    # Risiko hvis testen fejler: Passwordskift virker ikke korrekt.
    db = create_test_db(tmp_path)
    db.create_user(1, "Amir", "Khan", "Testvej", "12", "MitKode123")

    # When: Passwordet opdateres.
    db.update_password(1, "NyKode456")

    # Then: Det gamle password virker ikke, men det nye virker.
    assert db.authenticate(1, "MitKode123") is False
    assert db.authenticate(1, "NyKode456") is True


def test_delete_user_removes_user_from_flat_file(tmp_path):
    # Given: En bruger findes i databasen.
    # Risiko hvis testen fejler: Slettede brugere kan stadig ligge i systemet.
    db = create_test_db(tmp_path)
    db.create_user(1, "Amir", "Khan", "Testvej", "12", "MitKode123")

    # When: Brugeren slettes.
    deleted = db.delete_user(1)

    # Then: Brugeren findes ikke længere.
    assert deleted is True
    assert db.read_user(1) is None


def test_disabled_user_cannot_login(tmp_path):
    # Given: En bruger er deaktiveret.
    # Risiko hvis testen fejler: Deaktiverede brugere kan stadig få adgang.
    db = create_test_db(tmp_path)
    db.create_user(1, "Amir", "Khan", "Testvej", "12", "MitKode123", enabled=False)

    # When: Brugeren forsøger at logge ind.
    result = db.authenticate(1, "MitKode123")

    # Then: Login afvises.
    assert result is False


def test_clear_decrypted_data_removes_plaintext_from_memory(tmp_path):
    # Given: En bruger er læst og findes midlertidigt dekrypteret i hukommelsen.
    # Risiko hvis testen fejler: Følsomme data kan blive liggende i hukommelsen.
    db = create_test_db(tmp_path)
    db.create_user(1, "Amir", "Khan", "Testvej", "12", "MitKode123")

    # When: De dekrypterede data fjernes fra objektet.
    user = db.read_user(1)
    cleared_user = db.clear_decrypted_data(user)

    # Then: Følsomme felter er fjernet fra hukommelsen.
    assert cleared_user["first_name"] is None
    assert cleared_user["last_name"] is None
    assert cleared_user["address"] is None
    assert cleared_user["street_number"] is None


def test_list_users_returns_decrypted_user_overview(tmp_path):
    # Given: Flere brugere findes i flat file databasen.
    # Risiko hvis testen fejler: Systemet kan ikke vise en korrekt oversigt over brugere.
    db = create_test_db(tmp_path)
    db.create_user(1, "Amir", "Khan", "Testvej", "12", "MitKode123")
    db.create_user(2, "Sara", "Ali", "Hovedvej", "20", "KodeSara123")

    # When: Brugere listes.
    users = db.list_users()

    # Then: Listen viser brugerne korrekt.
    assert len(users) == 2
    assert users[0]["first_name"] == "Amir"
    assert users[1]["first_name"] == "Sara"
