import pytest


def is_valid_password(password):
    has_valid_length = 8 <= len(password) <= 16
    has_uppercase = any(char.isupper() for char in password)
    has_number = any(char.isdigit() for char in password)

    return has_valid_length and has_uppercase and has_number


@pytest.mark.parametrize(
    "password, expected",
    [
        ("MitKode123", True),
        ("123", False),
        ("mitkode123", False),
        ("MitKode", False),
        ("MITKODE1234567890", False),
    ],
)
def test_password_equivalence_classes(password, expected):
    assert is_valid_password(password) == expected


@pytest.mark.parametrize(
    "password, expected",
    [
        ("Kod1234", False),
        ("Kode1234", True),
        ("MitKode123456789", True),
        ("MitKode1234567890", False),
    ],
)
def test_password_boundary_values(password, expected):
    assert is_valid_password(password) == expected


@pytest.mark.parametrize(
    "password, has_uppercase, has_number, length_ok, expected",
    [
        ("MitKode123", True, True, True, True),
        ("mitkode123", False, True, True, False),
        ("MitKode", True, False, False, False),
        ("Mit123", True, True, False, False),
        ("MITKODE1234567890", True, True, False, False),
    ],
)
def test_password_decision_table(password, has_uppercase, has_number, length_ok, expected):
    actual_has_uppercase = any(char.isupper() for char in password)
    actual_has_number = any(char.isdigit() for char in password)
    actual_length_ok = 8 <= len(password) <= 16

    assert actual_has_uppercase == has_uppercase
    assert actual_has_number == has_number
    assert actual_length_ok == length_ok
    assert is_valid_password(password) == expected
