import pytest
from fastapi.testclient import TestClient

from src.auth_api import app, get_service
from src.auth_service import AuthService


@pytest.fixture()
def client(tmp_path):
    service = AuthService(
        db_file=tmp_path / "auth_users.json",
        secret_key="test-secret-key-for-auth-tests-32-bytes-long",
        token_minutes=60
    )

    app.dependency_overrides[get_service] = lambda: service

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def get_token(client, username="admin", password="admin1234"):
    response = client.post(
        "/get_bearer_token",
        json={
            "username": username,
            "password": password
        }
    )

    assert response.status_code == 200
    return response.json()["access_token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_docs_endpoint_is_available(client):
    # Given: Auth API is started.
    # Risk if this fails: The REST API cannot be tested through /docs as required.
    # When: The docs endpoint is opened.
    response = client.get("/docs")

    # Then: Swagger docs are available.
    assert response.status_code == 200


def test_default_admin_is_created_and_can_read_self(client):
    # Given: No user database exists before startup.
    # Risk if this fails: The system has no default admin account.
    token = get_token(client)

    # When: Admin reads its own user data.
    response = client.get("/user/admin", headers=auth_header(token))

    # Then: The default admin exists and has the admin role.
    assert response.status_code == 200
    assert response.json()["username"] == "admin"
    assert response.json()["roles"] == ["admin"]


def test_admin_can_get_security_token(client):
    # Given: A default admin user exists.
    # Risk if this fails: Users cannot receive security tokens.
    # When: Admin logs in with correct credentials.
    response = client.post(
        "/get_bearer_token",
        json={
            "username": "admin",
            "password": "admin1234"
        }
    )

    # Then: A bearer token is returned.
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"


def test_admin_can_change_own_password(client):
    # Given: Admin has the default password.
    # Risk if this fails: Password changes do not protect accounts correctly.
    token = get_token(client)

    # When: Admin changes password.
    response = client.post(
        "/change_password",
        headers=auth_header(token),
        json={
            "old_password": "admin1234",
            "new_password": "NyAdminKode456"
        }
    )

    # Then: Old password no longer works, new password works.
    assert response.status_code == 200

    old_login = client.post(
        "/get_bearer_token",
        json={
            "username": "admin",
            "password": "admin1234"
        }
    )

    new_login = client.post(
        "/get_bearer_token",
        json={
            "username": "admin",
            "password": "NyAdminKode456"
        }
    )

    assert old_login.status_code == 401
    assert new_login.status_code == 200


def test_register_new_account(client):
    # Given: Auth API is running.
    # Risk if this fails: New users cannot be created.
    # When: A new user registers.
    response = client.post(
        "/register_user",
        json={
            "username": "test_user@mail.com",
            "password": "Password123",
            "first_name": "Test",
            "last_name": "User"
        }
    )

    # Then: The account is created as active user.
    assert response.status_code == 200
    assert response.json()["username"] == "test_user@mail.com"
    assert response.json()["roles"] == ["user"]
    assert response.json()["enabled"] is True


def test_user_can_deactivate_own_account(client):
    # Given: A normal user exists and has a token.
    # Risk if this fails: Users cannot deactivate their own account.
    client.post(
        "/register_user",
        json={
            "username": "self_delete@mail.com",
            "password": "Password123",
            "first_name": "Self",
            "last_name": "Delete"
        }
    )

    token = get_token(client, "self_delete@mail.com", "Password123")

    # When: User deactivates own account.
    response = client.post("/deactivate_user", headers=auth_header(token))

    # Then: Login is rejected afterwards.
    assert response.status_code == 200

    login_after_deactivate = client.post(
        "/get_bearer_token",
        json={
            "username": "self_delete@mail.com",
            "password": "Password123"
        }
    )

    assert login_after_deactivate.status_code == 401


def test_admin_can_reactivate_account(client):
    # Given: A user has deactivated itself.
    # Risk if this fails: Admin cannot restore accounts.
    client.post(
        "/register_user",
        json={
            "username": "reactivate@mail.com",
            "password": "Password123",
            "first_name": "React",
            "last_name": "Ivate"
        }
    )

    user_token = get_token(client, "reactivate@mail.com", "Password123")
    client.post("/deactivate_user", headers=auth_header(user_token))

    admin_token = get_token(client)

    # When: Admin reactivates the user.
    response = client.post(
        "/activate_user",
        headers=auth_header(admin_token),
        json={
            "username": "reactivate@mail.com"
        }
    )

    # Then: The user can login again.
    assert response.status_code == 200

    login_after_reactivate = client.post(
        "/get_bearer_token",
        json={
            "username": "reactivate@mail.com",
            "password": "Password123"
        }
    )

    assert login_after_reactivate.status_code == 200


def test_non_admin_cannot_list_users(client):
    # Given: A normal user exists.
    # Risk if this fails: Normal users can access admin data.
    client.post(
        "/register_user",
        json={
            "username": "normal@mail.com",
            "password": "Password123",
            "first_name": "Normal",
            "last_name": "User"
        }
    )

    user_token = get_token(client, "normal@mail.com", "Password123")

    # When: Normal user tries to list all users.
    response = client.get("/users", headers=auth_header(user_token))

    # Then: Access is denied.
    assert response.status_code == 403


def test_admin_can_create_read_update_delete_and_list_users(client):
    # Given: Admin has a valid token.
    # Risk if this fails: REST API CRUD operations do not work correctly.
    admin_token = get_token(client)

    # When: A new user is created.
    create_response = client.post(
        "/register_user",
        json={
            "username": "crud@mail.com",
            "password": "Password123",
            "first_name": "Crud",
            "last_name": "User"
        }
    )

    # Then: Create works.
    assert create_response.status_code == 200

    # When: Admin reads the user.
    read_response = client.get(
        "/user/crud@mail.com",
        headers=auth_header(admin_token)
    )

    # Then: Read works.
    assert read_response.status_code == 200
    assert read_response.json()["username"] == "crud@mail.com"

    # When: Admin updates the user.
    update_response = client.put(
        "/user/crud@mail.com",
        headers=auth_header(admin_token),
        json={
            "first_name": "Updated",
            "last_name": "User",
            "roles": ["user"]
        }
    )

    # Then: Update works.
    assert update_response.status_code == 200
    assert update_response.json()["first_name"] == "Updated"

    # When: Admin lists users.
    list_response = client.get("/users", headers=auth_header(admin_token))

    # Then: List works.
    assert list_response.status_code == 200
    assert len(list_response.json()) >= 2

    # When: Admin deletes the user.
    delete_response = client.delete(
        "/user/crud@mail.com",
        headers=auth_header(admin_token)
    )

    # Then: Delete works.
    assert delete_response.status_code == 200
    assert delete_response.json()["deleted"] is True


def test_invalid_token_is_rejected(client):
    # Given: A fake token is used.
    # Risk if this fails: Attackers can access endpoints with invalid tokens.
    # When: A protected endpoint is called.
    response = client.get(
        "/users",
        headers={
            "Authorization": "Bearer fake.invalid.token"
        }
    )

    # Then: Access is rejected.
    assert response.status_code == 401
