import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from src.auth_service import AuthService


app = FastAPI(title="IT Security Auth API")
bearer_scheme = HTTPBearer(auto_error=False)


class TokenRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    first_name: str
    last_name: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class ActivateRequest(BaseModel):
    username: str


class UpdateUserRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    roles: Optional[list[str]] = None


def get_service():
    db_file = os.getenv("AUTH_DB_FILE", "auth_users.json")
    secret_key = os.getenv("AUTH_SECRET_KEY", "test-secret-change-me-32-bytes-long")
    return AuthService(db_file=db_file, secret_key=secret_key)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    service: AuthService = Depends(get_service)
):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    try:
        return service.verify_token(credentials.credentials)
    except ValueError as error:
        raise HTTPException(status_code=401, detail=str(error))


def require_admin(current_user=Depends(get_current_user)):
    if "admin" not in current_user["roles"]:
        raise HTTPException(status_code=403, detail="Admin role required")

    return current_user


@app.get("/")
def root():
    return {"message": "Auth API is running"}


@app.post("/get_bearer_token")
def get_bearer_token(body: TokenRequest, service: AuthService = Depends(get_service)):
    user = service.authenticate(body.username, body.password)

    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = service.create_token(user)

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@app.post("/register_user")
def register_user(body: RegisterRequest, service: AuthService = Depends(get_service)):
    try:
        return service.register_user(
            username=body.username,
            password=body.password,
            first_name=body.first_name,
            last_name=body.last_name
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/change_password")
def change_password(
    body: ChangePasswordRequest,
    current_user=Depends(get_current_user),
    service: AuthService = Depends(get_service)
):
    changed = service.change_password(
        current_user["username"],
        body.old_password,
        body.new_password
    )

    if not changed:
        raise HTTPException(status_code=400, detail="Password could not be changed")

    return {"changed": True}


@app.post("/deactivate_user")
def deactivate_user(
    current_user=Depends(get_current_user),
    service: AuthService = Depends(get_service)
):
    service.deactivate_user(current_user["username"])
    return {"deactivated": True}


@app.post("/activate_user")
def activate_user(
    body: ActivateRequest,
    admin_user=Depends(require_admin),
    service: AuthService = Depends(get_service)
):
    activated = service.reactivate_user(body.username)

    if not activated:
        raise HTTPException(status_code=404, detail="User not found")

    return {"activated": True}


@app.get("/users")
def list_users(
    admin_user=Depends(require_admin),
    service: AuthService = Depends(get_service)
):
    return service.list_users()


@app.get("/user/{username}")
def get_user(
    username: str,
    current_user=Depends(get_current_user),
    service: AuthService = Depends(get_service)
):
    if current_user["username"] != username and "admin" not in current_user["roles"]:
        raise HTTPException(status_code=403, detail="Not allowed")

    user = service.get_user(username)

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@app.put("/user/{username}")
def update_user(
    username: str,
    body: UpdateUserRequest,
    admin_user=Depends(require_admin),
    service: AuthService = Depends(get_service)
):
    user = service.update_user(
        username=username,
        first_name=body.first_name,
        last_name=body.last_name,
        roles=body.roles
    )

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@app.delete("/user/{username}")
def delete_user(
    username: str,
    admin_user=Depends(require_admin),
    service: AuthService = Depends(get_service)
):
    deleted = service.delete_user(username)

    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")

    return {"deleted": True}
