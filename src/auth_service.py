import json
import os
import hmac
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone

import jwt


class AuthService:
    def __init__(self, db_file="auth_users.json", secret_key=None, token_minutes=60):
        self.db_file = Path(db_file)
        self.secret_key = secret_key or os.getenv("AUTH_SECRET_KEY", "test-secret-change-me-32-bytes-long")
        self.algorithm = "HS256"
        self.token_minutes = token_minutes

        if not self.db_file.exists():
            self.db_file.write_text("[]", encoding="utf-8")

        self._ensure_default_admin()

    def _load(self):
        content = self.db_file.read_text(encoding="utf-8").strip()
        if not content:
            return []
        return json.loads(content)

    def _save(self, users):
        self.db_file.write_text(json.dumps(users, indent=2), encoding="utf-8")

    def _hash_password(self, password, salt=None):
        if salt is None:
            salt_bytes = os.urandom(16)
        else:
            salt_bytes = bytes.fromhex(salt)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt_bytes,
            100_000
        )

        return salt_bytes.hex(), password_hash.hex()

    def _verify_password(self, password, stored_password):
        salt, expected_hash = stored_password.split(":")
        _, actual_hash = self._hash_password(password, salt)
        return hmac.compare_digest(actual_hash, expected_hash)

    def _public_user(self, user):
        return {
            "username": user["username"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "roles": user["roles"],
            "enabled": user["enabled"],
        }

    def _find_user(self, users, username):
        for user in users:
            if user["username"] == username:
                return user
        return None

    def _ensure_default_admin(self):
        users = self._load()

        if len(users) == 0:
            salt, password_hash = self._hash_password("admin1234")
            users.append({
                "username": "admin",
                "password": f"{salt}:{password_hash}",
                "first_name": "Default",
                "last_name": "Admin",
                "roles": ["admin"],
                "enabled": True
            })
            self._save(users)

    def register_user(self, username, password, first_name, last_name):
        users = self._load()

        if self._find_user(users, username):
            raise ValueError("Username already exists")

        salt, password_hash = self._hash_password(password)

        user = {
            "username": username,
            "password": f"{salt}:{password_hash}",
            "first_name": first_name,
            "last_name": last_name,
            "roles": ["user"],
            "enabled": True
        }

        users.append(user)
        self._save(users)
        return self._public_user(user)

    def authenticate(self, username, password):
        users = self._load()
        user = self._find_user(users, username)

        if user is None:
            return None

        if not user["enabled"]:
            return None

        if not self._verify_password(password, user["password"]):
            return None

        return self._public_user(user)

    def create_token(self, user):
        now = datetime.now(timezone.utc)

        payload = {
            "sub": user["username"],
            "roles": user["roles"],
            "iat": now,
            "exp": now + timedelta(minutes=self.token_minutes)
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        if isinstance(token, bytes):
            token = token.decode("utf-8")

        return token

    def verify_token(self, token):
        if token.startswith("Bearer "):
            token = token.split(" ", 1)[1]

        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")

        username = payload.get("sub")
        users = self._load()
        user = self._find_user(users, username)

        if user is None:
            raise ValueError("Invalid token")

        if not user["enabled"]:
            raise ValueError("User is deactivated")

        return self._public_user(user)

    def get_user(self, username):
        users = self._load()
        user = self._find_user(users, username)

        if user is None:
            return None

        return self._public_user(user)

    def list_users(self):
        return [self._public_user(user) for user in self._load()]

    def update_user(self, username, first_name=None, last_name=None, roles=None):
        users = self._load()
        user = self._find_user(users, username)

        if user is None:
            return None

        if first_name is not None:
            user["first_name"] = first_name

        if last_name is not None:
            user["last_name"] = last_name

        if roles is not None:
            user["roles"] = roles

        self._save(users)
        return self._public_user(user)

    def delete_user(self, username):
        users = self._load()
        new_users = [user for user in users if user["username"] != username]

        if len(new_users) == len(users):
            return False

        self._save(new_users)
        return True

    def change_password(self, username, old_password, new_password):
        users = self._load()
        user = self._find_user(users, username)

        if user is None:
            return False

        if not self._verify_password(old_password, user["password"]):
            return False

        salt, password_hash = self._hash_password(new_password)
        user["password"] = f"{salt}:{password_hash}"
        self._save(users)
        return True

    def deactivate_user(self, username):
        users = self._load()
        user = self._find_user(users, username)

        if user is None:
            return False

        user["enabled"] = False
        self._save(users)
        return True

    def reactivate_user(self, username):
        users = self._load()
        user = self._find_user(users, username)

        if user is None:
            return False

        user["enabled"] = True
        self._save(users)
        return True
