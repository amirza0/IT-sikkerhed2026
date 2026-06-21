import json
import os
import hashlib
import hmac
from pathlib import Path
from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key()


class SecureFlatFileDB:
    def __init__(self, file_path, key):
        self.file_path = Path(file_path)
        self.fernet = Fernet(key)

        if not self.file_path.exists():
            self.file_path.write_text("[]", encoding="utf-8")

    def _load(self):
        return json.loads(self.file_path.read_text(encoding="utf-8"))

    def _save(self, data):
        self.file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _encrypt(self, value):
        return self.fernet.encrypt(str(value).encode()).decode()

    def _decrypt(self, value):
        return self.fernet.decrypt(value.encode()).decode()

    def _hash_password(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        else:
            salt = bytes.fromhex(salt)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            100_000
        )

        return salt.hex(), password_hash.hex()

    def _verify_password(self, password, stored_password):
        salt, expected_hash = stored_password.split(":")
        _, actual_hash = self._hash_password(password, salt)
        return hmac.compare_digest(actual_hash, expected_hash)

    def create_user(self, person_id, first_name, last_name, address, street_number, password, enabled=True):
        data = self._load()

        if any(user["person_id"] == person_id for user in data):
            raise ValueError("User already exists")

        salt, password_hash = self._hash_password(password)

        user = {
            "person_id": person_id,
            "first_name": self._encrypt(first_name),
            "last_name": self._encrypt(last_name),
            "address": self._encrypt(address),
            "street_number": self._encrypt(street_number),
            "password": f"{salt}:{password_hash}",
            "enabled": enabled
        }

        data.append(user)
        self._save(data)

    def read_user(self, person_id):
        data = self._load()

        for user in data:
            if user["person_id"] == person_id:
                return {
                    "person_id": user["person_id"],
                    "first_name": self._decrypt(user["first_name"]),
                    "last_name": self._decrypt(user["last_name"]),
                    "address": self._decrypt(user["address"]),
                    "street_number": self._decrypt(user["street_number"]),
                    "password": "<hashed>",
                    "enabled": user["enabled"]
                }

        return None

    def update_password(self, person_id, new_password):
        data = self._load()

        for user in data:
            if user["person_id"] == person_id:
                salt, password_hash = self._hash_password(new_password)
                user["password"] = f"{salt}:{password_hash}"
                self._save(data)
                return True

        return False

    def delete_user(self, person_id):
        data = self._load()
        new_data = [user for user in data if user["person_id"] != person_id]

        if len(new_data) == len(data):
            return False

        self._save(new_data)
        return True

    def list_users(self):
        return [self.read_user(user["person_id"]) for user in self._load()]

    def authenticate(self, person_id, password):
        data = self._load()

        for user in data:
            if user["person_id"] == person_id:
                if not user["enabled"]:
                    return False
                return self._verify_password(password, user["password"])

        return False

    def clear_decrypted_data(self, user):
        user["first_name"] = None
        user["last_name"] = None
        user["address"] = None
        user["street_number"] = None
        return user
