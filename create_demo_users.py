from pathlib import Path
from src.secure_flat_file_db import SecureFlatFileDB, generate_key

# Reset demo file so the script can run multiple times
Path("demo_users.json").write_text("[]", encoding="utf-8")

db = SecureFlatFileDB("demo_users.json", generate_key())

db.create_user(
    1,
    "Amir",
    "Khan",
    "Testvej",
    "12",
    "MitKode123",
    True
)

print("demo_users.json created with encrypted personal data and hashed password.")
