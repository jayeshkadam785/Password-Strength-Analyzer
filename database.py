"""
database.py
Handles storage of password *hashes* (never plaintext) per user, so the
tool can detect and block reuse of old passwords.

Uses SQLite for simplicity. Passwords are salted + hashed with PBKDF2-HMAC-SHA256
before ever touching the database.
"""

import sqlite3
import hashlib
import os
import secrets
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "passwords.db")
PBKDF2_ITERATIONS = 260_000
HISTORY_LIMIT = 5  # how many previous passwords to remember per user


def init_db(db_path: str = DB_PATH):
    with _connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                salt TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


@contextmanager
def _connect(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    ).hex()


def is_password_reused(username: str, password: str, db_path: str = DB_PATH) -> bool:
    """Check the new password's hash against the user's stored history."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT salt, pw_hash FROM password_history WHERE username = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (username, HISTORY_LIMIT),
        ).fetchall()

    for salt_hex, stored_hash in rows:
        salt = bytes.fromhex(salt_hex)
        if _hash_password(password, salt) == stored_hash:
            return True
    return False


def save_password(username: str, password: str, db_path: str = DB_PATH) -> None:
    """Store a new password hash in history, trimming old entries beyond the limit."""
    salt = secrets.token_bytes(16)
    pw_hash = _hash_password(password, salt)

    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO password_history (username, salt, pw_hash) VALUES (?, ?, ?)",
            (username, salt.hex(), pw_hash),
        )
        # Keep only the most recent HISTORY_LIMIT entries per user
        conn.execute("""
            DELETE FROM password_history
            WHERE username = ? AND id NOT IN (
                SELECT id FROM password_history
                WHERE username = ?
                ORDER BY created_at DESC
                LIMIT ?
            )
        """, (username, username, HISTORY_LIMIT))
        conn.commit()
