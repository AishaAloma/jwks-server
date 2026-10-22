
"""SQLite-backed RSA key store for the JWKS server."""

import base64
import sqlite3
import time
from contextlib import closing

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


DB_FILE = "totally_not_my_privateKeys.db"


def _b64url_uint(value: int) -> str:
    """Encode an integer as base64url without padding."""
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class Key:
    """Represent an RSA key and its expiration time."""

    def __init__(self, private_key, kid: int, expiry: int):
        self.kid = kid
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.expiry = expiry

    def is_expired(self) -> bool:
        """Return True if the key has expired."""
        return time.time() >= self.expiry

    def to_jwk(self) -> dict:
        """Return the public key in JSON Web Key format."""
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(self.kid),
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


class KeyStore:
    """Store and retrieve RSA private keys using SQLite."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._initialize_database()

    def _connect(self):
        """Open a connection to the SQLite database."""
        return sqlite3.connect(self.db_path)

    def _initialize_database(self):
        """Create the required table and ensure both key types exist."""
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS keys(
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL
                    )
                    """
                )

        # Keep at least one expired key and one unexpired key available.
        if self._get_key(expired=False) is None:
            self._save_key(expires_in_seconds=3600)

        if self._get_key(expired=True) is None:
            self._save_key(expires_in_seconds=-3600)

    def _save_key(self, expires_in_seconds: int) -> Key:
        """Generate an RSA key and save its PEM representation."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        expiry = int(time.time()) + expires_in_seconds

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO keys (key, exp) VALUES (?, ?)",
                    (sqlite3.Binary(private_pem), expiry),
                )
                kid = cursor.lastrowid

        return Key(private_key, kid, expiry)

    def _get_key(self, expired: bool) -> Key | None:
        """Retrieve one expired or unexpired key from the database."""
        comparison = "<=" if expired else ">"
        now = int(time.time())

        with closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT kid, key, exp
                FROM keys
                WHERE exp {comparison} ?
                ORDER BY kid DESC
                LIMIT 1
                """,
                (now,),
            ).fetchone()

        if row is None:
            return None

        kid, private_pem, expiry = row
        private_key = serialization.load_pem_private_key(
            bytes(private_pem),
            password=None,
        )
        return Key(private_key, kid, expiry)

    @property
    def valid_key(self) -> Key:
        """Return a valid key, generating one if necessary."""
        key = self._get_key(expired=False)
        if key is None:
            key = self._save_key(expires_in_seconds=3600)
        return key

    @property
    def expired_key(self) -> Key:
        """Return an expired key, generating one if necessary."""
        key = self._get_key(expired=True)
        if key is None:
            key = self._save_key(expires_in_seconds=-3600)
        return key

    def get_by_kid(self, kid: int) -> Key | None:
        """Retrieve a key by its database ID."""
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT kid, key, exp FROM keys WHERE kid = ?",
                (kid,),
            ).fetchone()

        if row is None:
            return None

        key_id, private_pem, expiry = row
        private_key = serialization.load_pem_private_key(
            bytes(private_pem),
            password=None,
        )
        return Key(private_key, key_id, expiry)

    def unexpired_keys(self) -> list[Key]:
        """Return all keys that have not expired."""
        now = int(time.time())

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY kid
                """,
                (now,),
            ).fetchall()

        return [
            Key(
                serialization.load_pem_private_key(
                    bytes(pem),
                    password=None,
                ),
                kid,
                expiry,
            )
            for kid, pem, expiry in rows
        ]
