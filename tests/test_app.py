
"""Tests for the SQLite-backed JWKS server."""

import base64
import sqlite3
import time
from contextlib import closing

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import app as app_module
from keys import DB_FILE, KeyStore


@pytest.fixture
def store(tmp_path):
    """Create an isolated database for each test."""
    return KeyStore(str(tmp_path / DB_FILE))


@pytest.fixture
def client(store, monkeypatch):
    """Create a Flask test client with an isolated database."""
    monkeypatch.setattr(app_module, "store", store)
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def test_database_file_and_required_schema(store):
    """The database contains the required keys table."""
    with closing(sqlite3.connect(store.db_path)) as connection:
        row = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = ? AND name = ?",
            ("table", "keys"),
        ).fetchone()

    assert row is not None
    schema = row[0].lower()
    assert "kid integer primary key autoincrement" in schema
    assert "key blob not null" in schema
    assert "exp integer not null" in schema


def test_database_has_expired_and_valid_keys(store):
    assert store.valid_key.is_expired() is False
    assert store.expired_key.is_expired() is True


def test_private_keys_are_persisted_as_blobs(store):
    with closing(sqlite3.connect(store.db_path)) as connection:
        rows = connection.execute(
            "SELECT key, exp FROM keys"
        ).fetchall()

    assert len(rows) >= 2
    assert all(isinstance(row[0], bytes) for row in rows)
    assert all(row[0] for row in rows)
    assert all(isinstance(row[1], int) for row in rows)


def test_key_survives_store_restart(store):
    original = store.valid_key
    restarted_store = KeyStore(store.db_path)
    restored = restarted_store.get_by_kid(original.kid)

    assert restored is not None
    assert restored.kid == original.kid
    assert restored.expiry == original.expiry
    assert restored.public_key.public_numbers() == (
        original.public_key.public_numbers()
    )


def test_get_by_kid_returns_none_for_missing_key(store):
    assert store.get_by_kid(-999) is None


def test_get_by_kid_uses_parameterized_query(store):
    key = store.valid_key
    assert store.get_by_kid(key.kid).kid == key.kid


def test_unexpired_keys_excludes_expired_keys(store):
    valid = store.valid_key
    expired = store.expired_key
    keys = store.unexpired_keys()
    kids = [key.kid for key in keys]

    assert valid.kid in kids
    assert expired.kid not in kids
    assert all(not key.is_expired() for key in keys)


def test_unexpired_keys_returns_all_valid_keys(store):
    first = store.valid_key
    additional = store._save_key(7200)
    kids = [key.kid for key in store.unexpired_keys()]

    assert first.kid in kids
    assert additional.kid in kids


def test_auth_post_returns_jwt(client):
    response = client.post("/auth")

    assert response.status_code == 200
    token = response.get_data(as_text=True)
    assert token.count(".") == 2


def test_auth_token_has_database_key_id(client, store):
    response = client.post("/auth")
    header = jwt.get_unverified_header(
        response.get_data(as_text=True)
    )

    assert header["kid"] == str(store.valid_key.kid)


def test_auth_token_is_valid_and_unexpired(client, store):
    response = client.post("/auth")
    token = response.get_data(as_text=True)

    decoded = jwt.decode(
        token,
        key=store.valid_key.public_key,
        algorithms=["RS256"],
    )

    assert decoded["sub"] == "fake-user"
    assert decoded["exp"] > time.time()


def test_auth_expired_parameter_uses_expired_key(client, store):
    response = client.post("/auth?expired=true")

    assert response.status_code == 200
    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)

    assert header["kid"] == str(store.expired_key.kid)

    decoded = jwt.decode(
        token,
        key=store.expired_key.public_key,
        algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert decoded["exp"] < time.time()

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            key=store.expired_key.public_key,
            algorithms=["RS256"],
        )


def test_auth_get_not_allowed(client):
    assert client.get("/auth").status_code == 405


def test_jwks_returns_only_unexpired_public_keys(client, store):
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    data = response.get_json()
    kids = [key["kid"] for key in data["keys"]]

    assert str(store.valid_key.kid) in kids
    assert str(store.expired_key.kid) not in kids

    for key in data["keys"]:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert "n" in key and "e" in key
        assert "d" not in key


def test_jwks_public_key_verifies_auth_token(client, store):
    token = client.post("/auth").get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    jwks = client.get("/.well-known/jwks.json").get_json()["keys"]

    matching = [
        key for key in jwks if key["kid"] == header["kid"]
    ]
    assert len(matching) == 1

    jwk = matching[0]
    n_bytes = base64.urlsafe_b64decode(
        jwk["n"] + "=" * (-len(jwk["n"]) % 4)
    )
    e_bytes = base64.urlsafe_b64decode(
        jwk["e"] + "=" * (-len(jwk["e"]) % 4)
    )

    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(e_bytes, "big"),
        int.from_bytes(n_bytes, "big"),
    ).public_key()

    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"


def test_jwks_post_not_allowed(client):
    assert client.post("/.well-known/jwks.json").status_code == 405


def test_jwks_put_not_allowed(client):
    assert client.put("/.well-known/jwks.json").status_code == 405


def test_auth_put_not_allowed(client):
    assert client.put("/auth").status_code == 405
