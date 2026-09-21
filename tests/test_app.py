import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import app as app_module
from keys import Key, KeyStore


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


# --- Key / KeyStore unit tests ---

def test_key_has_kid_and_rsa_keypair():
    key = Key(expires_in_seconds=3600)
    assert key.kid
    assert isinstance(key.private_key, rsa.RSAPrivateKey)
    assert isinstance(key.public_key, rsa.RSAPublicKey)


def test_key_not_expired_when_future():
    key = Key(expires_in_seconds=3600)
    assert key.is_expired() is False


def test_key_expired_when_past():
    key = Key(expires_in_seconds=-3600)
    assert key.is_expired() is True


def test_key_to_jwk_shape():
    key = Key(expires_in_seconds=3600)
    jwk = key.to_jwk()
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == key.kid
    assert "n" in jwk and "e" in jwk


def test_keystore_has_valid_and_expired():
    store = KeyStore()
    assert store.valid_key.is_expired() is False
    assert store.expired_key.is_expired() is True


def test_keystore_get_by_kid():
    store = KeyStore()
    assert store.get_by_kid(store.valid_key.kid) is store.valid_key
    assert store.get_by_kid("nonexistent") is None


def test_keystore_unexpired_keys_excludes_expired():
    store = KeyStore()
    unexpired = store.unexpired_keys()
    assert store.valid_key in unexpired
    assert store.expired_key not in unexpired


# --- /auth endpoint tests ---

def test_auth_post_returns_200_and_token(client):
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)
    assert token.count(".") == 2  # header.payload.signature


def test_auth_token_has_kid_header_matching_valid_key(client):
    resp = client.post("/auth")
    token = resp.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    assert header["kid"] == app_module.store.valid_key.kid


def test_auth_token_is_verifiable_and_unexpired(client):
    resp = client.post("/auth")
    token = resp.get_data(as_text=True)
    pubkey = app_module.store.valid_key.public_key
    decoded = jwt.decode(token, key=pubkey, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"
    assert decoded["exp"] > time.time()


def test_auth_expired_query_param_returns_expired_token(client):
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    assert header["kid"] == app_module.store.expired_key.kid

    pubkey = app_module.store.expired_key.public_key
    decoded = jwt.decode(
        token, key=pubkey, algorithms=["RS256"], options={"verify_exp": False}
    )
    assert decoded["exp"] < time.time()

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, key=pubkey, algorithms=["RS256"])


def test_auth_get_not_allowed(client):
    resp = client.get("/auth")
    assert resp.status_code == 405


# --- JWKS endpoint tests ---

def test_jwks_get_returns_200(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert "keys" in resp.get_json()


def test_jwks_only_contains_unexpired_kid(client):
    resp = client.get("/.well-known/jwks.json")
    kids = [k["kid"] for k in resp.get_json()["keys"]]
    assert app_module.store.valid_key.kid in kids
    assert app_module.store.expired_key.kid not in kids


def test_jwks_post_not_allowed(client):
    resp = client.post("/.well-known/jwks.json")
    assert resp.status_code == 405


def test_jwks_key_verifies_auth_token(client):
    """End-to-end: the key served by JWKS should verify a token from /auth."""
    token_resp = client.post("/auth")
    token = token_resp.get_data(as_text=True)
    header = jwt.get_unverified_header(token)

    jwks_resp = client.get("/.well-known/jwks.json")
    matching = [k for k in jwks_resp.get_json()["keys"] if k["kid"] == header["kid"]]
    assert len(matching) == 1

    jwk = matching[0]
    n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=="), "big")
    public_key = rsa.RSAPublicNumbers(e, n).public_key()

    decoded = jwt.decode(token, key=public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"
