
"""SQLite-backed JWKS server that issues signed JWTs."""

import time

import jwt
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, request

from keys import KeyStore

app = Flask(__name__)
store = KeyStore()


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return public keys that have not expired."""
    keys = [key.to_jwk() for key in store.unexpired_keys()]
    return jsonify({"keys": keys}), 200


@app.route(
    "/.well-known/jwks.json",
    methods=["POST", "PUT", "DELETE", "PATCH"],
)
def jwks_method_not_allowed():
    """Reject unsupported methods on the JWKS endpoint."""
    return jsonify({"error": "method not allowed"}), 405


@app.route("/auth", methods=["POST"])
def auth():
    """Issue a JWT signed with a database-backed private key."""
    use_expired = "expired" in request.args
    key = store.expired_key if use_expired else store.valid_key

    # An expired key must produce an expired JWT for the assignment.
    exp = key.expiry if use_expired else int(time.time()) + 3600

    private_pem = key.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "sub": "fake-user",
        "iat": int(time.time()),
        "exp": exp,
    }

    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": str(key.kid)},
    )

    return token, 200, {"Content-Type": "text/plain"}


@app.route("/auth", methods=["GET", "PUT", "DELETE", "PATCH"])
def auth_method_not_allowed():
    """Reject unsupported methods on the authentication endpoint."""
    return jsonify({"error": "method not allowed"}), 405


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
