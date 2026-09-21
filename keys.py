"""RSA key generation and in-memory key store with expiry + kid tracking."""

import base64
import time
import uuid

from cryptography.hazmat.primitives.asymmetric import rsa


def _b64url_uint(value: int) -> str:
    """Encode an integer as base64url without padding, per JWK spec."""
    byte_length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class Key:
    def __init__(self, expires_in_seconds: int):
        self.kid = str(uuid.uuid4())
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.expiry = int(time.time()) + expires_in_seconds

    def is_expired(self) -> bool:
        return time.time() >= self.expiry

    def to_jwk(self) -> dict:
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


class KeyStore:
    """Holds a valid key and an already-expired key, generated at startup."""

    def __init__(self):
        self.valid_key = Key(expires_in_seconds=3600)
        self.expired_key = Key(expires_in_seconds=-3600)
        self._by_kid = {
            self.valid_key.kid: self.valid_key,
            self.expired_key.kid: self.expired_key,
        }

    def get_by_kid(self, kid: str) -> Key | None:
        return self._by_kid.get(kid)

    def unexpired_keys(self) -> list[Key]:
        return [k for k in self._by_kid.values() if not k.is_expired()]
