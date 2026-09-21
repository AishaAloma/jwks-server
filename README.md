# JWKS Server

A RESTful JWKS server built with Flask. Generates RSA key pairs with unique
`kid`s and expiry timestamps, serves public keys via the standard
`.well-known` JWKS endpoint, and issues signed JWTs — including a path to
issue a token signed by an expired key for testing verification failure.

## Author

Aisha Aloma

## Endpoints

- `GET /.well-known/jwks.json` — returns unexpired public keys in JWKS format
- `POST /auth` — returns a JWT signed with a valid, unexpired key
- `POST /auth?expired=true` — returns a JWT signed with an expired key and an
  expired `exp` claim (this key is intentionally excluded from the JWKS
  response)

## Setup

```bash
pip install -r requirements.txt
```

## Run the server

```bash
python app.py
```

Server listens on `http://localhost:8080`.

## Run tests with coverage

```bash
pytest --cov=. --cov-report=term-missing
```

## Manual check

```bash
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
curl http://localhost:8080/.well-known/jwks.json
```

## Notes

This project mocks authentication for `/auth` — no credentials are checked.
Built for educational purposes only; not a production auth system.
