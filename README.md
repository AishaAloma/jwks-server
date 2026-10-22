# JWKS Server

A RESTful JWKS server built with Flask. Generates RSA key pairs with unique key IDs (`kid`) and expiration timestamps, stores private keys in a SQLite database, serves unexpired public keys through the standard JWKS endpoint, and issues signed JWTs. It also supports issuing a token signed with an expired key for testing verification failure.

## Author

Aisha Aloma

## Endpoints

- `GET /.well-known/jwks.json` — returns unexpired public keys in JWKS format.
- `POST /auth` — returns a JWT signed with a valid, unexpired key.
- `POST /auth?expired=true` — returns a JWT signed with an expired key and an expired `exp` claim. This key is excluded from the JWKS response.

## Database

The server uses SQLite and creates a database named `totally_not_my_privateKeys.db`.

The database contains a `keys` table with the following columns:

- `kid` — integer primary key that automatically increments.
- `key` — private key stored as a PEM-encoded BLOB.
- `exp` — key expiration time stored as an integer Unix timestamp.

Keys persist in the database between server restarts. The database file is excluded from Git using `.gitignore`.

## Setup

Activate your virtual environment, then install the dependencies:

```bash
pip install -r requirements.txt
```

## Run the server

```bash
python app.py
```

The server listens on `http://localhost:8080`.

## Run tests with coverage

```bash
python -m pytest --cov=app --cov=keys --cov-report=term-missing
```

## Manual check

With the server running, open another Terminal window and run:

```bash
curl -X POST http://localhost:8080/auth
```

```bash
curl -X POST "http://localhost:8080/auth?expired=true"
```

```bash
curl http://localhost:8080/.well-known/jwks.json
```

## Notes

The `/auth` endpoint mocks authentication; it does not validate user credentials. This project is for educational purposes and is not intended to be a production authentication system.
