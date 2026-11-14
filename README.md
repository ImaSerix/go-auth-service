# go-auth-service

Go Auth Service is a learning/portfolio (not production-ready) project focused on managing user authentication and basic authorization.

The main goal of the project, beyond implementing authentication and authorization, is to design a service that can be easily integrated into any other system.

---

## What problem does it solve?

The service allows delegating authentication and authorization responsibilities to a dedicated component.

It provides a convenient JWT-based authentication mechanism: issuing, refreshing, and validating tokens while exposing user context to other services.

---

## Core ideas

- JWT-based authentication
  - Access token — short-lived, used for authentication
  - Refresh token — long-lived, used to obtain new access tokens
- Session storage to allow refresh token revocation
- Only the auth service is responsible for issuing and validating JWT tokens
- External services treat tokens as opaque values
- Centralized role management

---

## Architecture overview

HTTP request → handler → service → repository

### Layers

#### Handler
- Parses request body
- Validates input
- Passes data to the service layer

#### Service
- Implements core business logic
- Manages JWT tokens
- Coordinates session lifecycle
- Uses repository for persistence

#### Repository
- Handles database access
- Manages users, sessions, and roles
- Writes the outbox entry of a new user together with the user

#### Background delivery
- `internal/service/outbox` sends new users to the Message service (see "User delivery to the Message service")

This separation keeps responsibilities isolated and allows individual layers to evolve independently.

---

## Authentication & Authorization model

Initial authentication is performed using `username` and `password`, which are passed in the request body.

After successful authentication:

- A JWT access token is issued for short-term authentication.
- A JWT refresh token is issued for obtaining new access tokens without re-entering credentials.

The refresh token:

- Must be stored securely by the client
- Has a long lifetime
- Can be revoked by deleting the corresponding session on the server

The service provides role management but does not implement business-level authorization rules. Authorization decisions are made by the consuming service.

External services may call `/auth/validate` to retrieve user context instead of implementing JWT validation logic themselves.

---

## API
### POST /auth/register
Creates a new user.

Request:
```json
{
  "username": "...",
  "password": "...",
  "role": "..."
}
```

Constraints:
- username: 4–32 characters
- password: 8–256 characters
- role: 2–32 characters

Response:

| Code |         Body          | Description              |
| ---- | :-------------------: | ------------------------ |
| 201  |     {"id": UUID}      | User created             |
| 400  |  "invalid json body"  | Invalid request body     |
| 400  | "invalid credentials" | Invalid username or password in request |
| 400  | "invalid role" | Invalid role in request |
| 409  |   "username taken"    | Username already exists  |
| 500  |   "internal error"    | Server error             |

The response does not wait for the delivery of the user to the Message service (see "User delivery to the Message service").

---

### POST /auth/login
Authenticates user and issues tokens.

Request:
```json
{
  "username": "...",
  "password": "..."
}
```

Constraints:
- username: 4–32 characters
- password: 8–256 characters

Response:

| Code | Body                                                                                                           | Description                 |
| ---- | -------------------------------------------------------------------------------------------------------------- | --------------------------- |
| 200  | {"id": UUID, "accessToken": JWT, "accessTokenExp": datetime, "refreshToken": JWT, "refreshTokenExp": datetime} | Successful authentication   |
| 400  | "invalid json body"                                                                                            | Invalid request body        |
| 401  | "invalid credentials"                                                                                          | Invalid authentication data |
| 500  | "internal error"                                                                                               | Server error                |

---

### POST /auth/logout
Invalidates the session associated with a refresh token.

Request:
```json
{
  "refreshToken": JWT
}
```

Constraints:
- refreshToken: valid JWT

Response:

| Code | Body                     | Description          |
| ---- | ------------------------ | -------------------- |
| 200  | {"status": "logged out"} | Successful logout    |
| 400  | "invalid json body"      | Invalid request body |
| 401  | "invalid token"          | Invalid token        |
| 401  | "token expired"          | Token expired        |
| 500  | "internal error"         | Server error         |

---

### POST /auth/refresh
Issues a new access token using a refresh token.

Request:
```json
{
  "refreshToken": JWT
}
```

Constraints:
- refreshToken: valid JWT

Response:

| Code | Body                                                                                               | Description                      |
| ---- | -------------------------------------------------------------------------------------------------- | -------------------------------- |
| 200  | {"accessToken": JWT, "accessTokenExp": datetime, "refreshToken": JWT, "refreshTokenExp": datetime} | Access token refreshed           |
| 400  | "invalid json body"                                                                                | Invalid request body             |
| 401  | "invalid token"                                                                                    | Invalid or revoked refresh token |
| 401  | "token expired"                                                                                    | Token expired                    |
| 401  | "token reuse"                                                                                      | Used revoked token               |
| 500  | "internal error"                                                                                   | Server error                     |

---

### POST /auth/validate
Validates an access token and returns user context.

Request:

The access token is passed in the `Authorization` header. The request body is not read.

```
Authorization: Bearer <JWT>
```

Constraints:
- Authorization: `Bearer ` followed by a valid JWT access token

Response:

| Code | Body                                                | Description                                         |
| ---- | --------------------------------------------------- | --------------------------------------------------- |
| 200  | {"id": UUID, "username": string, "roles": ["role"]} | Token valid                                         |
| 401  | "invalid token"                                     | Header missing, not in `Bearer` form, invalid token |
| 401  | "token expired"                                     | Token expired                                       |
| 500  | "internal error"                                    | Server error                                        |

---

## User delivery to the Message service

A registered user must appear in the Message service with the same UUID, even if Message is down at the moment of registration. Auth uses a transactional outbox for that; no message broker is involved.

- `POST /auth/register` writes the user and a row of the `outbox` table (`user_id`, `username`) in one database transaction: either both rows appear or none. The response does not wait for the delivery.
- A background task inside the Auth process (`internal/service/outbox`) reads undelivered rows (`delivered_at IS NULL`) in `id` order, up to 100 rows per pass, right after the start and then every 5 seconds.
- For every row it calls `POST <MESSAGE_URL>/internal/users` with the body `{"user_id": UUID, "username": "..."}` and a 5 second timeout. The call carries no credentials: it relies on the isolated internal network.
- `201` (created) and `409` (Message already has this user) both mean success: `delivered_at` is set. Any other status and any network error is a failure: it is logged (`outbox: deliver user ...`), the row stays undelivered and is retried on the next pass. There is no attempt limit. A failed row does not stop the delivery of the other rows of the pass.
- `attempts` counts the requests made for the row, including the successful one; it is kept for diagnostics only.
- If `MESSAGE_URL` is empty, the delivery is off: rows are still written and will be delivered once Auth is started with `MESSAGE_URL`.
- The task starts and stops with the process; one Auth instance is assumed (rows are not locked between instances). If the process stops between the answer of Message and the update of the row, the user is sent again after the restart and Message answers `409`.

Undelivered users:

```sql
SELECT id, user_id, username, created_at, attempts FROM outbox WHERE delivered_at IS NULL ORDER BY id;
```

---

## Security assumptions

This service is designed primarily for service-to-service communication.

Credentials and refresh tokens are accepted in the request body.  
The access token for `/auth/validate` is accepted only in the `Authorization: Bearer` header.

Clients are responsible for securely storing access and especially refresh tokens.  
If a refresh token is compromised, an attacker may obtain new access tokens until the session is revoked.

---

## What is intentionally missing

- Advanced role/permission system (only basic roles are supported)
- OAuth2, social login, MFA
- Fine-grained authorization policies
- Multy session for user

These decisions were made to keep the service focused, minimal, and suitable for learning purposes.

---

## Known issue
Token reuse attack. User could have only one session, session is stored with "user_id" as primary key, if not expired refresh token is leaked it is possible to permanently logout user.    

---
## Running locally

1. Prepare PostgreSQL database and user.

2. Create `.env` file in the project root (or export variables directly):

```bash
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db
DB_USER=auth_user
DB_PASSWORD=auth_password
DB_SSLMODE=disable

JWT_ACCESS_SECRET=replace-with-random-long-secret
JWT_ACCESS_TTL=15m
JWT_REFRESH_SECRET=replace-with-another-random-long-secret
JWT_REFRESH_TTL=720h

ARGON2_MEMORY=65536
ARGON2_ITERATIONS=3
ARGON2_PARALLELISM=2
ARGON2_SALT_LENGTH=16
ARGON2_KEY_LENGTH=32

# Optional: base URL of the Message service; empty or missing turns the user delivery off
MESSAGE_URL=http://localhost:8081
```

3. Run migrations (example with `migrate` CLI):

```bash
migrate -path ./migrations/postgres -database "postgres://auth_user:auth_password@localhost:5432/auth_db?sslmode=disable" up
```

4. Start server:

```bash
go run ./cmd/server
```

Server will be available at:

```bash
http://localhost:8080
```

### Tests

```bash
go test ./...
```

The tests of `internal/repository/postgres` need a real PostgreSQL and are skipped without `TEST_DATABASE_URL`. They create a schema of their own (`auth_test_<number>`), apply `migrations/postgres` to it and drop it afterwards, so the role must be allowed to create schemas:

```bash
TEST_DATABASE_URL="postgres://<role>:<password>@localhost:5432/<db-name>?sslmode=disable" go test ./internal/repository/postgres/
```

---

## Docker

The repository contains one `Dockerfile` with two targets:

| Target | Command | Purpose |
| --- | --- | --- |
| service (default) | `docker build -t go-auth-service .` | Static Go binary on `alpine:3.24.4`; listens on `:8080` |
| `migrate` | `docker build --target migrate -t go-auth-service-migrate .` | `migrate/migrate:v4.20.1` with `migrations/postgres` baked in |

The service runs as the unprivileged user `auth` (not root). The images contain no `.env`, no `.git` and no secrets (`.dockerignore`). All configuration is passed as environment variables at run time; the list is the same as in "Running locally" above (`DB_*`, `JWT_*`, `ARGON2_*` and the optional `MESSAGE_URL`). `DB_HOST` must be reachable from the container (for example the PostgreSQL service name in a shared Docker network).

### Migrations (one-shot container)

Run migrations under the **migrator** role (the owner of the database and schema), not under the application role:

```bash
docker run --rm --network <network> go-auth-service-migrate \
  -database "postgres://<migrator>:<password>@<db-host>:5432/<db-name>?sslmode=disable" up
```

The container applies the migrations and exits. Roll back one step with `down 1` instead of `up`.

### Running the service

Run the service under the **application** role (data rights only, no schema changes):

```bash
docker run --rm --network <network> -p 8080:8080 \
  -e DB_HOST=<db-host> -e DB_PORT=5432 -e DB_NAME=<db-name> \
  -e DB_USER=<app-role> -e DB_PASSWORD=<password> -e DB_SSLMODE=disable \
  -e JWT_ACCESS_SECRET=<secret> -e JWT_ACCESS_TTL=15m \
  -e JWT_REFRESH_SECRET=<other-secret> -e JWT_REFRESH_TTL=720h \
  -e ARGON2_MEMORY=65536 -e ARGON2_ITERATIONS=3 -e ARGON2_PARALLELISM=2 \
  -e ARGON2_SALT_LENGTH=16 -e ARGON2_KEY_LENGTH=32 \
  -e MESSAGE_URL=http://<message-host>:8080 \
  go-auth-service
```

Or pass the variables from a file kept outside the repository: `--env-file <path>`. The service has no `/health` endpoint; check it with any `POST /auth/*` request. The log line `Erorr while loading .env file` at startup is expected in a container: there is no `.env` file and the variables come from the environment.
