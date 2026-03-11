# go-auth-service

Go Auth Service is a learning/portfolio project focused on managing user authentication and basic authorization.

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
| 400  | "invalid credentials" | Invalid input in request |
| 409  |   "username taken"    | Username already exists  |
| 500  |   "internal error"    | Server error             |

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
```json
{
  "accessToken": JWT
}
```

Constraints:
- accessToken: valid JWT

Response:

| Code | Body                                                | Description   |
| ---- | --------------------------------------------------- | ------------- |
| 200  | {"id": UUID, "username": string, "roles": ["role"]} | Token valid   |
| 401  | "invalid token"                                     | Invalid token |
| 401  | "token expired"                                     | Token expired |
| 500  | "internal error"                                    | Server error  |

---

## Security assumptions

This service is designed primarily for service-to-service communication.

Authentication data and tokens are accepted in the request body.  
Header-based authentication may be added in future versions.

Clients are responsible for securely storing access and especially refresh tokens.  
If a refresh token is compromised, an attacker may obtain new access tokens until the session is revoked.

---

## What is intentionally missing

- Header-based authentication (Authorization header support)
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

1. Prepare a PostgreSQL database and user
2. Set connection variables in .env or environment
3. Run migrations from:
```bash
/migrations/postgres
```
(using github.com/golang-migrate/migrate)

4. Start server:
```bash
go run cmd/server/main.go
```
Server will be available at:
```bash
localhost:8080
```

