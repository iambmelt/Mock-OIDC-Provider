# Mock OIDC Identity Provider (Python, Flask)

A feature-rich, spec-compliant mock OpenID Connect (OIDC) / OAuth2 Identity Provider for testing client integrations.

Perfect for:
- Testing OIDC/OAuth2 client implementations
- Integration testing of applications requiring an identity provider
- Developing and debugging authentication flows
- Learning OIDC/OAuth2 concepts

---

## Features

### Core Flows
* **Authorization Code Flow** — with optional PKCE support
* **Refresh Token Flow** — single-use rotating refresh tokens
* **Client Credentials Flow** — for machine-to-machine authentication
* **PKCE Support** (optional) — Proof Key for Public Clients
  * S256 (recommended) and plain methods supported
  * Enable with `--pkce` flag

### OIDC Compliance
* **Spec-compliant tokens** — RS256-signed JWTs with RFC7519-compliant timestamps
* **Stable `sub` claim** — deterministic per user (hash-based, survives server restarts)
* **`at_hash` in ID tokens** — OIDC Core Section 3.3.2.11 compliance
* **Proper scope handling** — scope narrowing allowed on refresh, widening denied
* **`redirect_uri` validation** — matched between authorize and token endpoints

### Endpoints
* **`/authorize`** — Authorization endpoint with built-in login form
* **`/token`** — Token endpoint supporting authorization_code, refresh_token, and client_credentials grants
* **`/userinfo`** — OIDC UserInfo endpoint with scope-based claim filtering
* **`/introspect`** — RFC 7662 token introspection endpoint
* **`/revoke`** — RFC 7009 token revocation endpoint
* **`/.well-known/openid-configuration`** — OIDC discovery document
* **`/jwks.json`** — JSON Web Key Set (JWKS) for token verification

### Configuration & Customization
* **Configurable TTLs** — authorization codes, access tokens, ID tokens, refresh tokens
* **User configuration** — load users from JSON file with custom claims (name, email, groups, etc.)
* **Client configuration** — load client definitions with allowed grants and redirect URIs
* **Custom issuer** — override default issuer URI
* **SSL/TLS support** — provide your own certs or generate ephemeral self-signed certs
* **Structured logging** — both text and JSON output formats

### Token Features
* **Stable subject identifiers** — `sub` claim is deterministic per user
* **Custom claims** — support for custom user claims (groups, departments, etc.)
* **Single-use refresh tokens** — rotated on every exchange
* **Request ID tracking** — X-Request-ID header support for debugging
* **Thread-safe operations** — safe for concurrent integration testing

---

## Requirements

* Python 3.10+
* Dependencies (auto-installed):
  * `flask>=3.0` — web framework
  * `pyjwt>=2.8` — JWT signing and verification
  * `cryptography>=42` — RSA key generation and X.509 certificates
  * `structlog>=24` — structured logging (optional)

### Installation

**Option 1: Install as a package (recommended)**

```bash
pip install -e ".[dev]"  # Development mode with test dependencies
# or
pip install .            # Production installation
```

**Option 2: Install dependencies manually**

```bash
pip install flask pyjwt cryptography structlog pytest pytest-flask
```

**Option 3: Using `uv` (fast Python package manager)**

```bash
uv sync --extra dev  # Install with dev dependencies
# or
uv pip install flask pyjwt cryptography
```

---

## Getting Started

### Quick Start (5 seconds)

```bash
python -m mock_oidc --ssl-quickboot
```

This starts the IdP at `https://localhost:4567` with ephemeral certs. Open in browser:

```
https://localhost:4567/authorize?response_type=code&client_id=test-client&redirect_uri=https://localhost:4567/callback&scope=openid%20email&state=abc123
```

### Run Tests

```bash
pytest tests/ -v          # Run all tests
pytest tests/ --cov       # With coverage report
```

Currently: **351+ tests passing** with 87% code coverage, covering all major flows, edge cases, and spec compliance.

## Usage

Run the identity provider:

```bash
python -m mock_oidc [options]
```

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--port PORT` | Port to listen on | `4567` |
| `--auth-code-ttl SEC` | Authorization code TTL | `300` |
| `--access-token-ttl SEC` | Access token TTL | `3600` |
| `--id-token-ttl SEC` | ID token TTL | `3600` |
| `--refresh-ttl SEC` | Refresh token TTL | `50400` (14h) |
| `--issuer URI` | Override issuer URI | Auto-inferred from request |
| `--pkce` | Require PKCE for public clients | Disabled |
| `--cert FILE` | Token signing certificate (PEM) | Generate ephemeral |
| `--key FILE` | Token signing private key (PEM) | Generate ephemeral |
| `--ssl-cert FILE` | Service HTTPS certificate | HTTP only |
| `--ssl-key FILE` | Service HTTPS private key | HTTP only |
| `--ssl-quickboot` | Generate ephemeral SSL certs | Disabled |
| `--users FILE` | User definitions (JSON) | Accept all users |
| `--clients FILE` | Client definitions (JSON) | Accept all clients |

---

## User Configuration

Define users with custom claims using a JSON file:

```json
{
  "alice@example.com": {
    "name": "Alice Smith",
    "email": "alice@example.com",
    "groups": ["admin", "engineers"],
    "department": "Engineering"
  },
  "bob@example.com": {
    "name": "Bob Jones",
    "email": "bob@example.com",
    "groups": ["readers"]
  }
}
```

Then run:

```bash
python -m mock_oidc --users users.json
```

With this config:
- Only `alice@example.com` and `bob@example.com` can authenticate
- Unknown users get HTTP 400 response
- Custom claims appear in ID tokens and `/userinfo` responses
- Discovery document (`/.well-known/openid-configuration`) lists all available claims

---

## Examples

### Example 1: Start with Ephemeral SSL

```bash
python mock_oidc.py --ssl-quickboot --port 8443
```

This launches the IdP at **[https://localhost:8443](https://localhost:8443)** with ephemeral self-signed SSL and signing certs.

Open this in a browser:

```
https://localhost:8443/authorize?response_type=code&client_id=test-client&redirect_uri=https://localhost:8443/callback&scope=openid%20email&state=123
```

---

## Example: Start without SSL

```bash
python mock_oidc.py --port 8080
```

Open this in a browser:

```
http://localhost:8080/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:8080/callback&scope=openid%20email&state=123
```

---

## Example: Exchange an Authorization Code

Once you have a code from the `/authorize` redirect:

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=ABC123" \
  -d "client_id=test-client" \
  -d "redirect_uri=http://localhost:8080/callback"
```

Response:

```json
{
  "access_token": "...",
  "id_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid email"
}
```

---

## Example: Exchange with PKCE Enabled

When the server is started with `--pkce`, clients must include a `code_challenge` on `/authorize` and a `code_verifier` on `/token`.

### Step 1: Authorize with code challenge

```bash
https://localhost:8443/authorize?response_type=code&client_id=test-client&redirect_uri=https://localhost:8443/callback&scope=openid%20email&state=123&code_challenge=abc123&code_challenge_method=S256
```

### Step 2: Exchange code with code\_verifier

```bash
curl -X POST https://localhost:8443/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=ABC123" \
  -d "client_id=test-client" \
  -d "redirect_uri=https://localhost:8443/callback" \
  -d "code_verifier=xyz456"
```

---

## Example: Refresh a Token

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=eyJhbGciOi..." \
  -d "client_id=test-client"
```

### Example 5: Machine-to-Machine (Client Credentials Flow)

For service-to-service authentication, use client_credentials grant:

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=service-worker" \
  -d "client_secret=my-secret" \
  -d "scope=api:read api:write"
```

Response (access token only, no ID token or refresh token):

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api:read api:write"
}
```

### Example 6: Token Introspection (RFC 7662)

Check if a token is valid:

```bash
curl -X POST http://localhost:8080/introspect \
  -u "client_id:client_secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJ0eXAiOiJKV1QiLCJhbGc..."
```

Response (valid token):

```json
{
  "active": true,
  "sub": "user:abc123def456",
  "scope": "openid email",
  "client_id": "test-client",
  "exp": 1234567890,
  "iat": 1234564290,
  "token_type": "Bearer",
  "jti": "token-jti-value"
}
```

### Example 7: Token Revocation (RFC 7009)

Revoke a refresh token:

```bash
curl -X POST http://localhost:8080/revoke \
  -u "client_id:client_secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJ0eXAiOiJKV1QiLCJhbGc..."
```

Response: `200 OK` (empty body, per RFC 7009 spec)

### Example 8: UserInfo Endpoint (OIDC Core 5.3)

Get authenticated user information:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/userinfo
```

Response (claims based on access token scope):

```json
{
  "sub": "user:abc123def456",
  "name": "Alice Smith",
  "email": "alice@example.com"
}
```

---

## All Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/authorize` | GET, POST | — | Authorization endpoint with login form |
| `/token` | POST | Client auth | Token endpoint (code, refresh, client_credentials) |
| `/userinfo` | GET, POST | Bearer | Get authenticated user claims |
| `/introspect` | POST | Client auth | Introspect token validity (RFC 7662) |
| `/revoke` | POST | Client auth | Revoke refresh token (RFC 7009) |
| `/health` | GET | — | Health check endpoint with uptime (for Docker/K8s) |
| `/.well-known/openid-configuration` | GET | — | OIDC discovery document |
| `/jwks.json` | GET | — | JSON Web Key Set for verification |
| `/callback` | GET | — | Debug endpoint showing auth code (useful in browser testing) |
| `/admin/audit` | GET | — | Audit log with optional filtering (Phase 7) |
| `/admin/store` | GET | — | Token store statistics (Phase 7) |
| `/admin/` | GET | — | Admin dashboard UI with real-time stats (Phase 7) |
| `/admin/audit` | GET | — | Audit log with filtering (Phase 7) |
| `/admin/store` | GET | — | Token store statistics (Phase 7) |
| `/admin/` | GET | — | Admin dashboard UI (Phase 7) |

---

## Admin Endpoints (Phase 7 - Observability)

The Mock OIDC Provider includes admin endpoints for monitoring and debugging during local testing.

### `/admin/audit` — Audit Log Endpoint

Get audit log entries with optional filtering:

```bash
# Get recent audit events
curl http://localhost:4567/admin/audit

# Filter by event type
curl http://localhost:4567/admin/audit?event=token_issued

# Filter by client_id
curl http://localhost:4567/admin/audit?client_id=web-app

# Limit results
curl http://localhost:4567/admin/audit?limit=50

# Combine filters
curl http://localhost:4567/admin/audit?event=authorize_code_issued&client_id=web-app
```

Response:

```json
{
  "count": 5,
  "total_in_store": 427,
  "entries": [
    {
      "ts": "2026-05-10T12:34:56.789Z",
      "event": "token_issued",
      "request_id": "abc123def456",
      "client_id": "web-app",
      "scope": "openid email",
      "sub": "user:xyz789"
    },
    ...
  ]
}
```

**Features:**
- Returns up to `limit` entries (default 100, max 1000)
- Filter by `event` type (e.g., `token_issued`, `authorize_code_issued`, `token_refreshed`)
- Filter by `client_id`
- Entries sorted by timestamp (most recent first)
- Stores last 1000 audit events in memory

**Audit Event Types:**
- `authorize_code_issued` — Authorization code created
- `code_exchanged` — Auth code exchanged for tokens
- `token_issued` — Tokens issued (any grant type)
- `token_refreshed` — Refresh token exchanged
- `token_revoked` — Refresh token revoked
- `token_introspected` — Token introspected

### `/admin/store` — Store Statistics Endpoint

Get current token store statistics:

```bash
curl http://localhost:4567/admin/store
```

Response:

```json
{
  "codes": 3,
  "refresh_tokens": 5,
  "audit_events": 427
}
```

Shows:
- Active authorization codes
- Active refresh tokens
- Total audit events in store

### `/admin/` — Admin Dashboard UI

Open in a browser to view real-time dashboard:

```
http://localhost:4567/admin/
```

Features:
- Live statistics display (auto-updates every 5 seconds)
- Audit event table with filtering by event type or client_id
- Color-coded event badges
- No authentication required (for local testing only)

### Admin Endpoints (Phase 7)

For local testing and debugging, three admin endpoints provide observability:

**Audit Log:**
```bash
curl http://localhost:4567/admin/audit
curl http://localhost:4567/admin/audit?event=token_issued
curl http://localhost:4567/admin/audit?client_id=web-app&limit=20
```

Returns audit events with timestamps, request IDs, and details. Supports filtering by event type and client ID.

**Store Statistics:**
```bash
curl http://localhost:4567/admin/store
```

Returns current counts of active authorization codes, refresh tokens, and audit events.

**Admin Dashboard:**
```bash
# Open in browser:
http://localhost:4567/admin/
```

Interactive dashboard showing real-time statistics and filterable audit log with auto-refresh every 5 seconds.

---

## Token Format

All tokens are **JWTs signed with RS256**, issued in compliance with OIDC Core and OAuth 2.0 specs.

### Access Token

Standard OAuth 2.0 access token. Claims:

* `sub` — unique, stable user identifier (hash-based, deterministic per username)
* `iss` — issuer URI
* `aud` — client_id
* `iat`, `nbf`, `exp` — issued-at, not-before, expiration timestamps (seconds since epoch)
* `scope` — space-delimited scopes granted
* `jti` — unique token identifier

**Client Credentials Flow** access tokens have:
* `sub` = `client_id` (machine identity)

### ID Token

OIDC Core-compliant ID token. Always includes:

* `sub` — stable user identifier (same as in access token within a user session)
* `iss` — issuer URI
* `aud` — client_id
* `iat`, `nbf`, `exp` — timestamps
* `nonce` — if provided in authorization request
* **`at_hash`** — hash of accompanying access token (OIDC Core 3.3.2.11 requirement)

And from scopes:

* `name`, `email` — if `profile` or `email` scopes requested
* Custom claims — if configured via `--users` JSON file (e.g., `groups`, `department`)

### Refresh Token

Single-use refresh token with rotation. Claims:

* `sub` — user identifier
* `iss`, `aud` — issuer and client_id
* `iat`, `nbf`, `exp` — timestamps
* `jti` — unique token identifier (used for single-use enforcement and revocation)
* `typ` — "refresh"

**Single-use enforcement:** Each refresh token can only be exchanged once. A new refresh token is issued on each exchange.

---

## Project Status

**Phases Implemented:**
- Phase 1 (Foundation): Package structure, testability, no side effects on import
- Phase 2 (Correctness): Stable `sub`, `/userinfo`, `at_hash`, proper PKCE, redirect_uri validation
- Phase 3 (Capability): `/introspect`, `/revoke`, `client_credentials`, user config, client config
- Phase 4 (Robustness): Thread-safe TokenStore, TTL eviction, structured logging, request IDs
- Phase 5 (Testing): Full test suite with comprehensive coverage
- Phase 6 (Deployment): Docker support, GitHub Actions CI/CD, automated publishing
- Phase 7 (Observability): In-memory audit log, admin endpoints

**Test Coverage:** 351+ tests across all major flows and edge cases (including 35 Phase 7 admin/audit tests)

## Use Cases

This mock OIDC provider is ideal for:

- Integration testing of OIDC/OAuth2 clients and applications
- Learning and understanding OIDC/OAuth2 concepts
- Debugging authentication and authorization flows
- Testing mobile application integrations with identity providers
- Rapid prototyping of features that require authentication

## Limitations

- Not intended for production use; designed for local testing and development only
- No real user database; uses in-memory store with optional JSON configuration
- No persistent storage; tokens and codes are lost on server restart
- Client registration is not enforced; any client_id is accepted unless `--clients` config is provided
- Signing keys are generated on each restart by default; provide `--cert` and `--key` flags to persist keys

## Contributing

This is an educational and development tool. Bug reports and feature suggestions are welcome.
