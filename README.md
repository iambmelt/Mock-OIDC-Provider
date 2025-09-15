# Mock OIDC Identity Provider (Python, Flask)

This project provides a that implements a mock OpenID Connect (OIDC) Identity Provider.
It is designed for **testing OIDC client integrations** and supports the **Authorization Code Flow**, **Refresh Tokens**, and optional **PKCE**.

---

## Features

* `/authorize` endpoint with a simple login form (username/password + scope).
* `/token` endpoint with support for:

  * `grant_type=authorization_code`
  * `grant_type=refresh_token` (always rotates refresh tokens, single-use).
* **Optional PKCE support**:

  * Disabled by default.
  * Enable with `--pkce` flag.
  * Accepts `code_challenge` and `code_challenge_method` during `/authorize`.
  * Enforces `code_verifier` during `/token` exchange.
  * Supports `S256` (preferred) and `plain` methods.
* `.well-known/openid-configuration` discovery endpoint.
* `/jwks.json` endpoint exposing the signing key in JWK format.
* JWT-based tokens (`RS256`) with **RFC7519-compliant timestamps** (`iat`, `nbf`, `exp` are seconds since epoch).
* Configurable TTLs for:

  * Authorization codes
  * Access tokens
  * ID tokens
  * Refresh tokens
* ID Token includes hardcoded claims:

  * `name: "Max Musterman"`
  * `email: "max@example.com"`
* Support for SSL:

  * Provide your own `--ssl-cert/--ssl-key`
  * Or generate ephemeral self-signed certs with `--ssl-quickboot`.
* Optionally override the `issuer` value with `--issuer`.

---

## Requirements

* Python 3.8+
* Dependencies:

  * `flask`
  * `pyjwt`
  * `cryptography`

Install dependencies (using `uv` or pip):

```bash
# With uv
uv venv .venv
source .venv/bin/activate
uv pip install flask pyjwt cryptography

# Or with pip
pip install flask pyjwt cryptography
```

---

## Usage

Run the server:

```bash
python mock_oidc.py [options]
```

### CLI Options

| Flag                 | Description                                             |
| -------------------- | ------------------------------------------------------- |
| `--help`             | Show help message                                       |
| `--port PORT`        | Port to run on (default: 4567)                          |
| `--auth-code-ttl`    | TTL (seconds) for authorization codes (default: 300)    |
| `--access-token-ttl` | TTL (seconds) for access tokens (default: 3600)         |
| `--id-token-ttl`     | TTL (seconds) for ID tokens (default: 3600)             |
| `--refresh-ttl`      | TTL (seconds) for refresh tokens (default: 50400 = 14h) |
| `--cert FILE`        | Certificate (PEM) for token signing                     |
| `--key FILE`         | Private key (PEM) for token signing                     |
| `--ssl-cert FILE`    | SSL certificate for HTTPS service                       |
| `--ssl-key FILE`     | SSL private key for HTTPS service                       |
| `--ssl-quickboot`    | Generate ephemeral SSL + signing certs in memory        |
| `--issuer URL`       | Override issuer string (default: inferred from request) |
| `--pkce`             | Enable PKCE support (default: disabled)                 |

---

## Example: Start with Ephemeral SSL

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

---

## Endpoints

* **`/authorize`** — Presents login form and issues authorization codes.
* **`/token`** — Exchanges auth code or refresh token for tokens. Enforces PKCE when enabled.
* **`/.well-known/openid-configuration`** — OIDC discovery document.
* **`/jwks.json`** — Public key (RSA, JWK format).

---

## Tokens

All tokens are JWTs signed with RS256.

### Access Token

Claims:

* `sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `scope`

### ID Token

Claims:

* `sub`, `iss`, `aud`, `iat`, `nbf`, `exp`
* `name: "Max Musterman"`
* `email: "max@example.com"`

### Refresh Token

Claims:

* `sub`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`, `typ="refresh"`
* Single-use (rotated on each exchange)

---

## Notes

* This is **not production-ready**.
* For **local testing only**.
* No real user database (any non-empty username/password works).
* No client registration enforcement (any `client_id` is accepted).
* PKCE is optional: enable with `--pkce` to test clients that require code challenge/verification.
