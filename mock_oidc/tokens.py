import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
import jwt

from mock_oidc.crypto import KID, base64url_no_pad


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_ts() -> int:
    return int(now_utc().timestamp())


def ts_plus(seconds: int) -> int:
    return int((now_utc() + timedelta(seconds=seconds)).timestamp())


def sign_jwt(claims: dict, config) -> str:
    headers = {"kid": KID, "alg": "RS256", "typ": "JWT"}
    return jwt.encode(
        claims, config.signing_priv_pem, algorithm="RS256", headers=headers
    )


def compute_hash_claim(token_value: str) -> str:
    """Compute at_hash claim from access token (left half of SHA-256)."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(token_value.encode("ascii"))
    left_half = digest.finalize()[:16]  # Left half of SHA-256
    return base64url_no_pad(left_half)


def issue_tokens(
    client_id: str,
    scope: str,
    sub: str,
    iss: str,
    store,
    config,
    nonce: str = None,
    user_claims: dict = None,
    username: str = None,
) -> dict:
    """Issue access, ID, and refresh tokens."""
    iat = now_ts()
    access_jti = secrets.token_hex(16)
    refresh_jti = secrets.token_hex(16)

    access_claims = {
        "sub": sub,
        "iss": iss,
        "aud": client_id,
        "iat": iat,
        "nbf": iat,
        "exp": ts_plus(config.access_token_ttl),
        "scope": scope,
        "jti": access_jti,
    }
    if username:
        access_claims["username"] = username
    id_claims = {
        "sub": sub,
        "iss": iss,
        "aud": client_id,
        "iat": iat,
        "nbf": iat,
        "exp": ts_plus(config.id_token_ttl),
        "name": "Max Musterman",
        "email": "max@example.com",
    }
    if nonce:
        id_claims["nonce"] = nonce
    if user_claims:
        id_claims.update(user_claims)

    refresh_claims = {
        "sub": sub,
        "iss": iss,
        "aud": client_id,
        "iat": iat,
        "nbf": iat,
        "exp": ts_plus(config.refresh_ttl),
        "jti": refresh_jti,
        "typ": "refresh",
    }

    # Sign access token first so we can compute at_hash
    access_token = sign_jwt(access_claims, config)
    at_hash = compute_hash_claim(access_token)
    id_claims["at_hash"] = at_hash

    refresh_entry = {
        "client_id": client_id,
        "scope": scope,
        "sub": sub,
        "exp": now_utc() + timedelta(seconds=config.refresh_ttl),
    }
    if username:
        refresh_entry["username"] = username
    store.put_refresh(refresh_jti, refresh_entry)

    return {
        "access_token": access_token,
        "id_token": sign_jwt(id_claims, config),
        "refresh_token": sign_jwt(refresh_claims, config),
        "token_type": "Bearer",  # nosec B105 - OAuth2 token type, not a password
        "expires_in": config.access_token_ttl,
        "scope": scope,
    }


def validate_pkce(entry: dict, code_verifier: str) -> None:
    """Validate PKCE code_verifier against stored code_challenge.

    Raises ValueError with a code string on failure.
    """
    code_challenge = entry.get("code_challenge")
    if not code_challenge:
        raise ValueError("pkce_required")
    if not code_verifier:
        raise ValueError("missing_code_verifier")
    method = entry.get("code_challenge_method", "plain")
    if method == "plain":
        if code_verifier != code_challenge:
            raise ValueError("invalid_code_verifier")
    elif method == "S256":
        digest = hashes.Hash(hashes.SHA256())
        digest.update(code_verifier.encode("ascii"))
        derived = base64url_no_pad(digest.finalize())
        if derived != code_challenge:
            raise ValueError("invalid_code_verifier")
    else:
        raise ValueError("unsupported_challenge_method")
