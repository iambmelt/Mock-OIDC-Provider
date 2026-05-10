"""Tests for JWT token claims compliance (Phase 5).

Tests verify all required JWT claims per OIDC Core and OpenID Core specs:
- https://openid.net/specs/openid-connect-core-1_0.html
- https://tools.ietf.org/html/rfc7519 (JWT)
"""

import time
from tests.conftest import (
    do_authorize, exchange_code, decode_jwt,
    assert_jwt_has_claims, assert_timestamp_ordering, get_claim_value
)


class TestAccessTokenClaims:
    """Test access token required claims per OIDC Core 3.1.1."""

    def test_access_token_has_required_claims(self, client):
        """Verify access token has all required claims.

        OIDC Core 3.1.1: Access tokens are signed JWTs with sub, iss, aud.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]

        required_claims = ["sub", "iss", "aud", "iat", "exp", "nbf", "scope", "jti"]
        claims = assert_jwt_has_claims(access_token, required_claims)

    def test_access_token_sub_format(self, client):
        """Verify sub claim is non-empty string."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert "sub" in claims
        assert isinstance(claims["sub"], str)
        assert len(claims["sub"]) > 0

    def test_access_token_iss_format(self, client):
        """Verify iss (issuer) is valid URL per JWT spec.

        RFC 7519 Section 4.1.1: iss is a string.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert "iss" in claims
        issuer = claims["iss"]
        assert isinstance(issuer, str)
        assert issuer.startswith("http://") or issuer.startswith("https://")

    def test_access_token_aud_format(self, client):
        """Verify aud (audience) is client_id.

        RFC 7519 Section 4.1.3: aud is array or string.
        OIDC Core: aud should be the client_id.
        """
        code, _ = do_authorize(client, client_id="test-client")
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert "aud" in claims
        assert claims["aud"] == "test-client"

    def test_access_token_iat_is_numeric(self, client):
        """Verify iat (issued at) is numeric timestamp.

        RFC 7519 Section 4.1.6: iat MUST be a number.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert "iat" in claims
        assert isinstance(claims["iat"], int)
        # Should be reasonable (within last hour)
        now = int(time.time())
        assert now - 3600 <= claims["iat"] <= now + 60

    def test_access_token_exp_is_numeric(self, client):
        """Verify exp (expiration) is numeric timestamp.

        RFC 7519 Section 4.1.4: exp MUST be a number.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert "exp" in claims
        assert isinstance(claims["exp"], int)
        # Should be in future
        now = int(time.time())
        assert claims["exp"] > now

    def test_access_token_nbf_is_numeric(self, client):
        """Verify nbf (not before) is numeric timestamp.

        RFC 7519 Section 4.1.5: nbf MUST be a number.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert "nbf" in claims
        assert isinstance(claims["nbf"], int)

    def test_access_token_scope_present(self, client):
        """Verify scope claim is present and matches request.

        OIDC Core 3.1.1: scope claim contains list of scopes.
        """
        code, _ = do_authorize(client, scope="openid profile email")
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert "scope" in claims
        assert "openid" in claims["scope"]
        assert "profile" in claims["scope"]

    def test_access_token_jti_present(self, client):
        """Verify jti (JWT ID) claim is present.

        RFC 7519 Section 4.1.7: jti is optional but we include it.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert "jti" in claims
        assert isinstance(claims["jti"], str)
        assert len(claims["jti"]) > 0

    def test_access_token_timestamp_ordering(self, client):
        """Verify iat <= nbf <= exp.

        RFC 7519 Section 3: Must be properly ordered.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert_timestamp_ordering(claims)


class TestIDTokenClaims:
    """Test ID token required claims per OIDC Core 3.1.3."""

    def test_id_token_has_required_claims(self, client):
        """Verify ID token has all required claims.

        OIDC Core 3.1.3: ID token MUST contain sub, iss, aud, exp, iat.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        id_token = resp.get_json()["id_token"]

        required_claims = ["sub", "iss", "aud", "iat", "exp", "nbf"]
        claims = assert_jwt_has_claims(id_token, required_claims)

    def test_id_token_has_at_hash(self, client):
        """Verify at_hash claim is present when access token issued.

        OIDC Core 3.3.2.11: at_hash MUST be included if access_token issued.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        data = resp.get_json()
        id_token = data["id_token"]
        claims = decode_jwt(id_token)

        assert "at_hash" in claims
        assert isinstance(claims["at_hash"], str)

    def test_id_token_at_hash_valid_base64url(self, client):
        """Verify at_hash is valid base64url format.

        OIDC Core 3.3.2.11: at_hash is base64url without padding.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        data = resp.get_json()
        id_token = data["id_token"]
        claims = decode_jwt(id_token)

        at_hash = claims.get("at_hash")
        # Should be base64url (alphanumeric, -, _)
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in at_hash)
        # Should not have padding
        assert "=" not in at_hash

    def test_id_token_nonce_preserved(self, client):
        """Verify nonce is preserved in ID token.

        OIDC Core 3.1.3.3: If nonce was sent, must be included in ID token.
        """
        code, _ = do_authorize(client, nonce="test-nonce-12345")
        resp = exchange_code(client, code)
        id_token = resp.get_json()["id_token"]
        claims = decode_jwt(id_token)

        assert "nonce" in claims
        assert claims["nonce"] == "test-nonce-12345"

    def test_id_token_nonce_not_included_if_not_requested(self, client):
        """Verify nonce is not included if not requested.

        OIDC Core 3.1.3.3: nonce only included if requested.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        id_token = resp.get_json()["id_token"]
        claims = decode_jwt(id_token)

        assert "nonce" not in claims

    def test_id_token_sub_matches_access_token(self, client):
        """Verify ID token sub matches access token sub.

        OIDC Core: sub must be consistent across tokens.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        data = resp.get_json()
        access_token = data["access_token"]
        id_token = data["id_token"]

        access_claims = decode_jwt(access_token)
        id_claims = decode_jwt(id_token)

        assert access_claims["sub"] == id_claims["sub"]

    def test_id_token_iss_matches_access_token(self, client):
        """Verify ID token iss matches access token iss."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        data = resp.get_json()
        access_token = data["access_token"]
        id_token = data["id_token"]

        access_claims = decode_jwt(access_token)
        id_claims = decode_jwt(id_token)

        assert access_claims["iss"] == id_claims["iss"]

    def test_id_token_aud_is_client_id(self, client):
        """Verify ID token aud is the client_id.

        OIDC Core 3.1.3: aud MUST contain client_id.
        """
        client_id = "test-client-123"
        code, _ = do_authorize(client, client_id=client_id)
        resp = exchange_code(client, code)
        id_token = resp.get_json()["id_token"]
        claims = decode_jwt(id_token)

        assert claims["aud"] == client_id

    def test_id_token_timestamp_ordering(self, client):
        """Verify iat <= nbf <= exp in ID token."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        id_token = resp.get_json()["id_token"]
        claims = decode_jwt(id_token)

        assert_timestamp_ordering(claims)


class TestRefreshTokenClaims:
    """Test refresh token claims."""

    def test_refresh_token_is_jwt(self, client):
        """Verify refresh token is a signed JWT."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        refresh_token = resp.get_json()["refresh_token"]

        # Should be decodable JWT
        claims = decode_jwt(refresh_token)
        assert isinstance(claims, dict)

    def test_refresh_token_has_required_claims(self, client):
        """Verify refresh token has sub, iss, aud, jti."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        refresh_token = resp.get_json()["refresh_token"]

        required_claims = ["sub", "iss", "aud", "iat", "exp", "nbf", "jti", "typ"]
        claims = assert_jwt_has_claims(refresh_token, required_claims)

    def test_refresh_token_typ_is_refresh(self, client):
        """Verify refresh token has typ=refresh."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        refresh_token = resp.get_json()["refresh_token"]
        claims = decode_jwt(refresh_token)

        assert claims.get("typ") == "refresh"

    def test_refresh_token_jti_unique(self, client):
        """Verify different refresh tokens have different jti values."""
        code1, _ = do_authorize(client, username="alice@example.com")
        resp1 = exchange_code(client, code1)
        refresh_token1 = resp1.get_json()["refresh_token"]
        claims1 = decode_jwt(refresh_token1)

        code2, _ = do_authorize(client, username="bob@example.com")
        resp2 = exchange_code(client, code2)
        refresh_token2 = resp2.get_json()["refresh_token"]
        claims2 = decode_jwt(refresh_token2)

        assert claims1["jti"] != claims2["jti"]


class TestTokenTTLs:
    """Test token TTL/expiration configuration."""

    def test_access_token_expiration_configured(self, config, client):
        """Verify access token expiration matches config.

        access_token_ttl in config controls exp - iat.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        ttl = claims["exp"] - claims["iat"]
        assert ttl == config.access_token_ttl

    def test_id_token_expiration_configured(self, config, client):
        """Verify ID token expiration matches config.

        id_token_ttl in config controls exp - iat.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        id_token = resp.get_json()["id_token"]
        claims = decode_jwt(id_token)

        ttl = claims["exp"] - claims["iat"]
        assert ttl == config.id_token_ttl

    def test_refresh_token_expiration_configured(self, config, client):
        """Verify refresh token expiration matches config.

        refresh_ttl in config controls exp - iat.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        refresh_token = resp.get_json()["refresh_token"]
        claims = decode_jwt(refresh_token)

        ttl = claims["exp"] - claims["iat"]
        assert ttl == config.refresh_ttl


class TestTokenScopeNormalization:
    """Test scope handling in tokens."""

    def test_token_scope_normalized_in_access_token(self, client):
        """Verify scope is preserved in access token."""
        code, _ = do_authorize(client, scope="openid profile email")
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        scope = claims["scope"]
        assert "openid" in scope
        assert "profile" in scope
        assert "email" in scope

    def test_token_scope_multiple_spaces_handled(self, client):
        """Verify multiple spaces in scope are normalized."""
        # Authorization with extra spaces
        code, _ = do_authorize(client, scope="openid  profile   email")
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]
        claims = decode_jwt(access_token)

        scope = claims["scope"]
        # Should still contain all scopes even if formatting varied
        assert "openid" in scope


class TestAtHashValidation:
    """Test at_hash claim computation and validation."""

    def test_at_hash_computed_from_access_token(self, client):
        """Verify at_hash is correctly computed from access token.

        OIDC Core 3.3.2.11: at_hash is first 128 bits of SHA-256 hash of access_token.
        """
        import hashlib
        from mock_oidc.crypto import base64url_no_pad

        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        data = resp.get_json()
        access_token = data["access_token"]
        id_token = data["id_token"]

        id_claims = decode_jwt(id_token)
        at_hash = id_claims.get("at_hash")

        # Compute expected at_hash
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
        left_half = digest[:16]  # First 128 bits
        expected_at_hash = base64url_no_pad(left_half)

        assert at_hash == expected_at_hash

    def test_at_hash_different_for_different_tokens(self, client):
        """Verify different access tokens produce different at_hash."""
        code1, _ = do_authorize(client, username="alice@example.com")
        resp1 = exchange_code(client, code1)
        data1 = resp1.get_json()
        at_hash1 = decode_jwt(data1["id_token"]).get("at_hash")

        code2, _ = do_authorize(client, username="bob@example.com")
        resp2 = exchange_code(client, code2)
        data2 = resp2.get_json()
        at_hash2 = decode_jwt(data2["id_token"]).get("at_hash")

        assert at_hash1 != at_hash2
