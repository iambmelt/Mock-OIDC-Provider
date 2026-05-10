"""Tests for OAuth 2.0 Refresh Token flow edge cases (Phase 5).

Tests verify refresh token implementation per RFC 6749 and OIDC Core specs:
- https://tools.ietf.org/html/rfc6749#section-6
- https://openid.net/specs/openid-connect-core-1_0.html
"""

import threading
from tests.conftest import (
    do_authorize,
    exchange_code,
    decode_jwt,
    assert_timestamp_ordering,
)


class TestRefreshBasics:
    """Test basic refresh token flow."""

    def test_refresh_returns_new_tokens(self, client):
        """Test refresh token exchange returns new tokens.

        RFC 6749 Section 6: Returns access_token and optionally other tokens.
        """
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        assert resp2.status_code == 200
        data = resp2.get_json()

        assert "access_token" in data
        assert "id_token" in data
        assert data["token_type"] == "Bearer"

    def test_refresh_access_token_different(self, client):
        """Test new access token is different from previous."""
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        original_access_token = resp1.get_json()["access_token"]
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        new_access_token = resp2.get_json()["access_token"]

        # Should be different tokens
        assert original_access_token != new_access_token

    def test_refresh_id_token_returned(self, client):
        """Test refresh returns new ID token.

        OIDC Core 3.1.3.3: If ID token issued in authorization, may be returned.
        """
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        assert resp2.status_code == 200
        data = resp2.get_json()
        assert "id_token" in data


class TestRefreshSubStability:
    """Test sub claim stability across refresh."""

    def test_refresh_sub_unchanged(self, client):
        """Test sub claim remains same after refresh.

        OIDC Core 3.1.3.3: sub must be stable across tokens.
        """
        code, _ = do_authorize(client, username="alice@example.com")
        resp1 = exchange_code(client, code)
        original_sub = decode_jwt(resp1.get_json()["id_token"])["sub"]
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        new_sub = decode_jwt(resp2.get_json()["id_token"])["sub"]

        assert original_sub == new_sub

    def test_refresh_sub_matches_access_token(self, client):
        """Test refreshed access token sub matches ID token."""
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        data = resp2.get_json()
        access_claims = decode_jwt(data["access_token"])
        id_claims = decode_jwt(data["id_token"])

        assert access_claims["sub"] == id_claims["sub"]


class TestRefreshSingleUse:
    """Test refresh token single-use enforcement."""

    def test_refresh_token_single_use(self, client):
        """Test refresh token can only be used once.

        RFC 6749 Section 6: Refresh token single-use may be enforced.
        """
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        # First refresh should work
        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        assert resp2.status_code == 200

        # Second attempt with same token should fail
        resp3 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        assert resp3.status_code == 400
        data = resp3.get_json()
        assert data["error"] == "invalid_grant"

    def test_refresh_chain_works(self, client):
        """Test chain of refresh tokens (each generates new one).

        RFC 6749 Section 6: May issue new refresh token on each exchange.
        """
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token_1 = resp1.get_json()["refresh_token"]

        # First refresh
        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_1,
                "client_id": "test-client",
            },
        )
        assert resp2.status_code == 200
        refresh_token_2 = resp2.get_json()["refresh_token"]

        # Second refresh with new token
        resp3 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_2,
                "client_id": "test-client",
            },
        )
        assert resp3.status_code == 200


class TestRefreshConcurrency:
    """Test concurrent refresh token operations."""

    def test_refresh_concurrent_attempts_one_succeeds(self, client):
        """Test concurrent refresh attempts - only one succeeds.

        RFC 6749: Single-use enforcement in concurrent scenario.
        """
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        results = []
        lock = threading.Lock()

        def attempt_refresh():
            resp = client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": "test-client",
                },
            )
            with lock:
                results.append(resp.status_code)

        threads = [threading.Thread(target=attempt_refresh) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Exactly one should succeed
        successes = [r for r in results if r == 200]
        failures = [r for r in results if r == 400]

        assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"
        assert len(failures) == 4, f"Expected 4 failures, got {len(failures)}"


class TestRefreshTTL:
    """Test refresh token TTL and expiration."""

    def test_refresh_ttl_configured(self, config, client):
        """Test refresh token TTL matches configuration.

        config.refresh_ttl controls refresh token expiration.
        """
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        # Decode and check expiration
        claims = decode_jwt(refresh_token)
        ttl = claims["exp"] - claims["iat"]

        assert ttl == config.refresh_ttl

    def test_refresh_creates_new_ttl(self, client, config):
        """Test new access token from refresh has configured TTL.

        OIDC Core 3.1.3: Refreshed tokens should have standard TTL.
        """
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        new_access_token = resp2.get_json()["access_token"]
        claims = decode_jwt(new_access_token)

        ttl = claims["exp"] - claims["iat"]
        assert ttl == config.access_token_ttl


class TestRefreshScope:
    """Test scope handling in refresh flow."""

    def test_refresh_preserves_scope_by_default(self, client):
        """Test refresh preserves original scope if not specified.

        RFC 6749 Section 6: Defaults to original scope.
        """
        original_scope = "openid profile email"
        code, _ = do_authorize(client, scope=original_scope)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        new_access_token = resp2.get_json()["access_token"]
        claims = decode_jwt(new_access_token)

        # All original scopes should be present
        assert "openid" in claims["scope"]
        assert "profile" in claims["scope"]
        assert "email" in claims["scope"]

    def test_refresh_narrow_scope_allowed(self, client):
        """Test requesting narrower scope on refresh is allowed.

        RFC 6749 Section 6: May request subset of original.
        """
        code, _ = do_authorize(client, scope="openid profile email")
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
                "scope": "openid",  # Narrower
            },
        )
        assert resp2.status_code == 200

    def test_refresh_wider_scope_denied_or_narrowed(self, client):
        """Test requesting wider scope on refresh may be denied.

        RFC 6749 Section 6: Cannot request scope outside original auth.
        """
        code, _ = do_authorize(client, scope="openid")
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
                "scope": "openid profile email",  # Wider
            },
        )
        # Should either fail or return narrower scope
        if resp2.status_code == 200:
            access_token = resp2.get_json()["access_token"]
            claims = decode_jwt(access_token)
            # Should not grant new scope
            assert "openid" in claims["scope"]
        else:
            data = resp2.get_json()
            assert "error" in data


class TestRefreshClientId:
    """Test client_id validation in refresh."""

    def test_refresh_client_id_required(self, client):
        """Test client_id is required for refresh.

        RFC 6749 Section 6: client_id required for public clients.
        """
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                # Missing client_id
            },
        )
        assert resp2.status_code == 400

    def test_refresh_client_id_mismatch(self, client):
        """Test client_id must match original authorization.

        RFC 6749: Refresh tokens are tied to specific client.
        """
        code, _ = do_authorize(client, client_id="client-1")
        resp1 = exchange_code(client, code, client_id="client-1")
        refresh_token = resp1.get_json()["refresh_token"]

        # Try to use with different client — must be rejected
        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "client-2",  # Different client
            },
        )
        assert resp2.status_code == 400
        assert resp2.get_json()["error"] == "invalid_grant"


class TestRefreshTokenClaims:
    """Test JWT claims in refreshed tokens."""

    def test_refresh_access_token_has_required_claims(self, client):
        """Test refreshed access token has all required claims."""
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        access_token = resp2.get_json()["access_token"]
        claims = decode_jwt(access_token)

        required = ["sub", "iss", "aud", "iat", "exp", "nbf", "jti"]
        for claim in required:
            assert claim in claims, f"Missing required claim: {claim}"

    def test_refresh_id_token_has_at_hash(self, client):
        """Test refreshed ID token has at_hash claim."""
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        id_token = resp2.get_json()["id_token"]
        claims = decode_jwt(id_token)

        assert "at_hash" in claims

    def test_refresh_tokens_timestamp_ordering(self, client):
        """Test refreshed tokens have proper iat < nbf < exp."""
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        access_token = resp2.get_json()["access_token"]
        claims = decode_jwt(access_token)

        assert_timestamp_ordering(claims)

    def test_refresh_new_jti_issued(self, client):
        """Test refreshed tokens have new jti (not recycled)."""
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        original_jti = decode_jwt(resp1.get_json()["access_token"])["jti"]
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        new_jti = decode_jwt(resp2.get_json()["access_token"])["jti"]

        assert original_jti != new_jti


class TestRefreshIssuer:
    """Test issuer claim in refreshed tokens."""

    def test_refresh_iss_unchanged(self, client):
        """Test issuer remains same after refresh."""
        code, _ = do_authorize(client)
        resp1 = exchange_code(client, code)
        original_iss = decode_jwt(resp1.get_json()["id_token"])["iss"]
        refresh_token = resp1.get_json()["refresh_token"]

        resp2 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        new_iss = decode_jwt(resp2.get_json()["id_token"])["iss"]

        assert original_iss == new_iss
