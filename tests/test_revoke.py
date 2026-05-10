"""Tests for /revoke endpoint (RFC 7009)."""

from tests.conftest import do_authorize, exchange_code


class TestRevokeBasic:
    """Basic /revoke endpoint tests."""

    def test_revoke_valid_refresh_token_succeeds(self, client):
        """Revoking a valid refresh token should succeed."""
        code, _ = do_authorize(client, scope="openid offline_access")
        resp = exchange_code(client, code, scope="openid offline_access")
        assert resp.status_code == 200
        tokens = resp.get_json()
        refresh_token = tokens["refresh_token"]

        # Revoke the refresh token
        revoke_resp = client.post(
            "/revoke",
            data={
                "token": refresh_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.data == b""  # Empty body per RFC 7009

        # Try to use the revoked token - should fail
        refresh_resp = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        assert refresh_resp.status_code == 400
        error_data = refresh_resp.get_json()
        assert error_data["error"] == "invalid_grant"

    def test_revoke_returns_200_for_already_revoked(self, client):
        """Revoking an already-revoked token should return 200 (idempotent)."""
        code, _ = do_authorize(client, scope="openid offline_access")
        resp = exchange_code(client, code, scope="openid offline_access")
        tokens = resp.get_json()
        refresh_token = tokens["refresh_token"]

        # Revoke once
        revoke_resp1 = client.post(
            "/revoke",
            data={
                "token": refresh_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert revoke_resp1.status_code == 200

        # Revoke again - should still return 200 (idempotent)
        revoke_resp2 = client.post(
            "/revoke",
            data={
                "token": refresh_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert revoke_resp2.status_code == 200
        assert revoke_resp2.data == b""

    def test_revoke_returns_200_for_invalid_token(self, client):
        """Revoking an invalid token should return 200 per RFC 7009."""
        bad_token = "invalid.token.here"

        revoke_resp = client.post(
            "/revoke",
            data={
                "token": bad_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.data == b""

    def test_revoke_returns_empty_body(self, client):
        """Revoke should return empty body, not JSON."""
        code, _ = do_authorize(client, scope="openid offline_access")
        resp = exchange_code(client, code, scope="openid offline_access")
        tokens = resp.get_json()
        refresh_token = tokens["refresh_token"]

        revoke_resp = client.post(
            "/revoke",
            data={
                "token": refresh_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert revoke_resp.status_code == 200
        # Body should be completely empty
        assert revoke_resp.data == b""

    def test_revoke_missing_token_returns_200(self, client):
        """Revoke with missing token should return 200 per RFC 7009."""
        revoke_resp = client.post(
            "/revoke",
            data={
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.data == b""

    def test_revoke_no_client_auth_returns_401(self, client):
        """Revoke without client auth should return 401."""
        code, _ = do_authorize(client, scope="openid offline_access")
        resp = exchange_code(client, code, scope="openid offline_access")
        tokens = resp.get_json()
        refresh_token = tokens["refresh_token"]

        revoke_resp = client.post(
            "/revoke",
            data={"token": refresh_token},
        )
        assert revoke_resp.status_code == 401
        data = revoke_resp.get_json()
        assert data["error"] == "invalid_client"

    def test_revoke_with_basic_auth(self, client):
        """Revoke should accept client_secret_basic authentication."""
        code, _ = do_authorize(client, scope="openid offline_access")
        resp = exchange_code(client, code, scope="openid offline_access")
        tokens = resp.get_json()
        refresh_token = tokens["refresh_token"]

        # Use basic auth instead of form data
        import base64

        creds = base64.b64encode(b"test-client:secret").decode("ascii")
        revoke_resp = client.post(
            "/revoke",
            data={"token": refresh_token},
            headers={"Authorization": f"Basic {creds}"},
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.data == b""

        # Verify token was actually revoked
        refresh_resp = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        assert refresh_resp.status_code == 400
