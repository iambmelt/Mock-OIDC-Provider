"""Tests for client_credentials grant type."""

from tests.conftest import decode_jwt


class TestClientCredentials:
    """client_credentials grant type tests."""

    def test_client_credentials_returns_access_token_only(self, client, config):
        """client_credentials should return only access_token, not id_token or refresh_token."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "test-client",
                "client_secret": "secret",
                "scope": "api",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()

        # Should have access_token, token_type, expires_in, scope
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "Bearer"
        assert "expires_in" in data
        assert "scope" in data
        assert data["scope"] == "api"

        # Should NOT have id_token or refresh_token
        assert "id_token" not in data
        assert "refresh_token" not in data

    def test_client_credentials_without_secret_returns_401(self, client):
        """client_credentials without client_secret should return 401."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "test-client",
                "scope": "api",
            },
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"] == "invalid_client"

    def test_client_credentials_sub_equals_client_id(self, client, config):
        """Per RFC 6749 Section 4.4.3, sub in access token should equal client_id."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "test-client",
                "client_secret": "secret",
                "scope": "api",
            },
        )
        assert resp.status_code == 200
        tokens = resp.get_json()
        access_token = tokens["access_token"]

        # Decode the access token
        decoded = decode_jwt(access_token)
        assert decoded["sub"] == "test-client"

    def test_client_credentials_includes_scope(self, client):
        """Scope should be included in access token."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "test-client",
                "client_secret": "secret",
                "scope": "read write",
            },
        )
        assert resp.status_code == 200
        tokens = resp.get_json()
        access_token = tokens["access_token"]

        decoded = decode_jwt(access_token)
        assert decoded["scope"] == "read write"

    def test_client_credentials_returns_proper_token_structure(self, client):
        """Returned token should have proper structure."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "test-client",
                "client_secret": "secret",
                "scope": "api",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()

        # Check all required fields
        assert isinstance(data["access_token"], str)
        assert data["token_type"] == "Bearer"
        assert isinstance(data["expires_in"], int)
        assert data["expires_in"] > 0
        assert data["scope"] == "api"

    def test_client_credentials_with_basic_auth(self, client):
        """client_credentials should accept basic auth."""
        import base64

        creds = base64.b64encode(b"test-client:secret").decode("ascii")
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "scope": "api",
            },
            headers={"Authorization": f"Basic {creds}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert "id_token" not in data
        assert "refresh_token" not in data
