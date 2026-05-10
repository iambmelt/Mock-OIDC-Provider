"""Tests for /introspect endpoint (RFC 7662)."""
import pytest
from datetime import datetime, timedelta, timezone

from tests.conftest import do_authorize, exchange_code, decode_jwt


class TestIntrospectBasic:
    """Basic /introspect endpoint tests."""

    def test_introspect_valid_access_token_returns_active_true(self, client):
        """Valid access token should return active: true with claims."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        assert resp.status_code == 200
        tokens = resp.get_json()
        access_token = tokens["access_token"]

        # Introspect with client auth
        introspect_resp = client.post(
            "/introspect",
            data={
                "token": access_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert introspect_resp.status_code == 200
        data = introspect_resp.get_json()
        assert data["active"] is True
        assert "sub" in data
        assert "scope" in data
        assert "client_id" in data
        assert data["client_id"] == "test-client"
        assert data["token_type"] == "Bearer"

    def test_introspect_returns_jti(self, client):
        """Introspect should return jti from access token."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        assert resp.status_code == 200
        tokens = resp.get_json()
        access_token = tokens["access_token"]

        introspect_resp = client.post(
            "/introspect",
            data={
                "token": access_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert introspect_resp.status_code == 200
        data = introspect_resp.get_json()
        assert "jti" in data
        assert data["jti"] is not None

    def test_introspect_expired_token_returns_active_false(self, client, config):
        """Expired token should return active: false, not error."""
        # Monkey-patch config to issue very short-lived tokens
        old_ttl = config.access_token_ttl
        config.access_token_ttl = -1  # Already expired

        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        assert resp.status_code == 200
        tokens = resp.get_json()
        access_token = tokens["access_token"]

        config.access_token_ttl = old_ttl  # Restore

        # Introspect the expired token
        introspect_resp = client.post(
            "/introspect",
            data={
                "token": access_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert introspect_resp.status_code == 200
        data = introspect_resp.get_json()
        assert data["active"] is False

    def test_introspect_invalid_signature_returns_active_false(self, client):
        """Token with invalid signature should return active: false, not error."""
        # Create a fake token with bad signature
        bad_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.badsignature"

        introspect_resp = client.post(
            "/introspect",
            data={
                "token": bad_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert introspect_resp.status_code == 200
        data = introspect_resp.get_json()
        assert data["active"] is False

    def test_introspect_missing_token_returns_400(self, client):
        """Missing token parameter should return 400."""
        introspect_resp = client.post(
            "/introspect",
            data={
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert introspect_resp.status_code == 400
        data = introspect_resp.get_json()
        assert data["error"] == "invalid_request"

    def test_introspect_no_client_auth_returns_401(self, client):
        """Request without client authentication should return 401."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        tokens = resp.get_json()
        access_token = tokens["access_token"]

        introspect_resp = client.post(
            "/introspect",
            data={"token": access_token},
        )
        assert introspect_resp.status_code == 401
        data = introspect_resp.get_json()
        assert data["error"] == "invalid_client"

    def test_introspect_includes_exp_and_iat(self, client):
        """Introspect response should include exp and iat."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        tokens = resp.get_json()
        access_token = tokens["access_token"]

        introspect_resp = client.post(
            "/introspect",
            data={
                "token": access_token,
                "client_id": "test-client",
                "client_secret": "secret",
            },
        )
        assert introspect_resp.status_code == 200
        data = introspect_resp.get_json()
        assert "exp" in data
        assert "iat" in data
        assert data["exp"] > data["iat"]
