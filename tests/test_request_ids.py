"""Tests for X-Request-ID header handling (Phase 5).

Tests verify request ID generation and preservation per HTTP best practices.
"""

import re
from tests.conftest import do_authorize, exchange_code


class TestRequestIDGeneration:
    """Test X-Request-ID generation."""

    def test_request_id_generated_on_missing(self, client):
        """Test X-Request-ID is generated if not provided."""
        resp = client.get("/.well-known/openid-configuration")
        assert "X-Request-ID" in resp.headers
        request_id = resp.headers["X-Request-ID"]
        assert len(request_id) > 0

    def test_request_id_format_is_hex(self, client):
        """Test generated X-Request-ID is hex string.

        secrets.token_hex(8) produces 16 hex characters.
        """
        resp = client.get("/.well-known/openid-configuration")
        request_id = resp.headers["X-Request-ID"]

        # Should be hex (0-9a-f)
        assert re.match(r"^[0-9a-f]+$", request_id)

    def test_request_id_length_consistent(self, client):
        """Test generated request IDs have consistent length."""
        request_ids = []
        for _ in range(5):
            resp = client.get("/.well-known/openid-configuration")
            request_ids.append(resp.headers["X-Request-ID"])

        # All should have same length (token_hex(8) = 16 chars)
        assert all(len(rid) == 16 for rid in request_ids)

    def test_request_id_unique(self, client):
        """Test different requests get different request IDs."""
        request_ids = []
        for _ in range(5):
            resp = client.get("/.well-known/openid-configuration")
            request_ids.append(resp.headers["X-Request-ID"])

        # All should be unique
        assert len(set(request_ids)) == 5


class TestRequestIDPreservation:
    """Test X-Request-ID preservation when provided."""

    def test_request_id_preserved_if_provided(self, client):
        """Test provided X-Request-ID is preserved in response."""
        custom_id = "test-request-id-custom"
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": custom_id}
        )
        assert resp.headers["X-Request-ID"] == custom_id

    def test_request_id_preserved_on_token_endpoint(self, client):
        """Test request ID is preserved on token endpoint."""
        custom_id = "test-token-endpoint-123"
        resp = client.post("/token", data={}, headers={"X-Request-ID": custom_id})
        assert resp.headers["X-Request-ID"] == custom_id

    def test_request_id_preserved_on_userinfo(self, client):
        """Test request ID is preserved on userinfo endpoint."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]

        custom_id = "test-userinfo-req-id"
        resp = client.get(
            "/userinfo",
            headers={
                "Authorization": f"Bearer {access_token}",
                "X-Request-ID": custom_id,
            },
        )
        assert resp.headers["X-Request-ID"] == custom_id

    def test_request_id_with_special_characters(self, client):
        """Test request ID with various characters."""
        custom_id = "req-id_123.test_456"
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": custom_id}
        )
        assert resp.headers["X-Request-ID"] == custom_id

    def test_request_id_with_uuid_format(self, client):
        """Test request ID with UUID format."""
        import uuid

        custom_id = str(uuid.uuid4())
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": custom_id}
        )
        assert resp.headers["X-Request-ID"] == custom_id

    def test_request_id_empty_string_generates_new(self, client):
        """Test empty X-Request-ID header generates new one."""
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": ""}
        )
        request_id = resp.headers["X-Request-ID"]
        # Should generate new ID
        assert len(request_id) > 0
        assert request_id != ""


class TestRequestIDOnAllEndpoints:
    """Test X-Request-ID is present on all endpoints."""

    def test_request_id_on_discovery(self, client):
        """Test X-Request-ID on discovery endpoint."""
        resp = client.get("/.well-known/openid-configuration")
        assert "X-Request-ID" in resp.headers

    def test_request_id_on_token(self, client):
        """Test X-Request-ID on token endpoint."""
        resp = client.post("/token", data={})
        assert "X-Request-ID" in resp.headers

    def test_request_id_on_jwks(self, client):
        """Test X-Request-ID on JWKS endpoint."""
        resp = client.get("/jwks.json")
        assert "X-Request-ID" in resp.headers

    def test_request_id_on_authorize(self, client):
        """Test X-Request-ID on authorize endpoint."""
        resp = client.post(
            "/authorize",
            data={
                "client_id": "test-client",
                "redirect_uri": "http://localhost/cb",
                "scope": "openid",
                "username": "user@example.com",
                "password": "pw",
            },
        )
        assert "X-Request-ID" in resp.headers

    def test_request_id_on_userinfo(self, client):
        """Test X-Request-ID on userinfo endpoint."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]

        resp = client.get(
            "/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert "X-Request-ID" in resp.headers

    def test_request_id_on_introspect(self, client):
        """Test X-Request-ID on introspect endpoint."""
        resp = client.post(
            "/introspect",
            data={
                "token": "dummy-token",
                "client_id": "test-client",
            },
        )
        assert "X-Request-ID" in resp.headers

    def test_request_id_on_revoke(self, client):
        """Test X-Request-ID on revoke endpoint."""
        resp = client.post(
            "/revoke",
            data={
                "token": "dummy-token",
                "client_id": "test-client",
            },
        )
        assert "X-Request-ID" in resp.headers

    def test_request_id_on_error_response(self, client):
        """Test X-Request-ID is present even in error responses."""
        resp = client.post("/token", data={"grant_type": "invalid_grant_type"})
        assert resp.status_code == 400
        assert "X-Request-ID" in resp.headers


class TestRequestIDConsistency:
    """Test request ID consistency across request/response."""

    def test_request_id_in_multiple_requests(self, client):
        """Test request IDs are different across multiple requests."""
        ids = []
        for _ in range(10):
            resp = client.get("/.well-known/openid-configuration")
            ids.append(resp.headers["X-Request-ID"])

        # All should be different
        assert len(set(ids)) == 10

    def test_request_id_consistent_in_same_request(self, client):
        """Test request ID is consistent for request/response pair."""
        custom_id = "consistency-test-id"
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": custom_id}
        )
        response_id = resp.headers["X-Request-ID"]

        # Should match provided ID
        assert response_id == custom_id

    def test_request_id_not_leaked_between_requests(self, client):
        """Test request IDs don't leak between sequential requests."""
        resp1 = client.get("/.well-known/openid-configuration")
        id1 = resp1.headers["X-Request-ID"]

        resp2 = client.get("/.well-known/openid-configuration")
        id2 = resp2.headers["X-Request-ID"]

        # Should be different
        assert id1 != id2


class TestRequestIDFormats:
    """Test various X-Request-ID formats are accepted."""

    def test_numeric_request_id(self, client):
        """Test numeric request ID is preserved."""
        custom_id = "123456789"
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": custom_id}
        )
        assert resp.headers["X-Request-ID"] == custom_id

    def test_alphanumeric_request_id(self, client):
        """Test alphanumeric request ID is preserved."""
        custom_id = "ABC123DEF456"
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": custom_id}
        )
        assert resp.headers["X-Request-ID"] == custom_id

    def test_hyphenated_request_id(self, client):
        """Test hyphenated request ID is preserved."""
        custom_id = "req-id-001-abc"
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": custom_id}
        )
        assert resp.headers["X-Request-ID"] == custom_id

    def test_long_request_id(self, client):
        """Test long request ID is preserved."""
        custom_id = "a" * 100
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": custom_id}
        )
        assert resp.headers["X-Request-ID"] == custom_id
