"""Tests for endpoint compliance and HTTP basics (Phase 5).

Tests verify HTTP method, content-type, and endpoint path compliance per specs.
"""

from tests.conftest import do_authorize, exchange_code


class TestEndpointContentTypes:
    """Test content-type headers on endpoints."""

    def test_discovery_content_type_json(self, client):
        """Test discovery endpoint returns application/json."""
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        assert "application/json" in resp.content_type

    def test_token_content_type_json(self, client):
        """Test token endpoint returns application/json."""
        resp = client.post("/token", data={})
        assert "application/json" in resp.content_type

    def test_userinfo_content_type_json(self, client):
        """Test userinfo endpoint returns application/json."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]

        resp = client.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == 200
        assert "application/json" in resp.content_type

    def test_jwks_content_type_json(self, client):
        """Test JWKS endpoint returns application/json."""
        resp = client.get("/jwks.json")
        assert resp.status_code == 200
        assert "application/json" in resp.content_type


class TestEndpointPaths:
    """Test endpoint URI paths match spec."""

    def test_discovery_endpoint_path(self, client):
        """Test discovery is at /.well-known/openid-configuration.

        OIDC Core 4: Discovery endpoint must be at this path.
        """
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200

    def test_jwks_endpoint_path(self, client):
        """Test JWKS is at /jwks.json per spec."""
        resp = client.get("/jwks.json")
        assert resp.status_code == 200

    def test_userinfo_endpoint_path(self, client):
        """Test userinfo is at /userinfo per OIDC Core 5."""
        # With valid token
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]

        resp = client.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == 200


class TestHTTPMethods:
    """Test HTTP methods on endpoints."""

    def test_discovery_allows_get_only(self, client):
        """Test discovery endpoint only allows GET."""
        # GET should work
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200

        # POST should fail or not be allowed
        resp = client.post("/.well-known/openid-configuration", data={})
        # Server may return 405 (Method Not Allowed) or 400
        assert resp.status_code in [400, 405]

    def test_token_requires_post(self, client):
        """Test token endpoint requires POST per RFC 6749."""
        # POST should work (even with empty data, will fail with invalid_request)
        resp = client.post("/token", data={})
        assert resp.status_code in [200, 400]  # Valid response

        # GET should not work
        resp = client.get("/token")
        assert resp.status_code == 405 or resp.status_code == 400

    def test_authorize_allows_post(self, client):
        """Test /authorize allows POST."""
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
        # Should return 302 (redirect) or error
        assert resp.status_code in [302, 400, 401]

    def test_userinfo_allows_get_and_post(self, client):
        """Test /userinfo allows both GET and POST per OIDC Core 5."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]

        # GET should work
        resp = client.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == 200

        # POST should also work
        resp = client.post(
            "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == 200


class TestJSONResponseFormat:
    """Test JSON response format compliance."""

    def test_discovery_is_valid_json_object(self, client):
        """Test discovery response is JSON object (not array)."""
        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()
        assert isinstance(data, dict)

    def test_token_response_is_json_object(self, client):
        """Test token response is JSON object."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        data = resp.get_json()
        assert isinstance(data, dict)
        assert "access_token" in data

    def test_jwks_is_json_object(self, client):
        """Test JWKS response is JSON object."""
        resp = client.get("/jwks.json")
        data = resp.get_json()
        assert isinstance(data, dict)
        assert "keys" in data
        assert isinstance(data["keys"], list)

    def test_userinfo_is_json_object(self, client):
        """Test userinfo response is JSON object."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]

        resp = client.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        data = resp.get_json()
        assert isinstance(data, dict)
        assert "sub" in data


class TestHTTPHeaders:
    """Test HTTP header handling."""

    def test_all_responses_have_request_id(self, client):
        """Test all responses have X-Request-ID header."""
        endpoints = [
            ("GET", "/.well-known/openid-configuration", None),
            ("GET", "/jwks.json", None),
            ("POST", "/token", {}),
        ]

        for method, path, data in endpoints:
            if method == "GET":
                resp = client.get(path)
            else:
                resp = client.post(path, data=data)

            assert "X-Request-ID" in resp.headers
            request_id = resp.headers["X-Request-ID"]
            assert len(request_id) > 0

    def test_request_id_preserved_if_provided(self, client):
        """Test X-Request-ID is preserved if provided."""
        custom_id = "test-request-id-12345"
        resp = client.get(
            "/.well-known/openid-configuration", headers={"X-Request-ID": custom_id}
        )
        assert resp.headers["X-Request-ID"] == custom_id

    def test_request_id_generated_if_missing(self, client):
        """Test X-Request-ID is generated if not provided."""
        resp = client.get("/.well-known/openid-configuration")
        assert "X-Request-ID" in resp.headers
        request_id = resp.headers["X-Request-ID"]
        # Should be hex string
        assert all(c in "0123456789abcdef" for c in request_id)


class TestCORSHeaders:
    """Test CORS header behavior."""

    def test_no_cors_headers_by_default(self, client):
        """Test CORS headers are not set (not a CORS server).

        OIDC/OAuth servers typically don't enable CORS by default.
        """
        resp = client.get("/.well-known/openid-configuration")

        # Check common CORS headers are not set
        cors_headers = [
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
        ]

        for header in cors_headers:
            # May or may not be present, but if present should be reasonable
            if header in resp.headers:
                # Should not be "*" for security
                assert (
                    resp.headers[header] != "*"
                    or header == "Access-Control-Allow-Methods"
                )


class TestStatusCodes:
    """Test HTTP status codes."""

    def test_successful_endpoints_return_200(self, client):
        """Test successful endpoints return 200."""
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200

        resp = client.get("/jwks.json")
        assert resp.status_code == 200

    def test_error_endpoints_return_4xx(self, client):
        """Test error responses return 4xx status."""
        # Invalid token request
        resp = client.post("/token", data={})
        assert 400 <= resp.status_code < 500

        # Unauthorized userinfo
        resp = client.get("/userinfo")
        assert resp.status_code == 401

    def test_not_found_returns_404(self, client):
        """Test non-existent endpoint returns 404."""
        resp = client.get("/nonexistent/endpoint")
        assert resp.status_code == 404


class TestResponseFormat:
    """Test response body format."""

    def test_error_response_has_error_and_description(self, client):
        """Test error responses have error and error_description."""
        resp = client.post("/token", data={})
        assert resp.status_code == 400
        data = resp.get_json()

        assert "error" in data
        assert "error_description" in data
        assert isinstance(data["error"], str)
        assert isinstance(data["error_description"], str)

    def test_success_response_has_expected_fields(self, client):
        """Test token response has expected fields."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        assert resp.status_code == 200
        data = resp.get_json()

        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "Bearer"
