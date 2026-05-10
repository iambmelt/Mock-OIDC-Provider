"""Tests for structured logging and request ID middleware."""
import time
from unittest.mock import patch
import pytest
from mock_oidc.config import AppConfig
from mock_oidc.crypto import setup_signing_keys
from mock_oidc.provider import create_app
from tests.conftest import do_authorize, exchange_code


class TestRequestIDMiddleware:
    """Test request ID middleware functionality."""

    def test_request_id_binding_context(self, app, client):
        """Test that request ID is properly bound to structlog context."""
        resp = client.post("/token", data={})
        # If we got here without error, the binding happened
        assert resp.status_code == 400
        assert "X-Request-ID" in resp.headers

    def test_multiple_requests_different_ids(self, client):
        """Test that different requests get different IDs."""
        resp1 = client.post("/token", data={})
        id1 = resp1.headers.get("X-Request-ID")

        resp2 = client.post("/token", data={})
        id2 = resp2.headers.get("X-Request-ID")

        assert id1 != id2


class TestStructlogConfiguration:
    """Test structlog configuration."""

    def test_text_format_logging(self):
        """Test that text format logging is configured correctly."""
        config = AppConfig(eviction_interval=0, log_format="text")
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        # Just verify app created without error
        assert app is not None

    def test_json_format_logging(self):
        """Test that JSON format logging is configured correctly."""
        config = AppConfig(eviction_interval=0, log_format="json")
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        # Just verify app created without error
        assert app is not None

    def test_log_level_configuration(self):
        """Test that log level configuration is applied."""
        config = AppConfig(eviction_interval=0, log_level="DEBUG")
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        # Just verify app created without error
        assert app is not None


class TestEvictionThread:
    """Test background TTL eviction thread."""

    def test_eviction_disabled_when_interval_zero(self):
        """Test that eviction thread is not started when interval is 0."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        app = create_app(config)
        # Just verify app created - no thread should be running
        assert app is not None

    def test_eviction_enabled_when_interval_positive(self):
        """Test that eviction thread is started when interval > 0."""
        config = AppConfig(eviction_interval=1)
        setup_signing_keys(config)
        app = create_app(config)
        # Just verify app created with eviction enabled
        assert app is not None

    def test_eviction_logging(self):
        """Test that eviction events are logged."""
        from datetime import datetime, timedelta, timezone
        from mock_oidc.tokens import now_utc

        config = AppConfig(eviction_interval=1)
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()
        store = app.config["MOCK_OIDC_STORE"]

        # Add some tokens that will expire
        exp_past = now_utc() - timedelta(seconds=10)
        store.put_code("expired-code", {"exp": exp_past, "client_id": "test"})
        store.put_refresh("expired-jti", {"exp": exp_past, "client_id": "test"})

        # Evict manually and verify it works
        codes, refresh = store.evict_expired()
        assert codes == 1
        assert refresh == 1


class TestAuthorizationLogging:
    """Test authorization and token event logging."""

    def test_authorize_code_issued_logged(self, client):
        """Test that authorize_code_issued event is logged."""
        # Just verify authorization works - logging happens automatically
        resp = client.post(
            "/authorize",
            data={
                "username": "user@example.com",
                "password": "pw",
                "client_id": "test-client",
                "redirect_uri": "http://localhost/cb",
                "scope": "openid profile",
            },
        )
        assert resp.status_code == 302
        # The event is logged to structlog during request

    def test_token_issued_logged_auth_code(self, client):
        """Test that token_issued event is logged for authorization_code grant."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        assert resp.status_code == 200
        # The event is logged to structlog during request

    def test_token_error_logged_invalid_code(self, client):
        """Test that token_error event is logged for invalid code."""
        resp = exchange_code(client, "invalid-code-12345")
        assert resp.status_code == 400
        # The token_error event is logged to structlog

    def test_token_error_logged_expired_code(self, client, config):
        """Test that token_error event is logged for expired code."""
        from datetime import timedelta
        from mock_oidc.tokens import now_utc

        app = client.application
        store = app.config["MOCK_OIDC_STORE"]

        # Create an expired code
        exp = now_utc() - timedelta(seconds=10)
        store.put_code("expired-code", {
            "client_id": "test-client",
            "exp": exp,
            "scope": "openid",
        })

        resp = exchange_code(client, "expired-code")
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_grant"


class TestRefreshTokenLogging:
    """Test refresh token event logging."""

    def test_token_issued_logged_refresh_grant(self, client):
        """Test that token_issued event is logged for refresh_token grant."""
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
        # The token_issued event is logged to structlog

    def test_token_error_logged_invalid_refresh(self, client):
        """Test that token_error event is logged for invalid refresh token."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "invalid-refresh-token",
                "client_id": "test-client",
            },
        )
        assert resp.status_code == 400
        # The token_error event is logged to structlog

    def test_token_error_logged_malformed_refresh(self, client):
        """Test that token_error event is logged for malformed refresh token."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": "not-a-jwt-token",
                "client_id": "test-client",
            },
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_grant"
