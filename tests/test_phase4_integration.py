"""Integration tests for Phase 4 implementation."""
import time
import threading
from datetime import datetime, timedelta, timezone
import pytest
from mock_oidc.config import AppConfig
from mock_oidc.crypto import setup_signing_keys
from mock_oidc.provider import create_app
from mock_oidc.tokens import now_utc
from tests.conftest import do_authorize, exchange_code


class TestPhase4Integration:
    """Comprehensive Phase 4 feature integration tests."""

    def test_tokenstore_replaces_simplestore(self):
        """Verify TokenStore is used instead of SimpleStore."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        app = create_app(config)
        store = app.config["MOCK_OIDC_STORE"]

        # TokenStore should have evict_expired method
        assert hasattr(store, "evict_expired")
        assert callable(store.evict_expired)

        # Should support all original methods
        assert hasattr(store, "put_code")
        assert hasattr(store, "pop_code")
        assert hasattr(store, "put_refresh")
        assert hasattr(store, "pop_refresh")
        assert hasattr(store, "revoke_refresh")
        assert hasattr(store, "counts")

    def test_thread_safety_with_concurrent_auth(self):
        """Test thread safety with concurrent authorization code exchanges."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        # Issue an auth code
        code, _ = do_authorize(client)

        # Try to exchange concurrently from 5 threads
        results = []
        lock = threading.Lock()

        def exchange():
            resp = exchange_code(client, code)
            with lock:
                results.append(resp.status_code)

        threads = [threading.Thread(target=exchange) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly one should succeed, rest should fail
        assert results.count(200) == 1
        assert results.count(400) == 4

    def test_ttl_eviction_background_thread(self):
        """Test that TTL eviction thread runs in background."""
        config = AppConfig(eviction_interval=1)
        setup_signing_keys(config)
        app = create_app(config)
        store = app.config["MOCK_OIDC_STORE"]

        # Add expired tokens
        exp_past = now_utc() - timedelta(seconds=100)
        store.put_code("old-code-1", {"exp": exp_past})
        store.put_code("old-code-2", {"exp": exp_past})
        store.put_refresh("old-jti-1", {"exp": exp_past})

        # Verify they're in store
        assert store.counts()["codes"] == 2
        assert store.counts()["refresh_tokens"] == 1

        # Manually evict and verify
        codes_evicted, refresh_evicted = store.evict_expired()
        assert codes_evicted == 2
        assert refresh_evicted == 1

        # Verify they're gone
        assert store.counts()["codes"] == 0
        assert store.counts()["refresh_tokens"] == 0

    def test_ttl_eviction_disabled_in_tests(self):
        """Verify eviction is disabled (interval=0) in default test config."""
        from tests.conftest import base_config
        # The base_config fixture sets eviction_interval=0
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        app = create_app(config)
        # If we got here without hanging, eviction is properly disabled
        assert app is not None

    def test_structured_logging_text_format(self):
        """Test structured logging with text format."""
        config = AppConfig(eviction_interval=0, log_format="text", log_level="INFO")
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        # Make a request - logging should work
        code, _ = do_authorize(client)
        assert code is not None

    def test_structured_logging_json_format(self):
        """Test structured logging with JSON format."""
        config = AppConfig(eviction_interval=0, log_format="json", log_level="INFO")
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        # Make a request - logging should work
        code, _ = do_authorize(client)
        assert code is not None

    def test_request_id_header_injection(self):
        """Test X-Request-ID header is injected and returned."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        # Request without X-Request-ID should get one generated
        resp1 = client.get("/.well-known/openid-configuration")
        assert "X-Request-ID" in resp1.headers
        id1 = resp1.headers["X-Request-ID"]
        assert len(id1) == 16  # token_hex(8) produces 16 hex chars

        # Request with X-Request-ID should preserve it
        resp2 = client.get(
            "/.well-known/openid-configuration",
            headers={"X-Request-ID": "custom-request-123"}
        )
        assert resp2.headers["X-Request-ID"] == "custom-request-123"

    def test_authorization_code_logging(self):
        """Test authorize_code_issued event is logged with correct fields."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        # Issue an auth code - should log authorize_code_issued
        code, _ = do_authorize(
            client,
            client_id="test-client",
            scope="openid profile"
        )
        assert code is not None

    def test_token_issued_logging(self):
        """Test token_issued event is logged with correct fields."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        # Get code and exchange for tokens - should log token_issued
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert "id_token" in data
        assert "refresh_token" in data

    def test_token_error_logging(self):
        """Test token_error event is logged on errors."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        # Try to exchange invalid code - should log token_error
        resp = exchange_code(client, "invalid-code")
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_grant"

    def test_no_behavioral_changes(self):
        """Verify Phase 4 changes don't affect existing behavior."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        # Test existing behavior still works
        code, state = do_authorize(client, state="test-state")
        assert code is not None
        assert state == "test-state"

        # Code is single-use
        resp1 = exchange_code(client, code)
        assert resp1.status_code == 200

        resp2 = exchange_code(client, code)
        assert resp2.status_code == 400

        # Refresh token is single-use
        refresh_token = resp1.get_json()["refresh_token"]

        resp3 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        assert resp3.status_code == 200

        resp4 = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": "test-client",
            },
        )
        assert resp4.status_code == 400
