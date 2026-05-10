"""Tests for concurrent operation safety (Phase 5).

Tests verify thread safety and concurrent access patterns.
"""

import threading
from tests.conftest import do_authorize, exchange_code


class TestConcurrentAuthorization:
    """Test concurrent authorization code generation."""

    def test_concurrent_authorization_same_user(self, client):
        """Test concurrent authorization requests from same user.

        Should generate different codes.
        """
        codes = []
        lock = threading.Lock()

        def authorize():
            code, _ = do_authorize(client, username="alice@example.com")
            with lock:
                codes.append(code)

        threads = [threading.Thread(target=authorize) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(codes) == 5
        # All codes should be different
        assert len(set(codes)) == 5

    def test_concurrent_authorization_different_users(self, client):
        """Test concurrent authorization from different users."""
        codes = []
        lock = threading.Lock()
        users = [f"user{i}@example.com" for i in range(5)]

        def authorize(username):
            code, _ = do_authorize(client, username=username)
            with lock:
                codes.append((username, code))

        threads = [threading.Thread(target=authorize, args=(u,)) for u in users]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(codes) == 5
        # All codes should be different
        code_values = [c[1] for c in codes]
        assert len(set(code_values)) == 5


class TestConcurrentTokenExchange:
    """Test concurrent code exchange operations."""

    def test_concurrent_exchange_same_code_one_succeeds(self, client):
        """Test concurrent exchange of same code - only one succeeds."""
        code, _ = do_authorize(client)

        results = []
        lock = threading.Lock()

        def exchange():
            resp = exchange_code(client, code)
            with lock:
                results.append(
                    (
                        resp.status_code,
                        resp.get_json() if resp.status_code == 200 else None,
                    )
                )

        threads = [threading.Thread(target=exchange) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        successes = [r for r in results if r[0] == 200]
        failures = [r for r in results if r[0] == 400]

        assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"
        assert len(failures) == 9, f"Expected 9 failures, got {len(failures)}"

    def test_concurrent_exchange_different_codes(self, client):
        """Test concurrent exchange of different codes all succeed."""
        codes = []
        for _ in range(5):
            code, _ = do_authorize(client)
            codes.append(code)

        results = []
        lock = threading.Lock()

        def exchange(code):
            resp = exchange_code(client, code)
            with lock:
                results.append(resp.status_code)

        threads = [threading.Thread(target=exchange, args=(c,)) for c in codes]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All should succeed
        assert all(r == 200 for r in results)


class TestConcurrentRefreshToken:
    """Test concurrent refresh token operations."""

    def test_concurrent_refresh_same_token_one_succeeds(self, client):
        """Test concurrent refresh of same token - only one succeeds."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        refresh_token = resp.get_json()["refresh_token"]

        results = []
        lock = threading.Lock()

        def refresh():
            resp = client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": "test-client",
                },
            )
            with lock:
                results.append(
                    (
                        resp.status_code,
                        resp.get_json() if resp.status_code == 200 else None,
                    )
                )

        threads = [threading.Thread(target=refresh) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        successes = [r for r in results if r[0] == 200]
        failures = [r for r in results if r[0] == 400]

        assert len(successes) == 1
        assert len(failures) == 4

    def test_concurrent_refresh_different_tokens(self, client):
        """Test concurrent refresh of different tokens all succeed."""
        refresh_tokens = []
        for _ in range(5):
            code, _ = do_authorize(client)
            resp = exchange_code(client, code)
            refresh_tokens.append(resp.get_json()["refresh_token"])

        results = []
        lock = threading.Lock()

        def refresh(token):
            resp = client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": token,
                    "client_id": "test-client",
                },
            )
            with lock:
                results.append(resp.status_code)

        threads = [threading.Thread(target=refresh, args=(t,)) for t in refresh_tokens]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All should succeed
        assert all(r == 200 for r in results)


class TestConcurrentIntrospection:
    """Test concurrent token introspection."""

    def test_concurrent_introspect_same_token(self, client):
        """Test concurrent introspection of same token all succeed."""
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        access_token = resp.get_json()["access_token"]

        results = []
        lock = threading.Lock()

        def introspect():
            resp = client.post(
                "/introspect",
                data={
                    "token": access_token,
                    "client_id": "test-client",
                },
            )
            with lock:
                results.append(resp.status_code)

        threads = [threading.Thread(target=introspect) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All should succeed
        assert all(r in [200, 400] for r in results)  # 200 or 400 both valid


class TestConcurrentRevocation:
    """Test concurrent token revocation."""

    def test_concurrent_revoke_same_token_one_succeeds(self, client):
        """Test concurrent revocation of same token.

        Different from code/refresh single-use since revoke is idempotent.
        """
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        refresh_token = resp.get_json()["refresh_token"]

        results = []
        lock = threading.Lock()

        def revoke():
            resp = client.post(
                "/revoke",
                data={
                    "token": refresh_token,
                    "client_id": "test-client",
                },
            )
            with lock:
                results.append(resp.status_code)

        threads = [threading.Thread(target=revoke) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Revoke is idempotent - all should return 200
        assert all(r == 200 for r in results)

    def test_concurrent_revoke_different_tokens(self, client):
        """Test concurrent revocation of different tokens."""
        refresh_tokens = []
        for _ in range(5):
            code, _ = do_authorize(client)
            resp = exchange_code(client, code)
            refresh_tokens.append(resp.get_json()["refresh_token"])

        results = []
        lock = threading.Lock()

        def revoke(token):
            resp = client.post(
                "/revoke",
                data={
                    "token": token,
                    "client_id": "test-client",
                },
            )
            with lock:
                results.append(resp.status_code)

        threads = [threading.Thread(target=revoke, args=(t,)) for t in refresh_tokens]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All should succeed
        assert all(r == 200 for r in results)


class TestStoreCountsUnderConcurrency:
    """Test store counts are accurate under concurrent access."""

    def test_store_code_count_accurate_concurrent(self, client):
        """Test store code count is accurate with concurrent operations."""

        # Use app config to access store
        app = client.application
        store = app.config["MOCK_OIDC_STORE"]

        initial_count = store.counts()["codes"]

        codes = []
        lock = threading.Lock()

        def authorize():
            code, _ = do_authorize(client)
            with lock:
                codes.append(code)

        threads = [threading.Thread(target=authorize) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All codes should still be in store
        final_count = store.counts()["codes"]
        assert final_count == initial_count + 5

    def test_store_refresh_count_accurate_concurrent(self, client):
        """Test store refresh token count is accurate with concurrent ops."""

        app = client.application
        store = app.config["MOCK_OIDC_STORE"]

        initial_count = store.counts()["refresh_tokens"]

        refresh_tokens = []
        lock = threading.Lock()

        def authorize_and_exchange():
            code, _ = do_authorize(client)
            resp = exchange_code(client, code)
            token = resp.get_json()["refresh_token"]
            with lock:
                refresh_tokens.append(token)

        threads = [threading.Thread(target=authorize_and_exchange) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        final_count = store.counts()["refresh_tokens"]
        assert final_count == initial_count + 5


class TestMixedConcurrentOperations:
    """Test mixed concurrent operations."""

    def test_concurrent_authorization_and_exchange(self, client):
        """Test concurrent authorization and code exchange."""
        results = []
        lock = threading.Lock()

        def auth_and_exchange():
            try:
                code, _ = do_authorize(client)
                resp = exchange_code(client, code)
                with lock:
                    results.append(resp.status_code)
            except Exception:
                with lock:
                    results.append(None)

        threads = [threading.Thread(target=auth_and_exchange) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All should succeed
        assert all(r == 200 for r in results)

    def test_concurrent_exchange_and_refresh(self, client):
        """Test concurrent code exchange and refresh token use."""
        results = []
        lock = threading.Lock()

        def exchange_and_refresh():
            try:
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
                with lock:
                    results.append((resp1.status_code, resp2.status_code))
            except Exception:
                with lock:
                    results.append((None, None))

        threads = [threading.Thread(target=exchange_and_refresh) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # All should succeed
        assert all(r == (200, 200) for r in results)
