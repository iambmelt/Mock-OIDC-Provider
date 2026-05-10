"""Tests for TokenStore thread safety and expiration handling."""

import threading
from datetime import timedelta

from mock_oidc.store import TokenStore
from mock_oidc.tokens import now_utc


class TestTokenStoreBasic:
    """Basic TokenStore functionality tests."""

    def test_put_and_pop_code(self):
        """Test putting and popping authorization codes."""
        store = TokenStore()
        entry = {
            "client_id": "test-client",
            "exp": now_utc() + timedelta(seconds=300),
        }
        store.put_code("test-code-123", entry)
        result = store.pop_code("test-code-123")
        assert result == entry
        assert store.pop_code("test-code-123") is None  # Single-use

    def test_pop_code_nonexistent(self):
        """Test popping a non-existent code returns None."""
        store = TokenStore()
        assert store.pop_code("does-not-exist") is None

    def test_put_and_pop_refresh(self):
        """Test putting and popping refresh tokens."""
        store = TokenStore()
        entry = {
            "client_id": "test-client",
            "scope": "openid",
            "exp": now_utc() + timedelta(seconds=3600),
        }
        store.put_refresh("jti-123", entry)
        result = store.pop_refresh("jti-123")
        assert result == entry
        assert store.pop_refresh("jti-123") is None  # Single-use

    def test_pop_refresh_nonexistent(self):
        """Test popping a non-existent refresh token returns None."""
        store = TokenStore()
        assert store.pop_refresh("does-not-exist") is None

    def test_revoke_refresh_exists(self):
        """Test revoking an existing refresh token returns True."""
        store = TokenStore()
        entry = {"client_id": "test-client", "exp": now_utc() + timedelta(seconds=3600)}
        store.put_refresh("jti-123", entry)
        assert store.revoke_refresh("jti-123") is True
        assert store.pop_refresh("jti-123") is None  # Token is gone

    def test_revoke_refresh_nonexistent(self):
        """Test revoking a non-existent refresh token returns False."""
        store = TokenStore()
        assert store.revoke_refresh("does-not-exist") is False

    def test_counts(self):
        """Test counts() returns accurate counts of stored tokens."""
        store = TokenStore()
        assert store.counts() == {"codes": 0, "refresh_tokens": 0}

        exp = now_utc() + timedelta(seconds=300)
        store.put_code("code1", {"exp": exp})
        store.put_code("code2", {"exp": exp})
        store.put_refresh("jti1", {"exp": exp})

        assert store.counts() == {"codes": 2, "refresh_tokens": 1}

        store.pop_code("code1")
        assert store.counts() == {"codes": 1, "refresh_tokens": 1}


class TestEviction:
    """Test expiration eviction functionality."""

    def test_evict_expired_codes(self):
        """Test evict_expired() removes expired codes."""
        store = TokenStore()
        exp_future = now_utc() + timedelta(seconds=300)
        exp_past = now_utc() - timedelta(seconds=300)

        store.put_code("code-valid", {"exp": exp_future})
        store.put_code("code-expired", {"exp": exp_past})

        codes_evicted, refresh_evicted = store.evict_expired()
        assert codes_evicted == 1
        assert refresh_evicted == 0
        assert store.pop_code("code-valid") is not None
        assert store.pop_code("code-expired") is None

    def test_evict_expired_refresh(self):
        """Test evict_expired() removes expired refresh tokens."""
        store = TokenStore()
        exp_future = now_utc() + timedelta(seconds=3600)
        exp_past = now_utc() - timedelta(seconds=3600)

        store.put_refresh("jti-valid", {"exp": exp_future})
        store.put_refresh("jti-expired", {"exp": exp_past})

        codes_evicted, refresh_evicted = store.evict_expired()
        assert codes_evicted == 0
        assert refresh_evicted == 1
        assert store.pop_refresh("jti-valid") is not None
        assert store.pop_refresh("jti-expired") is None

    def test_evict_expired_mixed(self):
        """Test evict_expired() with both codes and refresh tokens."""
        store = TokenStore()
        exp_future = now_utc() + timedelta(seconds=300)
        exp_past = now_utc() - timedelta(seconds=300)

        store.put_code("code-valid", {"exp": exp_future})
        store.put_code("code-expired", {"exp": exp_past})
        store.put_refresh("jti-valid", {"exp": exp_future})
        store.put_refresh("jti-expired", {"exp": exp_past})

        codes_evicted, refresh_evicted = store.evict_expired()
        assert codes_evicted == 1
        assert refresh_evicted == 1

    def test_evict_expired_empty_store(self):
        """Test evict_expired() on empty store returns (0, 0)."""
        store = TokenStore()
        codes_evicted, refresh_evicted = store.evict_expired()
        assert codes_evicted == 0
        assert refresh_evicted == 0


class TestThreadSafety:
    """Test thread safety with concurrent operations."""

    def test_concurrent_pop_code_single_instance(self):
        """Test that concurrent pops of same code only succeeds once.

        This verifies that pop_code is truly single-use and thread-safe.
        """
        store = TokenStore()
        exp = now_utc() + timedelta(seconds=300)
        store.put_code("shared-code", {"exp": exp, "client_id": "test"})

        results = []
        lock = threading.Lock()

        def pop_code():
            result = store.pop_code("shared-code")
            with lock:
                results.append(result)

        # Spawn 10 threads trying to pop the same code
        threads = [threading.Thread(target=pop_code) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Exactly one should get the code, others get None
        assert len(results) == 10
        non_none_results = [r for r in results if r is not None]
        assert len(non_none_results) == 1
        assert non_none_results[0]["client_id"] == "test"

    def test_concurrent_operations_codes_and_refresh(self):
        """Test concurrent put/pop operations on both codes and refresh tokens."""
        store = TokenStore()
        exp = now_utc() + timedelta(seconds=300)
        errors = []
        lock = threading.Lock()

        def add_and_pop_code(code_id):
            try:
                store.put_code(f"code-{code_id}", {"exp": exp, "id": code_id})
                result = store.pop_code(f"code-{code_id}")
                assert result is not None
                assert result["id"] == code_id
            except Exception as e:
                with lock:
                    errors.append(f"code operation {code_id}: {e}")

        def add_and_pop_refresh(jti_id):
            try:
                store.put_refresh(f"jti-{jti_id}", {"exp": exp, "id": jti_id})
                result = store.pop_refresh(f"jti-{jti_id}")
                assert result is not None
                assert result["id"] == jti_id
            except Exception as e:
                with lock:
                    errors.append(f"refresh operation {jti_id}: {e}")

        # Spawn 20 threads (10 for codes, 10 for refresh)
        threads = []
        for i in range(10):
            threads.append(threading.Thread(target=add_and_pop_code, args=(i,)))
            threads.append(threading.Thread(target=add_and_pop_refresh, args=(i,)))

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == [], f"Errors occurred: {errors}"
        assert store.counts() == {"codes": 0, "refresh_tokens": 0}

    def test_concurrent_eviction_and_access(self):
        """Test eviction running concurrently with access operations."""
        store = TokenStore()
        exp_future = now_utc() + timedelta(seconds=300)
        exp_past = now_utc() - timedelta(seconds=100)
        errors = []
        lock = threading.Lock()

        # Pre-populate with a mix of valid and expired tokens
        for i in range(5):
            store.put_code(f"code-valid-{i}", {"exp": exp_future, "id": i})
            store.put_code(f"code-expired-{i}", {"exp": exp_past, "id": i})

        def access_codes():
            try:
                for i in range(5):
                    # Try to pop some codes
                    store.pop_code(f"code-valid-{i}")
            except Exception as e:
                with lock:
                    errors.append(f"access error: {e}")

        def evict_tokens():
            try:
                for _ in range(3):
                    store.evict_expired()
            except Exception as e:
                with lock:
                    errors.append(f"eviction error: {e}")

        threads = [
            threading.Thread(target=access_codes),
            threading.Thread(target=evict_tokens),
            threading.Thread(target=access_codes),
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == [], f"Errors occurred: {errors}"
        # After eviction, all expired codes should be gone
        codes_evicted, _ = store.evict_expired()
        assert codes_evicted == 0  # Already evicted

    def test_concurrent_revoke_and_pop_refresh(self):
        """Test concurrent revoke and pop operations on refresh tokens."""
        store = TokenStore()
        exp = now_utc() + timedelta(seconds=3600)
        jti_list = [f"jti-{i}" for i in range(10)]

        # Pre-populate all JTIs
        for jti in jti_list:
            store.put_refresh(jti, {"exp": exp})

        results = {"revoked": 0, "popped": 0, "errors": []}
        lock = threading.Lock()

        def revoke_jti(jti):
            try:
                if store.revoke_refresh(jti):
                    with lock:
                        results["revoked"] += 1
            except Exception as e:
                with lock:
                    results["errors"].append(f"revoke error: {e}")

        def pop_jti(jti):
            try:
                if store.pop_refresh(jti) is not None:
                    with lock:
                        results["popped"] += 1
            except Exception as e:
                with lock:
                    results["errors"].append(f"pop error: {e}")

        # Half will try to revoke, half will try to pop
        threads = []
        for i, jti in enumerate(jti_list):
            if i % 2 == 0:
                threads.append(threading.Thread(target=revoke_jti, args=(jti,)))
            else:
                threads.append(threading.Thread(target=pop_jti, args=(jti,)))

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Either revoked or popped, but not both (single-use)
        assert results["revoked"] + results["popped"] == 10
        assert results["errors"] == []
