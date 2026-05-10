import threading
from datetime import datetime, timezone


class TokenStore:
    """Thread-safe in-memory token store with expiration tracking."""

    def __init__(self):
        self._codes: dict = {}
        self._refresh: dict = {}
        self._lock = threading.Lock()

    def put_code(self, code: str, entry: dict) -> None:
        """Store an authorization code with expiration time."""
        with self._lock:
            self._codes[code] = entry

    def pop_code(self, code: str):
        """Remove and return an authorization code. Single-use; returns None if not found."""
        with self._lock:
            return self._codes.pop(code, None)

    def put_refresh(self, jti: str, entry: dict) -> None:
        """Store a refresh token entry with expiration time."""
        with self._lock:
            self._refresh[jti] = entry

    def pop_refresh(self, jti: str):
        """Remove and return a refresh token entry. Single-use; returns None if not found."""
        with self._lock:
            return self._refresh.pop(jti, None)

    def revoke_refresh(self, jti: str) -> bool:
        """Revoke a refresh token. Returns True if the token existed and was revoked."""
        with self._lock:
            return self._refresh.pop(jti, None) is not None

    def evict_expired(self) -> tuple[int, int]:
        """Remove expired codes and refresh tokens.

        Returns:
            tuple[int, int]: (count_codes_evicted, count_refresh_evicted)
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            expired_codes = [k for k, v in self._codes.items() if now > v["exp"]]
            expired_refresh = [k for k, v in self._refresh.items() if now > v["exp"]]
            for k in expired_codes:
                del self._codes[k]
            for k in expired_refresh:
                del self._refresh[k]
        return len(expired_codes), len(expired_refresh)

    def counts(self) -> dict:
        """Get current count of stored codes and refresh tokens."""
        with self._lock:
            return {"codes": len(self._codes), "refresh_tokens": len(self._refresh)}


# Backwards compatibility alias
SimpleStore = TokenStore
