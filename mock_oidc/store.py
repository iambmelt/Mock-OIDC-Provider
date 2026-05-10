import threading
from collections import deque
from datetime import datetime, timezone
from typing import Optional


class TokenStore:
    """Thread-safe in-memory token store with expiration tracking and audit logging."""

    def __init__(self):
        self._codes: dict = {}
        self._refresh: dict = {}
        self._audit: deque = deque(maxlen=1000)
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

    def record_audit(
        self, event: str, request_id: Optional[str] = None, **kwargs
    ) -> None:
        """Record an audit event.

        Args:
            event: Event type (string identifier)
            request_id: Optional request ID for tracing
            **kwargs: Event details (client_id, sub, scope, error, etc.)
        """
        entry = {
            "ts": datetime.now(timezone.utc).isoformat() + "Z",
            "event": event,
        }
        if request_id:
            entry["request_id"] = request_id
        entry.update(kwargs)

        with self._lock:
            self._audit.append(entry)

    def get_audit_log(
        self,
        limit: int = 100,
        event_filter: Optional[str] = None,
        client_id_filter: Optional[str] = None,
    ) -> tuple[int, list]:
        """Retrieve audit log entries with optional filtering.

        Args:
            limit: Max entries to return (default 100, max 1000)
            event_filter: Optional event type to filter by
            client_id_filter: Optional client_id to filter by

        Returns:
            tuple[int, list]: (total_in_store, filtered_entries)
        """
        limit = min(limit, 1000)

        with self._lock:
            total = len(self._audit)
            entries = list(self._audit)

        # Sort by timestamp, most recent first
        entries.sort(key=lambda x: x["ts"], reverse=True)

        # Apply filters
        if event_filter:
            entries = [e for e in entries if e.get("event") == event_filter]
        if client_id_filter:
            entries = [e for e in entries if e.get("client_id") == client_id_filter]

        # Limit results
        entries = entries[:limit]

        return total, entries


# Backwards compatibility alias
SimpleStore = TokenStore
