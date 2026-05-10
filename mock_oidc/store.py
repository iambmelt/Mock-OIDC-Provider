class SimpleStore:
    """Non-thread-safe in-memory token store. Phase 4 upgrades to TokenStore with locks."""

    def __init__(self):
        self._codes: dict = {}
        self._refresh: dict = {}

    def put_code(self, code: str, entry: dict) -> None:
        self._codes[code] = entry

    def pop_code(self, code: str):
        return self._codes.pop(code, None)

    def put_refresh(self, jti: str, entry: dict) -> None:
        self._refresh[jti] = entry

    def pop_refresh(self, jti: str):
        return self._refresh.pop(jti, None)

    def revoke_refresh(self, jti: str) -> bool:
        return self._refresh.pop(jti, None) is not None

    def counts(self) -> dict:
        return {"codes": len(self._codes), "refresh_tokens": len(self._refresh)}
