from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AppConfig:
    """Immutable configuration for Mock OIDC Provider."""
    port: int = 4567
    auth_code_ttl: int = 300
    access_token_ttl: int = 3600
    id_token_ttl: int = 3600
    refresh_ttl: int = 50400
    issuer: Optional[str] = None
    pkce: bool = False
    log_format: str = "text"
    log_level: str = "INFO"
    eviction_interval: int = 60
    users: dict = field(default_factory=dict)
    clients: dict = field(default_factory=dict)
    signing_priv_key: Any = field(default=None, repr=False)
    signing_priv_pem: Optional[bytes] = field(default=None, repr=False)
    signing_cert_pem: Optional[bytes] = field(default=None, repr=False)
    ssl_context: Any = field(default=None, repr=False)
