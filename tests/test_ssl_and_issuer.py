"""Tests for SSL context and issuer URI handling (Phase 5).

Tests verify SSL configuration and issuer detection per OIDC Core.
"""

from mock_oidc.config import AppConfig
from mock_oidc.crypto import setup_signing_keys
from mock_oidc.provider import create_app


class TestIssuerURI:
    """Test issuer URI inferred from request vs configuration."""

    def test_issuer_from_request_when_not_configured(self):
        """Test issuer is inferred from request if not configured."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        # No issuer set in config
        assert config.issuer is None

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()

        issuer = data["issuer"]
        # Should infer from request
        assert "http://localhost" in issuer or "http://" in issuer

    def test_issuer_from_config_when_set(self):
        """Test configured issuer takes precedence."""
        config = AppConfig(issuer="https://example.com", eviction_interval=0)
        setup_signing_keys(config)

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()

        assert data["issuer"] == "https://example.com"

    def test_issuer_no_trailing_slash(self):
        """Test issuer does not have trailing slash per OIDC spec.

        OIDC Core 3.0: Issuer must be URL without trailing slash.
        """
        config = AppConfig(issuer="https://example.com/", eviction_interval=0)
        setup_signing_keys(config)

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()

        # Should be stripped of trailing slash
        issuer = data["issuer"]
        assert not issuer.endswith("/")


class TestSchemeDetection:
    """Test scheme detection (http vs https)."""

    def test_http_scheme_in_test_mode(self):
        """Test http scheme is used in test environment."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)
        # No issuer configured

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()

        issuer = data["issuer"]
        # In test, should be http
        assert issuer.startswith("http://")

    def test_issuer_consistency_in_all_endpoints(self):
        """Test issuer is consistent across all endpoints."""
        config = AppConfig(issuer="https://auth.example.com", eviction_interval=0)
        setup_signing_keys(config)

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()

        issuer = data["issuer"]
        assert issuer == "https://auth.example.com"

        # Verify in authorization_endpoint and other discovery fields
        assert data["authorization_endpoint"].startswith(issuer)
        assert data["token_endpoint"].startswith(issuer)


class TestSSLContext:
    """Test SSL context configuration."""

    def test_ssl_context_optional(self):
        """Test SSL context is optional."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)

        # SSL context may be None for testing
        assert config.ssl_context is None or isinstance(config.ssl_context, tuple)

    def test_signing_keys_generated_without_ssl(self):
        """Test signing keys are generated independently of SSL context."""
        config = AppConfig(eviction_interval=0)
        setup_signing_keys(config)

        assert config.signing_priv_pem is not None
        assert config.signing_cert_pem is not None
        assert config.signing_priv_key is not None


class TestEndpointURIs:
    """Test endpoint URIs use correct issuer."""

    def test_authorization_endpoint_includes_issuer(self):
        """Test authorization_endpoint starts with issuer."""
        config = AppConfig(issuer="https://example.com", eviction_interval=0)
        setup_signing_keys(config)

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()

        auth_endpoint = data["authorization_endpoint"]
        assert auth_endpoint.startswith("https://example.com")

    def test_token_endpoint_includes_issuer(self):
        """Test token_endpoint starts with issuer."""
        config = AppConfig(issuer="https://example.com", eviction_interval=0)
        setup_signing_keys(config)

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()

        token_endpoint = data["token_endpoint"]
        assert token_endpoint.startswith("https://example.com")

    def test_jwks_uri_includes_issuer(self):
        """Test jwks_uri starts with issuer."""
        config = AppConfig(issuer="https://example.com", eviction_interval=0)
        setup_signing_keys(config)

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()

        jwks_uri = data["jwks_uri"]
        assert jwks_uri.startswith("https://example.com")

    def test_userinfo_endpoint_includes_issuer(self):
        """Test userinfo_endpoint starts with issuer."""
        config = AppConfig(issuer="https://example.com", eviction_interval=0)
        setup_signing_keys(config)

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/.well-known/openid-configuration")
        data = resp.get_json()

        userinfo_endpoint = data["userinfo_endpoint"]
        assert userinfo_endpoint.startswith("https://example.com")


class TestIssuerInTokens:
    """Test issuer claim in issued tokens."""

    def test_tokens_contain_issuer_claim(self):
        """Test issued tokens contain iss claim matching discovery issuer."""
        from tests.conftest import do_authorize, exchange_code, decode_jwt

        config = AppConfig(issuer="https://example.com", eviction_interval=0)
        setup_signing_keys(config)

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        data = resp.get_json()

        access_token = data["access_token"]
        id_token = data["id_token"]

        access_claims = decode_jwt(access_token)
        id_claims = decode_jwt(id_token)

        assert access_claims["iss"] == "https://example.com"
        assert id_claims["iss"] == "https://example.com"

    def test_iss_claim_matches_discovery_issuer(self):
        """Test iss claim in tokens matches discovery issuer."""
        from tests.conftest import do_authorize, exchange_code, decode_jwt

        config = AppConfig(issuer="https://auth.test.com", eviction_interval=0)
        setup_signing_keys(config)

        app = create_app(config)
        app.config["TESTING"] = True
        client = app.test_client()

        # Get discovery issuer
        resp = client.get("/.well-known/openid-configuration")
        discovery_issuer = resp.get_json()["issuer"]

        # Get token issuer
        code, _ = do_authorize(client)
        resp = exchange_code(client, code)
        token_issuer = decode_jwt(resp.get_json()["id_token"])["iss"]

        assert token_issuer == discovery_issuer
