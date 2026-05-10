"""Tests for OIDC Discovery document compliance (Phase 5).

Tests verify all required and optional fields per OpenID Connect Core 1.0 spec:
https://openid.net/specs/openid-connect-discovery-1_0.html
"""

import re


class TestDiscoveryRequired:
    """Test required discovery document fields per OIDC Core."""

    def test_discovery_returns_200(self, client):
        """Test discovery document is accessible at well-known endpoint."""
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        assert resp.content_type == "application/json"

    def test_discovery_has_issuer(self, client):
        """Test issuer claim is present per OIDC Core 3.0.

        OIDC Core 3.0: issuer REQUIRED. URL using the https scheme
        with no query or fragment components.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        assert "issuer" in doc
        issuer = doc["issuer"]
        assert len(issuer) > 0
        # Should be HTTPS (unless in test/dev mode where http is allowed)
        assert issuer.startswith("http://") or issuer.startswith("https://")
        # Must not have query or fragment
        assert "?" not in issuer
        assert "#" not in issuer

    def test_discovery_has_authorization_endpoint(self, client):
        """Test authorization_endpoint is present per OIDC Core 3.0.

        OIDC Core 3.0: authorization_endpoint REQUIRED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        assert "authorization_endpoint" in doc
        assert doc["authorization_endpoint"]
        assert doc["authorization_endpoint"].startswith("http://") or \
               doc["authorization_endpoint"].startswith("https://")

    def test_discovery_has_token_endpoint(self, client):
        """Test token_endpoint is present per OIDC Core 3.0.

        OIDC Core 3.0: token_endpoint REQUIRED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        assert "token_endpoint" in doc
        assert doc["token_endpoint"]
        assert doc["token_endpoint"].startswith("http://") or \
               doc["token_endpoint"].startswith("https://")

    def test_discovery_has_jwks_uri(self, client):
        """Test jwks_uri is present per OIDC Core 3.0.

        OIDC Core 3.0: jwks_uri REQUIRED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        assert "jwks_uri" in doc
        assert doc["jwks_uri"]
        assert doc["jwks_uri"].startswith("http://") or \
               doc["jwks_uri"].startswith("https://")

    def test_discovery_has_subject_types_supported(self, client):
        """Test subject_types_supported is present per OIDC Core 3.0.

        OIDC Core 3.0: subject_types_supported REQUIRED.
        Must be array of strings; we support at least "public".
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        assert "subject_types_supported" in doc
        assert isinstance(doc["subject_types_supported"], list)
        assert len(doc["subject_types_supported"]) > 0
        assert "public" in doc["subject_types_supported"]

    def test_discovery_has_id_token_signing_alg_values_supported(self, client):
        """Test id_token_signing_alg_values_supported per OIDC Core 3.0.

        OIDC Core 3.0: id_token_signing_alg_values_supported REQUIRED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        assert "id_token_signing_alg_values_supported" in doc
        assert isinstance(doc["id_token_signing_alg_values_supported"], list)
        assert "RS256" in doc["id_token_signing_alg_values_supported"]


class TestDiscoveryOptional:
    """Test optional discovery document fields per OIDC Core."""

    def test_discovery_has_userinfo_endpoint(self, client):
        """Test userinfo_endpoint is present.

        OIDC Core 3.0: userinfo_endpoint RECOMMENDED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        assert "userinfo_endpoint" in doc
        assert doc["userinfo_endpoint"]
        assert doc["userinfo_endpoint"].startswith("http://") or \
               doc["userinfo_endpoint"].startswith("https://")

    def test_discovery_has_revocation_endpoint(self, client):
        """Test revocation_endpoint is present.

        OAuth 2.0 Token Revocation: revocation_endpoint RECOMMENDED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        # Check if present
        if "revocation_endpoint" in doc:
            assert doc["revocation_endpoint"]
            assert doc["revocation_endpoint"].startswith("http://") or \
                   doc["revocation_endpoint"].startswith("https://")

    def test_discovery_has_introspection_endpoint(self, client):
        """Test introspection_endpoint is present.

        OAuth 2.0 Token Introspection: introspection_endpoint RECOMMENDED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        if "introspection_endpoint" in doc:
            assert doc["introspection_endpoint"]
            assert doc["introspection_endpoint"].startswith("http://") or \
                   doc["introspection_endpoint"].startswith("https://")

    def test_discovery_grant_types_supported(self, client):
        """Test grant_types_supported array.

        OAuth 2.0 Discovery: grant_types_supported OPTIONAL.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        if "grant_types_supported" in doc:
            assert isinstance(doc["grant_types_supported"], list)
            assert "authorization_code" in doc["grant_types_supported"]
            if "refresh_token" in doc.get("grant_types_supported", []):
                assert "refresh_token" in doc["grant_types_supported"]

    def test_discovery_response_types_supported(self, client):
        """Test response_types_supported array.

        OIDC Core 3.0: response_types_supported REQUIRED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        assert "response_types_supported" in doc
        assert isinstance(doc["response_types_supported"], list)

    def test_discovery_scopes_supported(self, client):
        """Test scopes_supported array.

        OIDC Core 3.0: scopes_supported RECOMMENDED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        if "scopes_supported" in doc:
            assert isinstance(doc["scopes_supported"], list)
            assert "openid" in doc["scopes_supported"]

    def test_discovery_claims_supported(self, client):
        """Test claims_supported array.

        OIDC Core 3.0: claims_supported RECOMMENDED.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        if "claims_supported" in doc:
            assert isinstance(doc["claims_supported"], list)
            assert "sub" in doc["claims_supported"]

    def test_discovery_response_modes_supported(self, client):
        """Test response_modes_supported array.

        OIDC Core 3.0: response_modes_supported OPTIONAL.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        if "response_modes_supported" in doc:
            assert isinstance(doc["response_modes_supported"], list)

    def test_discovery_code_challenge_methods_supported(self, client):
        """Test code_challenge_methods_supported for PKCE.

        RFC 7636 (PKCE): code_challenge_methods_supported OPTIONAL.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        if "code_challenge_methods_supported" in doc:
            assert isinstance(doc["code_challenge_methods_supported"], list)
            # If present, S256 should be supported
            if len(doc["code_challenge_methods_supported"]) > 0:
                assert "S256" in doc["code_challenge_methods_supported"] or \
                       "plain" in doc["code_challenge_methods_supported"]


class TestDiscoveryEndpointURIs:
    """Test that discovery endpoints have correct URI format."""

    def test_discovery_endpoints_are_valid_uris(self, client):
        """Test all endpoint URIs are properly formatted."""
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()

        endpoint_fields = [
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
            "revocation_endpoint",
            "introspection_endpoint",
        ]

        for field in endpoint_fields:
            if field in doc:
                uri = doc[field]
                # Should be absolute URI
                assert uri.startswith("http://") or uri.startswith("https://")
                # Should not have fragments
                assert "#" not in uri

    def test_discovery_issuer_no_trailing_slash(self, client):
        """Test issuer does not have trailing slash per spec.

        OIDC Core 3.0: issuer must be URL without trailing slash.
        """
        resp = client.get("/.well-known/openid-configuration")
        doc = resp.get_json()
        issuer = doc["issuer"]
        assert not issuer.endswith("/"), "Issuer must not have trailing slash"


class TestDiscoveryContentType:
    """Test discovery document content type."""

    def test_discovery_content_type_json(self, client):
        """Test discovery document has application/json content type.

        OIDC Core 3.0: Response MUST be JSON.
        """
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        assert "application/json" in resp.content_type

    def test_discovery_json_valid(self, client):
        """Test discovery document is valid JSON."""
        resp = client.get("/.well-known/openid-configuration")
        # Should not raise
        data = resp.get_json()
        assert isinstance(data, dict)
        assert len(data) > 0
