import jwt as pyjwt
import pytest
from urllib.parse import urlparse, parse_qsl

from mock_oidc.config import AppConfig
from mock_oidc.crypto import setup_signing_keys
from mock_oidc.provider import create_app


@pytest.fixture(scope="session")
def base_config():
    """Session-scoped config with ephemeral keys — shared across all tests."""
    cfg = AppConfig(eviction_interval=0)
    setup_signing_keys(cfg)
    return cfg


@pytest.fixture()
def config(base_config):
    """Per-test config; inherits key material from base_config."""
    return base_config


@pytest.fixture()
def app(config):
    app = create_app(config)
    app.config["TESTING"] = True
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


# ===== Test Utilities (Phase 5) =====

def assert_jwt_has_claims(token_str, required_claims):
    """Verify JWT has all required claims.

    Args:
        token_str: JWT token string
        required_claims: List of claim names that must be present
    """
    claims = pyjwt.decode(token_str, options={"verify_signature": False})
    for claim in required_claims:
        assert claim in claims, f"Required claim '{claim}' missing from token"
    return claims


def assert_error_response(response, expected_error, expected_status=400):
    """Check OAuth error response format.

    Args:
        response: Flask test response
        expected_error: Expected error code (e.g., 'invalid_grant')
        expected_status: Expected HTTP status code
    """
    assert response.status_code == expected_status, \
        f"Expected status {expected_status}, got {response.status_code}"
    data = response.get_json()
    assert "error" in data, "Missing 'error' field in error response"
    assert data["error"] == expected_error, \
        f"Expected error '{expected_error}', got '{data['error']}'"
    assert "error_description" in data, "Missing 'error_description' in error response"
    assert data["error_description"], "error_description must be non-empty"
    return data


def get_claim_value(token_str, claim_key):
    """Extract claim value from JWT safely.

    Args:
        token_str: JWT token string
        claim_key: Claim name to extract

    Returns:
        Claim value or None if not present
    """
    claims = pyjwt.decode(token_str, options={"verify_signature": False})
    return claims.get(claim_key)


def assert_timestamp_ordering(claims):
    """Verify JWT timestamp claims are properly ordered: iat <= nbf <= exp.

    Args:
        claims: JWT claims dict (should have 'iat', 'nbf', 'exp')
    """
    iat = claims.get("iat")
    nbf = claims.get("nbf")
    exp = claims.get("exp")

    assert iat is not None, "Missing 'iat' claim"
    assert nbf is not None, "Missing 'nbf' claim"
    assert exp is not None, "Missing 'exp' claim"

    assert iat <= nbf, f"iat ({iat}) must be <= nbf ({nbf})"
    assert nbf <= exp, f"nbf ({nbf}) must be <= exp ({exp})"
    assert iat < exp, f"iat ({iat}) must be < exp ({exp})"


def do_authorize(
    client,
    client_id="test-client",
    redirect_uri="http://localhost/cb",
    scope="openid",
    username="user@example.com",
    password="pw",
    state=None,
    nonce=None,
    code_challenge=None,
    code_challenge_method=None,
):
    """POST to /authorize and extract the code from the redirect."""
    data = {
        "username": username,
        "password": password,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }
    if state:
        data["state"] = state
    if nonce:
        data["nonce"] = nonce
    if code_challenge:
        data["code_challenge"] = code_challenge
    if code_challenge_method:
        data["code_challenge_method"] = code_challenge_method
    resp = client.post("/authorize", data=data)
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    params = dict(parse_qsl(urlparse(loc).query))
    return params["code"], params.get("state")


def exchange_code(
    client,
    code,
    client_id="test-client",
    redirect_uri="http://localhost/cb",
    scope=None,
    code_verifier=None,
):
    """POST to /token with authorization_code grant."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }
    if scope:
        data["scope"] = scope
    if code_verifier:
        data["code_verifier"] = code_verifier
    return client.post("/token", data=data)


def decode_jwt(token_str):
    """Decode JWT without verification for assertion testing."""
    return pyjwt.decode(token_str, options={"verify_signature": False})


def concurrent_exchange_code(client, code, num_requests=5):
    """Helper to test concurrent code exchange attempts.

    Returns a list of response tuples (status_code, json_data or None).
    """
    import threading

    results = []
    lock = threading.Lock()

    def exchange():
        resp = exchange_code(client, code)
        with lock:
            results.append((resp.status_code, resp.get_json() if resp.status_code == 200 else None))

    threads = [threading.Thread(target=exchange) for _ in range(num_requests)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    return results
