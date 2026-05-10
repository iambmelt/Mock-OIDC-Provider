import re
from tests.conftest import (
    do_authorize,
    exchange_code,
    decode_jwt,
    concurrent_exchange_code,
)


def test_token_no_grant_type(client):
    resp = client.post("/token", data={})
    assert resp.status_code == 400


def test_token_happy_path(client):
    code, _ = do_authorize(client)
    resp = exchange_code(client, code)
    assert resp.status_code == 200
    data = resp.get_json()
    assert "access_token" in data
    assert "id_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"


def test_token_at_id_token_have_same_sub(client):
    code, _ = do_authorize(client)
    resp = exchange_code(client, code)
    data = resp.get_json()
    at_claims = decode_jwt(data["access_token"])
    it_claims = decode_jwt(data["id_token"])
    assert at_claims["sub"] == it_claims["sub"]


def test_token_invalid_code(client):
    resp = exchange_code(client, "invalid-code-12345")
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"] == "invalid_grant"


def test_token_code_single_use(client):
    code, _ = do_authorize(client)
    resp1 = exchange_code(client, code)
    assert resp1.status_code == 200
    resp2 = exchange_code(client, code)
    assert resp2.status_code == 400
    assert resp2.get_json()["error"] == "invalid_grant"


def test_request_id_header_generated(client):
    """Test that X-Request-ID header is generated if not provided."""
    resp = client.post("/token", data={})
    assert "X-Request-ID" in resp.headers
    request_id = resp.headers["X-Request-ID"]
    # Verify it's a valid hex string (token_hex(8) produces 16 hex chars)
    assert re.match(r"^[0-9a-f]+$", request_id)
    assert len(request_id) == 16  # 8 bytes -> 16 hex chars


def test_request_id_header_preserved(client):
    """Test that provided X-Request-ID header is preserved in response."""
    resp = client.post("/token", data={}, headers={"X-Request-ID": "test-request-123"})
    assert resp.headers["X-Request-ID"] == "test-request-123"


def test_concurrent_code_exchange_thread_safe(client):
    """Test that concurrent attempts to exchange same code are thread-safe."""
    code, _ = do_authorize(client)
    results = concurrent_exchange_code(client, code, num_requests=10)

    # Exactly one should succeed with 200, others fail with 400
    successful = [r for r in results if r[0] == 200]
    failed = [r for r in results if r[0] == 400]

    assert len(successful) == 1, f"Expected 1 success, got {len(successful)}"
    assert len(failed) == 9, f"Expected 9 failures, got {len(failed)}"

    # Verify successful response has tokens
    tokens = successful[0][1]
    assert "access_token" in tokens
    assert "id_token" in tokens


def test_token_refresh_token_exchange(client):
    """Test exchanging a refresh token for new tokens."""
    code, _ = do_authorize(client)
    resp1 = exchange_code(client, code)
    assert resp1.status_code == 200
    data1 = resp1.get_json()
    refresh_token = data1["refresh_token"]

    # Exchange refresh token
    resp2 = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "test-client",
        },
    )
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert "access_token" in data2
    assert "id_token" in data2


def test_token_refresh_single_use(client):
    """Test that refresh tokens are single-use."""
    code, _ = do_authorize(client)
    resp1 = exchange_code(client, code)
    refresh_token = resp1.get_json()["refresh_token"]

    # First refresh should work
    resp2 = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "test-client",
        },
    )
    assert resp2.status_code == 200

    # Second attempt with same refresh token should fail
    resp3 = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "test-client",
        },
    )
    assert resp3.status_code == 400
    assert resp3.get_json()["error"] == "invalid_grant"


# Phase 2 tests - Sub stability and at_hash


def test_token_sub_stable_same_username(client):
    """Test that sub is stable for the same username across multiple authorizations."""
    # First authorization
    code1, _ = do_authorize(client, username="alice@example.com")
    resp1 = exchange_code(client, code1)
    data1 = resp1.get_json()
    at_claims1 = decode_jwt(data1["access_token"])
    id_claims1 = decode_jwt(data1["id_token"])

    # Second authorization with same username
    code2, _ = do_authorize(client, username="alice@example.com")
    resp2 = exchange_code(client, code2)
    data2 = resp2.get_json()
    at_claims2 = decode_jwt(data2["access_token"])
    id_claims2 = decode_jwt(data2["id_token"])

    # Same user should have same sub
    assert at_claims1["sub"] == at_claims2["sub"]
    assert id_claims1["sub"] == id_claims2["sub"]
    assert at_claims1["sub"] == id_claims1["sub"]


def test_token_sub_different_for_different_users(client):
    """Test that sub differs for different users."""
    code1, _ = do_authorize(client, username="alice@example.com")
    resp1 = exchange_code(client, code1)
    data1 = resp1.get_json()
    sub1 = decode_jwt(data1["id_token"])["sub"]

    code2, _ = do_authorize(client, username="bob@example.com")
    resp2 = exchange_code(client, code2)
    data2 = resp2.get_json()
    sub2 = decode_jwt(data2["id_token"])["sub"]

    # Different users should have different subs
    assert sub1 != sub2


def test_token_at_hash_present_in_id_token(client):
    """Test that at_hash is present in ID token when access token is issued."""
    code, _ = do_authorize(client)
    resp = exchange_code(client, code)
    data = resp.get_json()
    id_claims = decode_jwt(data["id_token"])

    # at_hash should be present
    assert "at_hash" in id_claims


def test_token_at_hash_format(client):
    """Test that at_hash is properly formatted (base64url without padding)."""
    code, _ = do_authorize(client)
    resp = exchange_code(client, code)
    data = resp.get_json()
    id_claims = decode_jwt(data["id_token"])
    at_hash = id_claims.get("at_hash")

    # Should be a base64url string (alphanumeric, -, _, no =)
    assert at_hash
    assert all(
        c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for c in at_hash
    )


def test_token_sub_stable_after_refresh(client):
    """Test that sub remains the same after refresh token exchange."""
    code, _ = do_authorize(client, username="charlie@example.com")
    resp1 = exchange_code(client, code)
    data1 = resp1.get_json()
    original_sub = decode_jwt(data1["id_token"])["sub"]
    refresh_token = data1["refresh_token"]

    # Exchange refresh token
    resp2 = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "test-client",
        },
    )
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    refreshed_sub = decode_jwt(data2["id_token"])["sub"]

    # Sub should remain the same
    assert original_sub == refreshed_sub


def test_token_redirect_uri_mismatch_fails(client):
    """Test that redirect_uri mismatch between authorize and token fails."""
    code, _ = do_authorize(client, redirect_uri="http://localhost/cb1")

    # Try to exchange code with different redirect_uri
    resp = exchange_code(client, code, redirect_uri="http://localhost/cb2")
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"] == "invalid_grant"
    assert "redirect_uri" in data.get("error_description", "").lower()


def test_token_redirect_uri_match_succeeds(client):
    """Test that matching redirect_uri succeeds."""
    redirect_uri = "http://example.com/callback"
    code, _ = do_authorize(client, redirect_uri=redirect_uri)

    # Exchange with matching redirect_uri
    resp = exchange_code(client, code, redirect_uri=redirect_uri)
    assert resp.status_code == 200
    assert "access_token" in resp.get_json()


def test_token_pkce_code_challenge_stored(client):
    """Test that code_challenge is stored regardless of PKCE config."""
    import hashlib
    import base64
    from mock_oidc.crypto import base64url_no_pad

    verifier = "a" * 43
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64url_no_pad(digest)

    code, _ = do_authorize(
        client,
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    # Exchange with correct verifier should succeed
    resp = exchange_code(client, code, code_verifier=verifier)
    assert resp.status_code == 200
    assert "access_token" in resp.get_json()


def test_token_pkce_wrong_verifier_fails(client):
    """Test that wrong code_verifier fails PKCE validation."""
    import hashlib
    from mock_oidc.crypto import base64url_no_pad

    verifier = "a" * 43
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64url_no_pad(digest)

    code, _ = do_authorize(
        client,
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    # Exchange with wrong verifier should fail
    wrong_verifier = "b" * 43
    resp = exchange_code(client, code, code_verifier=wrong_verifier)
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"] == "invalid_grant"


def test_token_pkce_missing_verifier_fails(client):
    """Test that missing code_verifier when challenge exists fails."""
    import hashlib
    from mock_oidc.crypto import base64url_no_pad

    verifier = "a" * 43
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64url_no_pad(digest)

    code, _ = do_authorize(
        client,
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    # Exchange without verifier should fail
    resp = exchange_code(client, code)
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"] == "invalid_request"


def test_token_pkce_plain_method(client):
    """Test PKCE with plain code_challenge_method."""
    challenge = "plain_challenge_string_43_chars_minimum"

    code, _ = do_authorize(
        client,
        code_challenge=challenge,
        code_challenge_method="plain",
    )

    # Exchange with same verifier should succeed
    resp = exchange_code(client, code, code_verifier=challenge)
    assert resp.status_code == 200
    assert "access_token" in resp.get_json()
