import re
from tests.conftest import do_authorize, exchange_code, decode_jwt, concurrent_exchange_code


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
