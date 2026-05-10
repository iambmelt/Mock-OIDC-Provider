from tests.conftest import do_authorize, exchange_code, decode_jwt


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
