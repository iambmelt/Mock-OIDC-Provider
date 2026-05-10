def test_jwks_returns_200(client):
    resp = client.get("/jwks.json")
    assert resp.status_code == 200


def test_jwks_has_rsa_key(client):
    resp = client.get("/jwks.json")
    data = resp.get_json()
    assert "keys" in data
    assert len(data["keys"]) > 0
    assert data["keys"][0]["kty"] == "RSA"
