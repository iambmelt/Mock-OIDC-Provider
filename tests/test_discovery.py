def test_discovery_returns_200(client):
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200


def test_discovery_has_issuer(client):
    resp = client.get("/.well-known/openid-configuration")
    doc = resp.get_json()
    assert "issuer" in doc
    assert len(doc["issuer"]) > 0
