def test_authorize_get_renders_form(client):
    resp = client.get(
        "/authorize?response_type=code&client_id=test&redirect_uri=http://localhost/cb"
    )
    assert resp.status_code == 200
    assert b"<form" in resp.data


def test_authorize_get_wrong_response_type(client):
    resp = client.get(
        "/authorize?response_type=token&client_id=test&redirect_uri=http://localhost/cb"
    )
    assert resp.status_code == 400
