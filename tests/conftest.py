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
