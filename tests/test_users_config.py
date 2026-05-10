"""Tests for users configuration file loading and integration."""
import pytest
import json
import tempfile
import os

from mock_oidc.config import AppConfig
from mock_oidc.crypto import setup_signing_keys
from mock_oidc.provider import create_app
from tests.conftest import do_authorize, exchange_code, decode_jwt


class TestUsersConfig:
    """Users configuration file tests."""

    @pytest.fixture
    def users_config(self):
        """Create a temporary users config file."""
        users = {
            "alice": {"name": "Alice Smith", "email": "alice@example.com", "groups": ["admin", "users"]},
            "bob": {"name": "Bob Johnson", "email": "bob@example.com", "department": "Engineering"},
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(users, f)
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    @pytest.fixture
    def app_with_users(self, users_config):
        """Create app with users config loaded."""
        cfg = AppConfig(eviction_interval=0)
        setup_signing_keys(cfg)

        # Load users config
        with open(users_config, 'r') as f:
            cfg.users = json.load(f)

        app = create_app(cfg)
        app.config["TESTING"] = True
        return app

    def test_known_user_can_authorize(self, app_with_users):
        """Known user should be able to authorize."""
        client = app_with_users.test_client()

        code, _ = do_authorize(client, username="alice", password="pw")
        assert code is not None

        # Exchange code for tokens
        resp = exchange_code(client, code)
        assert resp.status_code == 200

    def test_unknown_user_gets_400(self, app_with_users):
        """Unknown user should get 400 during authorization."""
        client = app_with_users.test_client()

        resp = client.post(
            "/authorize",
            data={
                "username": "unknown",
                "password": "pw",
                "client_id": "test-client",
                "redirect_uri": "http://localhost/cb",
                "scope": "openid",
            },
        )
        assert resp.status_code == 400

    def test_custom_claims_in_id_token(self, app_with_users):
        """Custom claims from users config should appear in ID token."""
        client = app_with_users.test_client()

        code, _ = do_authorize(client, username="alice", password="pw")
        resp = exchange_code(client, code, scope="openid profile")
        assert resp.status_code == 200
        tokens = resp.get_json()
        id_token = tokens["id_token"]

        decoded = decode_jwt(id_token)
        # Name and email come from user config
        assert decoded["name"] == "Alice Smith"
        assert decoded["email"] == "alice@example.com"
        # Custom claim: groups
        assert decoded["groups"] == ["admin", "users"]

    def test_custom_claims_in_userinfo(self, app_with_users):
        """Custom claims should appear in /userinfo."""
        client = app_with_users.test_client()

        code, _ = do_authorize(client, username="bob", password="pw", scope="openid profile email")
        resp = exchange_code(client, code, scope="openid profile email")
        tokens = resp.get_json()
        access_token = tokens["access_token"]

        userinfo_resp = client.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert userinfo_resp.status_code == 200
        data = userinfo_resp.get_json()

        assert data["name"] == "Bob Johnson"
        assert data["email"] == "bob@example.com"
        assert data["department"] == "Engineering"

    def test_claims_in_discovery(self, app_with_users):
        """Dynamic claims should appear in discovery document."""
        client = app_with_users.test_client()

        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        data = resp.get_json()

        claims_supported = data["claims_supported"]
        # Should include standard claims
        assert "sub" in claims_supported
        assert "name" in claims_supported
        assert "email" in claims_supported
        # Should include custom claims from users
        assert "groups" in claims_supported
        assert "department" in claims_supported

    def test_multiple_users_different_claims(self, app_with_users):
        """Different users can have different custom claims."""
        client = app_with_users.test_client()

        # Alice has groups
        code_alice, _ = do_authorize(client, username="alice", password="pw")
        resp_alice = exchange_code(client, code_alice)
        tokens_alice = resp_alice.get_json()
        id_token_alice = tokens_alice["id_token"]
        decoded_alice = decode_jwt(id_token_alice)
        assert "groups" in decoded_alice
        assert "department" not in decoded_alice

        # Bob has department
        code_bob, _ = do_authorize(client, username="bob", password="pw")
        resp_bob = exchange_code(client, code_bob)
        tokens_bob = resp_bob.get_json()
        id_token_bob = tokens_bob["id_token"]
        decoded_bob = decode_jwt(id_token_bob)
        assert "department" in decoded_bob
        assert decoded_bob["department"] == "Engineering"

    def test_no_users_config_accepts_all_users(self):
        """Without users config, any username should be accepted (backward compatible)."""
        cfg = AppConfig(eviction_interval=0)
        setup_signing_keys(cfg)
        # Don't load users config
        assert cfg.users == {}

        app = create_app(cfg)
        app.config["TESTING"] = True
        client = app.test_client()

        # Any user should work
        code, _ = do_authorize(client, username="anybody", password="pw")
        assert code is not None

        resp = exchange_code(client, code)
        assert resp.status_code == 200

    def test_authorization_with_offline_access_and_custom_claims(self, app_with_users):
        """Custom claims should work with offline_access scope."""
        client = app_with_users.test_client()

        code, _ = do_authorize(client, username="alice", password="pw", scope="openid offline_access")
        resp = exchange_code(client, code, scope="openid offline_access")
        assert resp.status_code == 200
        tokens = resp.get_json()

        # ID token should have custom claims
        decoded = decode_jwt(tokens["id_token"])
        assert decoded["groups"] == ["admin", "users"]

        # Should have refresh token
        assert "refresh_token" in tokens
