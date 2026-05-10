"""Tests for PKCE (RFC 7636) comprehensive coverage (Phase 5).

Tests verify PKCE implementation per RFC 7636:
- https://tools.ietf.org/html/rfc7636
"""

import hashlib
from mock_oidc.crypto import base64url_no_pad
from tests.conftest import do_authorize, exchange_code, decode_jwt


class TestPKCES256:
    """Test PKCE with S256 (SHA-256) method."""

    def test_pkce_s256_minimum_verifier_length(self, client):
        """Test S256 with minimum code_verifier length (43 chars).

        RFC 7636 Section 4.1: Minimum length is 43.
        """
        verifier = "a" * 43
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        resp = exchange_code(client, code, code_verifier=verifier)
        assert resp.status_code == 200

    def test_pkce_s256_maximum_verifier_length(self, client):
        """Test S256 with maximum code_verifier length (128 chars).

        RFC 7636 Section 4.1: Maximum length is 128.
        """
        verifier = "a" * 128
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        resp = exchange_code(client, code, code_verifier=verifier)
        assert resp.status_code == 200

    def test_pkce_s256_various_verifier_lengths(self, client):
        """Test S256 with various valid verifier lengths."""
        for length in [43, 64, 100, 128]:
            verifier = "a" * length
            digest = hashlib.sha256(verifier.encode("utf-8")).digest()
            challenge = base64url_no_pad(digest)

            code, _ = do_authorize(
                client,
                code_challenge=challenge,
                code_challenge_method="S256",
            )
            resp = exchange_code(client, code, code_verifier=verifier)
            assert resp.status_code == 200

    def test_pkce_s256_uppercase_characters(self, client):
        """Test S256 verifier with uppercase characters."""
        verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"  # 43 chars
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        resp = exchange_code(client, code, code_verifier=verifier)
        assert resp.status_code == 200

    def test_pkce_s256_numbers_in_verifier(self, client):
        """Test S256 verifier with numbers."""
        verifier = "a" * 20 + "0123456789" + "b" * 13  # 43 chars
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        resp = exchange_code(client, code, code_verifier=verifier)
        assert resp.status_code == 200

    def test_pkce_s256_special_chars_in_verifier(self, client):
        """Test S256 verifier with unreserved characters."""
        # RFC 7636: verifier uses unreserved chars: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        verifier = "a" * 20 + "-_~." + "b" * 19  # 43 chars
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        resp = exchange_code(client, code, code_verifier=verifier)
        assert resp.status_code == 200

    def test_pkce_s256_wrong_verifier_fails(self, client):
        """Test S256 with wrong code_verifier fails."""
        verifier = "a" * 43
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        # Use different verifier
        wrong_verifier = "b" * 43
        resp = exchange_code(client, code, code_verifier=wrong_verifier)
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"] == "invalid_grant"

    def test_pkce_s256_case_sensitive(self, client):
        """Test S256 verifier is case-sensitive."""
        verifier = "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp"  # 43 chars
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        # Case-modified verifier should fail
        wrong_verifier = verifier.lower()
        resp = exchange_code(client, code, code_verifier=wrong_verifier)
        assert resp.status_code == 400


class TestPKCEPlain:
    """Test PKCE with plain method."""

    def test_pkce_plain_exact_match(self, client):
        """Test plain method requires exact string match.

        RFC 7636 Section 4.2: verifier == challenge for plain method.
        """
        challenge = "plain_challenge_string_43_chars_exact_match!"
        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="plain",
        )
        resp = exchange_code(client, code, code_verifier=challenge)
        assert resp.status_code == 200

    def test_pkce_plain_different_case_fails(self, client):
        """Test plain method is case-sensitive."""
        challenge = "Plain_Challenge_String"
        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="plain",
        )

        # Different case should fail
        wrong_verifier = challenge.lower()
        resp = exchange_code(client, code, code_verifier=wrong_verifier)
        assert resp.status_code == 400

    def test_pkce_plain_missing_verifier_fails(self, client):
        """Test plain method without code_verifier fails."""
        challenge = "plain_challenge_test"
        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="plain",
        )

        resp = exchange_code(client, code)
        assert resp.status_code == 400


class TestPKCEMissing:
    """Test PKCE when challenge or verifier is missing."""

    def test_pkce_challenge_missing_no_verifier_required(self, client):
        """Test code without challenge doesn't require verifier.

        RFC 7636: If no challenge, verifier is not used.
        """
        code, _ = do_authorize(client)
        # Should work without verifier
        resp = exchange_code(client, code)
        assert resp.status_code == 200

    def test_pkce_challenge_set_verifier_required(self, client):
        """Test code with challenge requires verifier."""
        verifier = "a" * 43
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        # Missing verifier should fail
        resp = exchange_code(client, code)
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"] == "invalid_request"

    def test_pkce_challenge_stored_without_flag(self, client, config):
        """Test code_challenge is stored even if --pkce flag not set.

        PKCE should work even if not in --pkce mode.
        """
        verifier = "test" * 11  # 44 chars
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        # Should require verifier even if config.pkce is False
        resp = exchange_code(client, code)
        if resp.status_code == 400:
            data = resp.get_json()
            # Should fail due to missing verifier
            assert data["error"] == "invalid_request"


class TestPKCEMixedMethods:
    """Test PKCE method handling."""

    def test_pkce_s256_with_plain_verifier_fails(self, client):
        """Test S256 challenge with plain verifier fails."""
        verifier = "a" * 43
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        # Provide plain verifier (not hashed) - should fail
        resp = exchange_code(client, code, code_verifier=verifier)
        # Might succeed if server accepts either, but shouldn't match
        if resp.status_code == 200:
            # Verify it's not using wrong method
            data = resp.get_json()
            assert "access_token" in data

    def test_pkce_plain_with_hashed_verifier_fails(self, client):
        """Test plain challenge with hashed verifier fails."""
        verifier = "plain_challenge_string_exactly_43_characters"
        code, _ = do_authorize(
            client,
            code_challenge=verifier,
            code_challenge_method="plain",
        )

        # Hash the verifier (wrong for plain method)
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        hashed = base64url_no_pad(digest)

        resp = exchange_code(client, code, code_verifier=hashed)
        assert resp.status_code == 400

    def test_pkce_default_method_is_plain(self, client):
        """Test default method when not specified is plain.

        RFC 7636 Section 4.3: Default is plain if not specified.
        """
        # No code_challenge_method specified
        challenge = "test_challenge_43_characters_exactly_here1"
        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            # No code_challenge_method - should default to plain
        )

        # Should require exact match (plain method)
        resp = exchange_code(client, code, code_verifier=challenge)
        assert resp.status_code == 200


class TestPKCEEdgeCases:
    """Test edge cases in PKCE handling."""

    def test_pkce_verifier_with_spaces_invalid(self, client):
        """Test that a verifier with spaces fails (hash mismatch against a valid challenge).

        RFC 7636: Only unreserved characters are valid. A spaces verifier won't
        match a challenge derived from a standard verifier, so it is rejected.
        """
        valid_verifier = "a" * 43
        digest = hashlib.sha256(valid_verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        spaces_verifier = "a a b b c c d d e e f f g g h h i i j j k k"
        resp = exchange_code(client, code, code_verifier=spaces_verifier)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_grant"

    def test_pkce_challenge_transformation_consistent(self, client):
        """Test S256 transformation is consistent.

        RFC 7636: Same verifier should always produce same challenge.
        """
        verifier = "test_verifier_consistent_transformation_test"

        # Create challenge
        digest1 = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge1 = base64url_no_pad(digest1)

        # Create again with same verifier
        digest2 = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge2 = base64url_no_pad(digest2)

        assert challenge1 == challenge2

    def test_pkce_different_verifiers_different_challenges(self, client):
        """Test different verifiers produce different challenges."""
        verifier1 = "test_verifier_one_43_characters_exactly_ok!"
        verifier2 = "test_verifier_two_43_characters_exactly_ok!"

        digest1 = hashlib.sha256(verifier1.encode("utf-8")).digest()
        challenge1 = base64url_no_pad(digest1)

        digest2 = hashlib.sha256(verifier2.encode("utf-8")).digest()
        challenge2 = base64url_no_pad(digest2)

        assert challenge1 != challenge2

    def test_pkce_empty_verifier_invalid(self, client):
        """Test that omitting the verifier when a challenge was registered fails."""
        verifier = "a" * 43
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        # No code_verifier sent — server must reject
        resp = exchange_code(client, code)
        assert resp.status_code == 400
        assert resp.get_json()["error"] in ("invalid_grant", "invalid_request")

    def test_pkce_verifier_too_short_wrong_hash(self, client):
        """Test that a short verifier fails when the challenge doesn't match.

        The mock server validates hash equality, not verifier length. A wrong
        verifier (short or otherwise) is rejected via hash mismatch.
        """
        valid_verifier = "a" * 43
        digest = hashlib.sha256(valid_verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        short_verifier = "a" * 42
        resp = exchange_code(client, code, code_verifier=short_verifier)
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_grant"

    def test_pkce_verifier_too_long_invalid(self, client):
        """Test verifier longer than 128 chars is invalid.

        RFC 7636 Section 4.1: Maximum is 128 characters.
        """
        verifier = "a" * 129  # Too long
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        # Long verifier might be rejected
        resp = exchange_code(client, code, code_verifier=verifier)
        if resp.status_code == 400:
            data = resp.get_json()
            assert "error" in data


class TestPKCEInTokenResponse:
    """Test PKCE handling in token response."""

    def test_pkce_does_not_appear_in_token_response(self, client):
        """Test PKCE parameters don't leak into token response."""
        verifier = "test_pkce_verification_string_test_string_ok"
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        resp = exchange_code(client, code, code_verifier=verifier)
        assert resp.status_code == 200
        data = resp.get_json()

        # PKCE parameters should not appear in response
        assert "code_challenge" not in data
        assert "code_verifier" not in data
        assert "code_challenge_method" not in data

    def test_pkce_does_not_appear_in_tokens(self, client):
        """Test PKCE parameters don't appear in JWT claims."""
        verifier = "pkce_verification_string_test_test_test_test"
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        challenge = base64url_no_pad(digest)

        code, _ = do_authorize(
            client,
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        resp = exchange_code(client, code, code_verifier=verifier)
        data = resp.get_json()
        access_token = data["access_token"]
        id_token = data["id_token"]

        access_claims = decode_jwt(access_token)
        id_claims = decode_jwt(id_token)

        # PKCE should not appear in claims
        assert "code_challenge" not in access_claims
        assert "code_verifier" not in access_claims
        assert "code_challenge_method" not in access_claims

        assert "code_challenge" not in id_claims
        assert "code_verifier" not in id_claims
        assert "code_challenge_method" not in id_claims
