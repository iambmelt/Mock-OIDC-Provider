#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =========================
# Imports & Constants
# =========================
import argparse
import atexit
import base64
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from flask import (
    Flask,
    request,
    redirect,
    jsonify,
    make_response,
    render_template_string,
)
import jwt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

KID = "mock-oidc-key"


# =========================
# CLI / Config
# =========================
def parse_args():
    p = argparse.ArgumentParser(
        description="Mock OIDC Provider (Flask, single-file)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--port", type=int, default=4567, help="Port to listen on")
    p.add_argument(
        "--auth-code-ttl",
        type=int,
        default=300,
        help="TTL (seconds) for authorization codes",
    )
    p.add_argument(
        "--access-token-ttl",
        type=int,
        default=3600,
        help="TTL (seconds) for access tokens",
    )
    p.add_argument(
        "--id-token-ttl", type=int, default=3600, help="TTL (seconds) for ID tokens"
    )
    p.add_argument(
        "--refresh-ttl",
        type=int,
        default=14 * 3600,
        help="TTL (seconds) for refresh tokens",
    )

    # Token signing keypair (PEM files)
    p.add_argument(
        "--cert",
        type=str,
        help="Certificate PEM for token signing (public part or cert)",
    )
    p.add_argument("--key", type=str, help="Private key PEM for token signing")

    # HTTPS for the Flask service
    p.add_argument(
        "--ssl-cert", type=str, help="SSL certificate PEM for the HTTPS service"
    )
    p.add_argument(
        "--ssl-key", type=str, help="SSL private key PEM for the HTTPS service"
    )

    # Quickboot: ephemeral (in-memory) service cert + separate signing keypair
    p.add_argument(
        "--ssl-quickboot",
        action="store_true",
        help=(
            "Generate ephemeral self-signed SSL cert for the service AND a separate RSA keypair for token signing. "
            "Nothing persists across restarts."
        ),
    )

    # Optional explicit issuer override (otherwise inferred from request)
    p.add_argument(
        "--issuer", type=str, help="Override issuer (e.g., https://localhost:8443)"
    )

    # Optional PKCE enforcement
    p.add_argument(
        "--pkce",
        action="store_true",
        help="Require PKCE for authorization_code exchanges",
    )

    return p.parse_args()


ARGS = parse_args()


# =========================
# Time & Encoding Utilities
# =========================
def now_utc():
    return datetime.now(timezone.utc)


def now_ts():
    return int(now_utc().timestamp())


def ts_plus(seconds: int):
    return int((now_utc() + timedelta(seconds=seconds)).timestamp())


def base64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def base64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# =========================
# Crypto Helpers
# =========================
def generate_rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem_bytes_private(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def pem_bytes_public_cert_from_key(key, cn="MockOIDC Signing") -> bytes:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def load_public_key_from_cert_or_key(pem_bytes: bytes):
    """Load a public key from either an X.509 cert PEM or a raw public key PEM."""
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
        return cert.public_key()
    except Exception:
        return serialization.load_pem_public_key(pem_bytes)


# =========================
# Signing Material
# =========================
if ARGS.cert and ARGS.key:
    with open(ARGS.key, "rb") as f:
        SIGNING_PRIV_PEM = f.read()
    SIGNING_PRIV_KEY = serialization.load_pem_private_key(
        SIGNING_PRIV_PEM, password=None
    )
    with open(ARGS.cert, "rb") as f:
        SIGNING_CERT_PEM = f.read()
else:
    SIGNING_PRIV_KEY = generate_rsa_keypair()
    SIGNING_PRIV_PEM = pem_bytes_private(SIGNING_PRIV_KEY)
    SIGNING_CERT_PEM = pem_bytes_public_cert_from_key(
        SIGNING_PRIV_KEY, cn="MockOIDC Signing (Default)"
    )

PUBLIC_KEY = load_public_key_from_cert_or_key(SIGNING_CERT_PEM)

# =========================
# Service SSL Setup
# =========================
SERVICE_SSL_CONTEXT = None
_TEMP_SSL_FILES = []

if ARGS.ssl_quickboot:
    svc_key = generate_rsa_keypair()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "MockOIDC Service")]
    )
    svc_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(svc_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=svc_key, algorithm=hashes.SHA256())
    )
    cf = tempfile.NamedTemporaryFile(delete=False)
    kf = tempfile.NamedTemporaryFile(delete=False)
    cf.write(svc_cert.public_bytes(serialization.Encoding.PEM))
    cf.flush()
    cf.close()
    kf.write(pem_bytes_private(svc_key))
    kf.flush()
    kf.close()
    SERVICE_SSL_CONTEXT = (cf.name, kf.name)
    _TEMP_SSL_FILES.extend([cf.name, kf.name])
elif ARGS.ssl_cert and ARGS.ssl_key:
    SERVICE_SSL_CONTEXT = (ARGS.ssl_cert, ARGS.ssl_key)


@atexit.register
def _cleanup_temp_ssl_files():
    for f in _TEMP_SSL_FILES:
        try:
            os.remove(f)
        except Exception:
            pass


# =========================
# Flask App & In-Memory Stores
# =========================
app = Flask(__name__)

# Authorization codes: code -> { client_id, redirect_uri, scope, exp (datetime), nonce?, code_challenge?, code_challenge_method? }
AUTH_CODES = {}

# Refresh tokens tracked by JTI for single-use rotation:
# jti -> { client_id, scope, exp (datetime) }
REFRESH_JTIS = {}


# =========================
# App Helpers (need request/app context)
# =========================
def current_issuer():
    if ARGS.issuer:
        return ARGS.issuer.rstrip("/")
    scheme = "https" if request.is_secure else "http"
    return f"{scheme}://{request.host}"


def sign_jwt(claims: dict) -> str:
    headers = {"kid": KID, "alg": "RS256", "typ": "JWT"}
    return jwt.encode(claims, SIGNING_PRIV_PEM, algorithm="RS256", headers=headers)


def oauth_error(error: str, description: str, status: int = 400, headers: dict = None):
    """Standardized OAuth 2.0 error JSON (RFC 6749)."""
    payload = jsonify(error=error, error_description=description)
    return (payload, status) if headers is None else (payload, status, headers)


def issue_tokens(client_id: str, scope: str, nonce: str = None):
    sub = secrets.token_hex(16)
    iss = current_issuer()
    iat = now_ts()

    access_claims = {
        "sub": sub,
        "iss": iss,
        "aud": client_id,
        "iat": iat,
        "nbf": iat,
        "exp": ts_plus(ARGS.access_token_ttl),
        "scope": scope,
    }
    id_claims = {
        "sub": sub,
        "iss": iss,
        "aud": client_id,
        "iat": iat,
        "nbf": iat,
        "exp": ts_plus(ARGS.id_token_ttl),
        "name": "Max Musterman",
        "email": "max@example.com",
    }
    if nonce:
        id_claims["nonce"] = nonce

    refresh_jti = secrets.token_hex(16)
    refresh_claims = {
        "sub": sub,
        "iss": iss,
        "aud": client_id,
        "iat": iat,
        "nbf": iat,
        "exp": ts_plus(ARGS.refresh_ttl),
        "jti": refresh_jti,
        "typ": "refresh",
    }

    REFRESH_JTIS[refresh_jti] = {
        "client_id": client_id,
        "scope": scope,
        "exp": now_utc() + timedelta(seconds=ARGS.refresh_ttl),
    }

    return {
        "access_token": sign_jwt(access_claims),
        "id_token": sign_jwt(id_claims),
        "refresh_token": sign_jwt(refresh_claims),
        "token_type": "Bearer",
        "expires_in": ARGS.access_token_ttl,
        "scope": scope,
    }


def validate_pkce_if_needed(entry: dict, code_verifier: str):
    if not ARGS.pkce:
        return
    code_challenge = entry.get("code_challenge")
    if not code_challenge:
        raise ValueError("pkce_required")
    if not code_verifier:
        raise ValueError("missing_code_verifier")
    method = (entry.get("code_challenge_method") or "plain").upper()
    if method == "PLAIN":
        if code_verifier != code_challenge:
            raise ValueError("invalid_code_verifier")
    elif method == "S256":
        digest = hashes.Hash(hashes.SHA256())
        digest.update(code_verifier.encode("ascii"))
        derived = base64url_no_pad(digest.finalize())
        if derived != code_challenge:
            raise ValueError("invalid_code_verifier")
    else:
        raise ValueError("unsupported_challenge_method")


# =========================
# HTML Templates
# =========================
LOGIN_HTML = """<!DOCTYPE html>
<html>
  <body>
    <h2>Mock OIDC Login</h2>
    <form method="post" action="/authorize">
      <label>Username: <input type="text" name="username"></label><br>
      <label>Password: <input type="password" name="password"></label><br>
      <label>Scopes: <input type="text" name="scope" value="{{ scope }}"></label><br>
      <input type="hidden" name="client_id" value="{{ client_id }}">
      <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
      <input type="hidden" name="state" value="{{ state }}">
      <input type="hidden" name="nonce" value="{{ nonce }}">
      <input type="hidden" name="code_challenge" value="{{ code_challenge }}">
      <input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">
      <input type="submit" value="Sign In">
    </form>
  </body>
</html>
"""

CALLBACK_HTML = """<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8"/>
    <title>OIDC Callback</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }
      .box { border: 1px solid #ddd; padding: 1rem; border-radius: .5rem; max-width: 700px; background: #fafafa; }
      code { background: #fff; padding: .25rem .5rem; border: 1px solid #eee; border-radius: .25rem; }
      button { padding: .5rem .75rem; border: 1px solid #ccc; border-radius: .5rem; cursor: pointer; }
      .muted { color: #666; }
    </style>
  </head>
  <body>
    <div class="box">
      <h2>Callback</h2>
      {% if code %}
        <p>You were supposed to catch this redirect! But since you're already here, here's the authorization code you requested:</p>
        <p><strong>code:</strong> <code id="auth-code">{{ code }}</code></p>
        {% if state %}<p class="muted"><strong>state:</strong> <code id="auth-state">{{ state }}</code></p>{% endif %}
        <p><button id="copy-btn">Copy code to clipboard</button></p>
      {% else %}
        <p>No <code>code</code> parameter was found on this URL.</p>
      {% endif %}
    </div>
    <script>
      (function () {
        var btn = document.getElementById('copy-btn');
        if (!btn) return;
        btn.addEventListener('click', function () {
          var el = document.getElementById('auth-code');
          if (!el) return;
          var text = el.textContent || el.innerText;
          navigator.clipboard.writeText(text).then(function () {
            btn.textContent = 'Copied!';
            setTimeout(function(){ btn.textContent = 'Copy code to clipboard'; }, 1500);
          }, function () {
            var range = document.createRange();
            range.selectNodeContents(el);
            var sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            try { document.execCommand('copy'); btn.textContent = 'Copied!'; }
            catch (e) { btn.textContent = 'Copy failed'; }
            setTimeout(function(){ btn.textContent = 'Copy code to clipboard'; }, 1500);
            sel.removeAllRanges();
          });
        });
      })();
    </script>
  </body>
</html>
"""


# =========================
# Routes
# =========================
@app.route("/authorize", methods=["GET"])
def authorize_get():
    if request.args.get("response_type") != "code":
        return make_response("response_type must be 'code'", 400)

    return render_template_string(
        LOGIN_HTML,
        scope=request.args.get("scope", "openid"),
        client_id=request.args.get("client_id", ""),
        redirect_uri=request.args.get("redirect_uri", ""),
        state=request.args.get("state", ""),
        nonce=request.args.get("nonce", ""),
        code_challenge=request.args.get("code_challenge", ""),
        code_challenge_method=request.args.get("code_challenge_method", ""),
    )


@app.route("/authorize", methods=["POST"])
def authorize_post():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not username or not password:
        return make_response("Missing username/password", 400)

    code = secrets.token_hex(16)
    entry = {
        "client_id": request.form.get("client_id"),
        "redirect_uri": request.form.get("redirect_uri"),
        "scope": request.form.get("scope") or "openid",
        "exp": now_utc() + timedelta(seconds=ARGS.auth_code_ttl),
        "nonce": request.form.get("nonce") or None,
    }
    if ARGS.pkce:
        cc = request.form.get("code_challenge")
        ccm = request.form.get("code_challenge_method") or "plain"
        if cc:
            entry["code_challenge"] = cc
            entry["code_challenge_method"] = ccm

    AUTH_CODES[code] = entry

    ru = urlparse(entry["redirect_uri"])
    q = dict(parse_qsl(ru.query))
    q["code"] = code
    st = request.form.get("state")
    if st:
        q["state"] = st
    new_query = urlencode(q)
    redir = urlunparse(
        (ru.scheme, ru.netloc, ru.path, ru.params, new_query, ru.fragment)
    )
    return redirect(redir, code=302)


@app.route("/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type")

    if grant_type in ("authorization_code", "code"):
        code = request.form.get("code")
        data = AUTH_CODES.pop(code, None)
        if not data:
            return oauth_error(
                "invalid_grant",
                "Authorization code is invalid, already used, or was not issued by this server.",
            )
        if now_utc() > data["exp"]:
            return oauth_error("invalid_grant", "Authorization code has expired.")

        # Optional PKCE verification
        try:
            validate_pkce_if_needed(data, request.form.get("code_verifier"))
        except ValueError as e:
            msg = str(e)
            if msg == "pkce_required":
                return oauth_error(
                    "invalid_request",
                    "PKCE required but no code_challenge associated with this code.",
                )
            if msg == "missing_code_verifier":
                return oauth_error("invalid_request", "Missing code_verifier.")
            if msg == "invalid_code_verifier":
                return oauth_error("invalid_grant", "Invalid code_verifier.")
            if msg == "unsupported_challenge_method":
                return oauth_error(
                    "invalid_request", "Unsupported code_challenge_method."
                )
            return oauth_error("invalid_request", "PKCE validation failed.")

        client_id = request.form.get("client_id") or data["client_id"]
        scope = request.form.get("scope") or data["scope"]
        tokens = issue_tokens(client_id=client_id, scope=scope, nonce=data.get("nonce"))
        return jsonify(tokens), 200

    elif grant_type == "refresh_token":
        refresh_token = request.form.get("refresh_token")
        if not refresh_token:
            return oauth_error("invalid_request", "Missing refresh_token.")

        try:
            decoded = jwt.decode(
                refresh_token,
                key=PUBLIC_KEY,
                algorithms=["RS256"],
                options={"require": ["exp", "iat", "nbf", "jti"]},
                audience=None,  # Not enforcing aud here
            )
        except Exception:
            return oauth_error(
                "invalid_grant",
                "Refresh token is malformed or has an invalid signature.",
            )

        jti = decoded.get("jti")
        if not jti or jti not in REFRESH_JTIS:
            return oauth_error(
                "invalid_grant", "Refresh token has been revoked or already used."
            )

        entry = REFRESH_JTIS.pop(jti)  # single-use rotation
        if now_utc() > entry["exp"]:
            return oauth_error("invalid_grant", "Refresh token has expired.")

        client_id = request.form.get("client_id") or entry["client_id"]
        scope = entry["scope"]
        req_scope = request.form.get("scope")
        if req_scope:
            requested = set(req_scope.split())
            original = set(scope.split())
            if not requested.issubset(original):
                return oauth_error(
                    "invalid_scope",
                    "Requested scope expands the original scope; only narrowing is allowed.",
                )
            scope = " ".join(sorted(requested))

        tokens = issue_tokens(client_id=client_id, scope=scope)
        return jsonify(tokens), 200

    else:
        return oauth_error(
            "unsupported_grant_type",
            "The grant_type is not supported. Use authorization_code or refresh_token.",
        )


@app.route("/.well-known/openid-configuration", methods=["GET"])
def well_known():
    iss = ARGS.issuer.rstrip("/") if ARGS.issuer else current_issuer()
    return jsonify(
        {
            "issuer": iss,
            "authorization_endpoint": f"{iss}/authorize",
            "token_endpoint": f"{iss}/token",
            "jwks_uri": f"{iss}/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256", "plain"],
        }
    )


@app.route("/jwks.json", methods=["GET"])
def jwks():
    pub = PUBLIC_KEY
    numbers = pub.public_numbers()
    n = base64url_uint(numbers.n)
    e = base64url_uint(numbers.e)
    return jsonify(
        {
            "keys": [
                {"kty": "RSA", "use": "sig", "kid": KID, "alg": "RS256", "n": n, "e": e}
            ]
        }
    )


@app.route("/callback", methods=["GET"])
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    return render_template_string(CALLBACK_HTML, code=code, state=state)


# =========================
# Main
# =========================
def main():
    app.run(host="0.0.0.0", port=ARGS.port, ssl_context=SERVICE_SSL_CONTEXT)


if __name__ == "__main__":
    main()
