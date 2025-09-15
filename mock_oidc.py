#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import json
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

# cryptography for RSA keypair + self-signed certs
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# ---------------------------
# CLI / CONFIG
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Mock OIDC IdP (Flask, single file, RFC7519-compliant timestamps)",
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
        "--cert", type=str, help="Certificate PEM for token signing (public part)"
    )
    p.add_argument("--key", type=str, help="Private key PEM for token signing")

    # HTTPS for the Flask service
    p.add_argument(
        "--ssl-cert", type=str, help="SSL certificate PEM for the HTTPS service"
    )
    p.add_argument(
        "--ssl-key", type=str, help="SSL private key PEM for the HTTPS service"
    )

    # Quickboot: ephemeral (in-memory) self-signed certs for service + separate keypair for signing
    p.add_argument(
        "--ssl-quickboot",
        action="store_true",
        help="Generate ephemeral self-signed SSL cert for the service AND a separate RSA keypair for token signing. Nothing persists across restarts.",
    )

    # Optional explicit issuer override (otherwise inferred from request)
    p.add_argument(
        "--issuer", type=str, help="Override issuer (e.g., https://localhost:8443)"
    )

    return p.parse_args()


ARGS = parse_args()
KID = "mock-kid"


# ---------------------------
# TIME HELPERS (RFC7519)
# ---------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def now_ts() -> int:
    # NumericDate per RFC7519: seconds since epoch
    return int(now_utc().timestamp())


def ts_plus(seconds: int) -> int:
    return int((now_utc() + timedelta(seconds=seconds)).timestamp())


# ---------------------------
# KEY MATERIAL
# ---------------------------
def generate_rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem_bytes_private(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def pem_bytes_public_cert_from_key(key, cn="MockOIDC Signing"):
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


def generate_self_signed_service_cert():
    key = generate_rsa_keypair()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "MockOIDC Service")]
    )
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = pem_bytes_private(key)
    return cert_pem, key_pem


# Token signing keypair
if ARGS.ssl_quickboot:
    SIGNING_PRIV_KEY = generate_rsa_keypair()
    SIGNING_PRIV_PEM = pem_bytes_private(SIGNING_PRIV_KEY)
    SIGNING_CERT_PEM = pem_bytes_public_cert_from_key(
        SIGNING_PRIV_KEY, cn="MockOIDC Signing (Ephemeral)"
    )
elif ARGS.cert and ARGS.key:
    with open(ARGS.key, "rb") as f:
        SIGNING_PRIV_PEM = f.read()
    SIGNING_PRIV_KEY = serialization.load_pem_private_key(
        SIGNING_PRIV_PEM, password=None
    )
    with open(ARGS.cert, "rb") as f:
        SIGNING_CERT_PEM = f.read()
else:
    # Default to self-signed signing cert if nothing provided
    SIGNING_PRIV_KEY = generate_rsa_keypair()
    SIGNING_PRIV_PEM = pem_bytes_private(SIGNING_PRIV_KEY)
    SIGNING_CERT_PEM = pem_bytes_public_cert_from_key(
        SIGNING_PRIV_KEY, cn="MockOIDC Signing (Default)"
    )


def load_public_key_from_cert_or_key(pem_bytes: bytes):
    """
    Robustly obtain a public key from either:
      - a PEM-encoded X.509 certificate, or
      - a PEM-encoded public key.
    """
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
        return cert.public_key()
    except Exception:
        # Not a cert; try as a public key
        return serialization.load_pem_public_key(pem_bytes)


PUBLIC_KEY = load_public_key_from_cert_or_key(SIGNING_CERT_PEM)

# Service SSL (HTTPS)
SERVICE_SSL_CONTEXT = None
TEMP_SERVICE_CERT_FILE = None
TEMP_SERVICE_KEY_FILE = None
if ARGS.ssl_quickboot:
    svc_cert_pem, svc_key_pem = generate_self_signed_service_cert()
    cf = tempfile.NamedTemporaryFile(delete=False)
    kf = tempfile.NamedTemporaryFile(delete=False)
    cf.write(svc_cert_pem)
    cf.flush()
    cf.close()
    kf.write(svc_key_pem)
    kf.flush()
    kf.close()
    TEMP_SERVICE_CERT_FILE = cf.name
    TEMP_SERVICE_KEY_FILE = kf.name
elif ARGS.ssl_cert and ARGS.ssl_key:
    TEMP_SERVICE_CERT_FILE = ARGS.ssl_cert
    TEMP_SERVICE_KEY_FILE = ARGS.ssl_key

if TEMP_SERVICE_CERT_FILE and TEMP_SERVICE_KEY_FILE:
    SERVICE_SSL_CONTEXT = (TEMP_SERVICE_CERT_FILE, TEMP_SERVICE_KEY_FILE)

# ---------------------------
# APP + IN-MEMORY STORES
# ---------------------------
app = Flask(__name__)

# Authorization codes: code -> { client_id, redirect_uri, scope, exp (datetime), nonce? }
AUTH_CODES = {}
# Refresh tokens tracked by JTI for single-use rotation:
# jti -> { client_id, scope, exp (datetime) }
REFRESH_JTIS = {}


# ---------------------------
# HELPERS
# ---------------------------
def base64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def current_issuer():
    if ARGS.issuer:
        return ARGS.issuer.rstrip("/")
    scheme = "https" if request.is_secure else "http"
    return f"{scheme}://{request.host}"


def sign_jwt(claims: dict) -> str:
    headers = {"kid": KID, "alg": "RS256", "typ": "JWT"}
    return jwt.encode(claims, SIGNING_PRIV_PEM, algorithm="RS256", headers=headers)


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
    access_token = sign_jwt(access_claims)

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
    id_token = sign_jwt(id_claims)

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
    refresh_token = sign_jwt(refresh_claims)
    REFRESH_JTIS[refresh_jti] = {
        "client_id": client_id,
        "scope": scope,
        "exp": now_utc() + timedelta(seconds=ARGS.refresh_ttl),
    }

    return {
        "access_token": access_token,
        "id_token": id_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": ARGS.access_token_ttl,
        "scope": scope,
    }


# ---------------------------
# VIEWS
# ---------------------------
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
      <input type="submit" value="Sign In">
    </form>
  </body>
</html>
"""


# ---------------------------
# ROUTES
# ---------------------------
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
    )


@app.route("/authorize", methods=["POST"])
def authorize_post():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not username or not password:
        return make_response("Missing username/password", 400)

    code = secrets.token_hex(16)
    AUTH_CODES[code] = {
        "client_id": request.form.get("client_id"),
        "redirect_uri": request.form.get("redirect_uri"),
        "scope": request.form.get("scope") or "openid",
        "exp": now_utc() + timedelta(seconds=ARGS.auth_code_ttl),
        "nonce": request.form.get("nonce") or None,
    }

    ru = urlparse(AUTH_CODES[code]["redirect_uri"])
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
            return jsonify(error="invalid_grant"), 400
        if now_utc() > data["exp"]:
            return jsonify(error="expired_code"), 400

        client_id = request.form.get("client_id") or data["client_id"]
        scope_req = request.form.get("scope")
        scope = scope_req if scope_req else data["scope"]
        tokens = issue_tokens(client_id=client_id, scope=scope, nonce=data.get("nonce"))
        return jsonify(tokens), 200

    elif grant_type == "refresh_token":
        refresh_token = request.form.get("refresh_token")
        if not refresh_token:
            return jsonify(error="invalid_request"), 400

        try:
            # With numeric exp/iat/nbf we can verify standard claims per RFC7519.
            decoded = jwt.decode(
                refresh_token,
                key=PUBLIC_KEY,
                algorithms=["RS256"],
                options={"require": ["exp", "iat", "nbf", "jti"]},  # enforce presence
                audience=None,  # not verifying aud here; you could set it if desired
            )
        except Exception:
            return jsonify(error="invalid_grant"), 400

        jti = decoded.get("jti")
        if not jti or jti not in REFRESH_JTIS:
            return jsonify(error="invalid_grant"), 400

        entry = REFRESH_JTIS.pop(jti)  # single-use rotation
        if now_utc() > entry["exp"]:
            return jsonify(error="expired_token"), 400

        client_id = request.form.get("client_id") or entry["client_id"]
        req_scope = request.form.get("scope")
        if req_scope:
            requested = set(req_scope.split())
            original = set(entry["scope"].split())
            if not requested.issubset(original):
                return jsonify(error="invalid_scope"), 400
            scope = " ".join(sorted(requested))
        else:
            scope = entry["scope"]

        tokens = issue_tokens(client_id=client_id, scope=scope)
        return jsonify(tokens), 200

    else:
        return jsonify(error="unsupported_grant_type"), 400


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


# ---------------------------
# MAIN
# ---------------------------
def main():
    try:
        if SERVICE_SSL_CONTEXT:
            app.run(host="0.0.0.0", port=ARGS.port, ssl_context=SERVICE_SSL_CONTEXT)
        else:
            app.run(host="0.0.0.0", port=ARGS.port)
    finally:
        if ARGS.ssl_quickboot and isinstance(SERVICE_SSL_CONTEXT, tuple):
            cert_file, key_file = SERVICE_SSL_CONTEXT
            for f in (cert_file, key_file):
                try:
                    os.remove(f)
                except Exception:
                    pass


if __name__ == "__main__":
    main()
