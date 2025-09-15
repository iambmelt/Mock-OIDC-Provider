#!/usr/bin/env python3
import argparse, base64, secrets, tempfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import jwt
from flask import (
    Flask,
    request,
    redirect,
    jsonify,
    make_response,
    render_template_string,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# ---------------------------
# ARG PARSING
# ---------------------------
parser = argparse.ArgumentParser(description="Mock OIDC Provider")
parser.add_argument("--port", type=int, default=4567)
parser.add_argument("--auth-code-ttl", type=int, default=300)
parser.add_argument("--access-token-ttl", type=int, default=3600)
parser.add_argument("--id-token-ttl", type=int, default=3600)
parser.add_argument("--refresh-ttl", type=int, default=14 * 3600)
parser.add_argument("--cert", help="PEM cert for token signing")
parser.add_argument("--key", help="PEM private key for token signing")
parser.add_argument("--ssl-cert", help="SSL cert for service")
parser.add_argument("--ssl-key", help="SSL key for service")
parser.add_argument(
    "--ssl-quickboot",
    action="store_true",
    help="Ephemeral self-signed SSL + signing certs",
)
parser.add_argument("--issuer", help="Override issuer URL")
parser.add_argument("--pkce", action="store_true", help="Require PKCE")
ARGS = parser.parse_args()


# ---------------------------
# CRYPTO UTILITIES
# ---------------------------
def generate_rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem_bytes_private(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
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
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def load_public_key_from_cert_or_key(pem_bytes):
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
        return cert.public_key()
    except Exception:
        return serialization.load_pem_public_key(pem_bytes)


# ---------------------------
# SIGNING KEYS
# ---------------------------
KID = "mock-oidc-key"
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
    SIGNING_CERT_PEM = pem_bytes_public_cert_from_key(SIGNING_PRIV_KEY)

PUBLIC_KEY = load_public_key_from_cert_or_key(SIGNING_CERT_PEM)

# Service SSL
SERVICE_SSL_CONTEXT = None
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
        .sign(private_key=svc_key, algorithm=hashes.SHA256())
    )
    cf, kf = tempfile.NamedTemporaryFile(delete=False), tempfile.NamedTemporaryFile(
        delete=False
    )
    cf.write(svc_cert.public_bytes(serialization.Encoding.PEM))
    cf.flush()
    cf.close()
    kf.write(pem_bytes_private(svc_key))
    kf.flush()
    kf.close()
    SERVICE_SSL_CONTEXT = (cf.name, kf.name)
elif ARGS.ssl_cert and ARGS.ssl_key:
    SERVICE_SSL_CONTEXT = (ARGS.ssl_cert, ARGS.ssl_key)

# ---------------------------
# APP + STORES
# ---------------------------
app = Flask(__name__)
AUTH_CODES = (
    {}
)  # code -> {client_id, redirect_uri, scope, exp, nonce?, code_challenge?, method?}
REFRESH_JTIS = {}  # jti -> {client_id, scope, exp}


# ---------------------------
# HELPERS
# ---------------------------
def now_utc():
    return datetime.now(timezone.utc)


def now_ts():
    return int(now_utc().timestamp())


def ts_plus(seconds):
    return int((now_utc() + timedelta(seconds=seconds)).timestamp())


def base64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def base64url_no_pad(b: bytes) -> str:
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
    sub, iss, iat = secrets.token_hex(16), current_issuer(), now_ts()
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


def validate_pkce_if_needed(entry, code_verifier):
    if not ARGS.pkce:
        return
    cc = entry.get("code_challenge")
    if not cc:
        raise ValueError("pkce_required")
    if not code_verifier:
        raise ValueError("missing_code_verifier")
    method = (entry.get("code_challenge_method") or "plain").upper()
    if method == "PLAIN" and code_verifier != cc:
        raise ValueError("invalid_code_verifier")
    elif method == "S256":
        digest = hashes.Hash(hashes.SHA256())
        digest.update(code_verifier.encode("ascii"))
        if base64url_no_pad(digest.finalize()) != cc:
            raise ValueError("invalid_code_verifier")
    elif method not in ("PLAIN", "S256"):
        raise ValueError("unsupported_challenge_method")


# ---------------------------
# HTML Templates
# ---------------------------
LOGIN_HTML = """<!DOCTYPE html><html><body>
<h2>Mock OIDC Login</h2>
<form method="post" action="/authorize">
  <label>Username: <input name="username"></label><br>
  <label>Password: <input name="password" type="password"></label><br>
  <label>Scopes: <input name="scope" value="{{ scope }}"></label><br>
  <input type="hidden" name="client_id" value="{{ client_id }}">
  <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
  <input type="hidden" name="state" value="{{ state }}">
  <input type="hidden" name="nonce" value="{{ nonce }}">
  <input type="hidden" name="code_challenge" value="{{ code_challenge }}">
  <input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">
  <input type="submit" value="Sign In">
</form>
</body></html>"""

CALLBACK_HTML = """<!DOCTYPE html><html><body>
<div>
  <h2>Callback</h2>
  {% if code %}
    <p>You were supposed to catch this redirect! But since you're already here, here's the authorization code you requested:</p>
    <p><strong>code:</strong> <code id="auth-code">{{ code }}</code></p>
    {% if state %}<p><strong>state:</strong> <code id="auth-state">{{ state }}</code></p>{% endif %}
    <button id="copy-btn">Copy code to clipboard</button>
  {% else %}
    <p>No code parameter was found.</p>
  {% endif %}
</div>
<script>
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("copy-btn");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const el = document.getElementById("auth-code");
    if (!el) return;
    const text = el.textContent;
    navigator.clipboard.writeText(text).then(() => {
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = "Copy code to clipboard"; }, 1500);
    });
  });
});
</script>
</body></html>"""


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
        code_challenge=request.args.get("code_challenge", ""),
        code_challenge_method=request.args.get("code_challenge_method", ""),
    )


@app.route("/authorize", methods=["POST"])
def authorize_post():
    if not request.form.get("username") or not request.form.get("password"):
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
        cc, ccm = (
            request.form.get("code_challenge"),
            request.form.get("code_challenge_method") or "plain",
        )
        if cc:
            entry["code_challenge"], entry["code_challenge_method"] = cc, ccm
    AUTH_CODES[code] = entry
    ru, q = urlparse(entry["redirect_uri"]), dict(
        parse_qsl(urlparse(entry["redirect_uri"]).query)
    )
    q["code"] = code
    if request.form.get("state"):
        q["state"] = request.form.get("state")
    return redirect(
        urlunparse(
            (ru.scheme, ru.netloc, ru.path, ru.params, urlencode(q), ru.fragment)
        ),
        code=302,
    )


@app.route("/token", methods=["POST"])
def token():
    gt = request.form.get("grant_type")
    if gt in ("authorization_code", "code"):
        code, data = request.form.get("code"), AUTH_CODES.pop(
            request.form.get("code"), None
        )
        if not data:
            return (
                jsonify(
                    error="invalid_grant",
                    error_description="Code invalid or already used",
                ),
                400,
            )
        if now_utc() > data["exp"]:
            return jsonify(error="invalid_grant", error_description="Code expired"), 400
        try:
            validate_pkce_if_needed(data, request.form.get("code_verifier"))
        except ValueError as e:
            r = str(e)
            if r == "pkce_required":
                return (
                    jsonify(
                        error="invalid_request",
                        error_description="PKCE required but no code_challenge associated",
                    ),
                    400,
                )
            elif r == "missing_code_verifier":
                return (
                    jsonify(
                        error="invalid_request",
                        error_description="Missing code_verifier",
                    ),
                    400,
                )
            elif r == "invalid_code_verifier":
                return (
                    jsonify(
                        error="invalid_grant", error_description="Invalid code_verifier"
                    ),
                    400,
                )
            elif r == "unsupported_challenge_method":
                return (
                    jsonify(
                        error="invalid_request",
                        error_description="Unsupported code_challenge_method",
                    ),
                    400,
                )
            else:
                return jsonify(error="invalid_request"), 400
        return (
            jsonify(
                issue_tokens(
                    client_id=request.form.get("client_id") or data["client_id"],
                    scope=request.form.get("scope") or data["scope"],
                    nonce=data.get("nonce"),
                )
            ),
            200,
        )
    elif gt == "refresh_token":
        rt = request.form.get("refresh_token")
        if not rt:
            return (
                jsonify(
                    error="invalid_request", error_description="Missing refresh_token"
                ),
                400,
            )
        try:
            decoded = jwt.decode(
                rt,
                key=PUBLIC_KEY,
                algorithms=["RS256"],
                options={"require": ["exp", "iat", "nbf", "jti"]},
                audience=None,
            )
        except Exception:
            return (
                jsonify(
                    error="invalid_grant", error_description="Refresh token invalid"
                ),
                400,
            )
        jti = decoded.get("jti")
        if not jti or jti not in REFRESH_JTIS:
            return (
                jsonify(
                    error="invalid_grant",
                    error_description="Refresh token revoked or already used",
                ),
                400,
            )
        entry = REFRESH_JTIS.pop(jti)
        if now_utc() > entry["exp"]:
            return (
                jsonify(
                    error="invalid_grant", error_description="Refresh token expired"
                ),
                400,
            )
        scope = entry["scope"]
        req_scope = request.form.get("scope")
        if req_scope:
            requested, original = set(req_scope.split()), set(scope.split())
            if not requested.issubset(original):
                return jsonify(error="invalid_scope"), 400
            scope = " ".join(sorted(requested))
        return (
            jsonify(
                issue_tokens(
                    client_id=request.form.get("client_id") or entry["client_id"],
                    scope=scope,
                )
            ),
            200,
        )
    return jsonify(error="unsupported_grant_type"), 400


@app.route("/callback")
def callback():
    return render_template_string(
        CALLBACK_HTML, code=request.args.get("code"), state=request.args.get("state")
    )


@app.route("/.well-known/openid-configuration")
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


@app.route("/jwks.json")
def jwks():
    numbers = PUBLIC_KEY.public_numbers()
    return jsonify(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": KID,
                    "alg": "RS256",
                    "n": base64url_uint(numbers.n),
                    "e": base64url_uint(numbers.e),
                }
            ]
        }
    )


# ---------------------------
# MAIN
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=ARGS.port, ssl_context=SERVICE_SSL_CONTEXT)
