import base64
import hashlib
import logging
import secrets
import structlog
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import jwt as pyjwt
from flask import Flask, g, jsonify, make_response, redirect, render_template, request

from mock_oidc.config import AppConfig
from mock_oidc.crypto import jwks_dict, load_public_key_from_cert_or_key
from mock_oidc.store import TokenStore
from mock_oidc.tokens import issue_tokens, now_utc, validate_pkce


def create_app(config: AppConfig) -> Flask:
    app = Flask(__name__, template_folder="templates")
    store = TokenStore()
    app.config["MOCK_OIDC_CONFIG"] = config
    app.config["MOCK_OIDC_STORE"] = store
    # Track startup time for health endpoint
    app.config["MOCK_OIDC_START_TIME"] = datetime.now(timezone.utc)

    # Configure structlog based on config
    if config.log_format == "json":
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(),
            ],
            logger_factory=structlog.PrintLoggerFactory(),
        )
    else:
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.dev.ConsoleRenderer(),
            ],
        )

    # Set log level
    logging.basicConfig(level=getattr(logging, config.log_level.upper(), logging.INFO))
    log = structlog.get_logger()

    # Start background TTL eviction thread if enabled
    if config.eviction_interval > 0:
        def _evict_loop():
            while True:
                import time
                time.sleep(config.eviction_interval)
                codes_evicted, refresh_evicted = store.evict_expired()
                if codes_evicted > 0 or refresh_evicted > 0:
                    log.info(
                        "store_eviction",
                        codes_evicted=codes_evicted,
                        refresh_evicted=refresh_evicted,
                    )

        evict_thread = threading.Thread(target=_evict_loop, daemon=True)
        evict_thread.start()

    # Request ID middleware
    @app.before_request
    def _before_request():
        request_id = request.headers.get("X-Request-ID", secrets.token_hex(8))
        g.request_id = request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

    @app.after_request
    def _after_request(response):
        response.headers["X-Request-ID"] = g.request_id
        return response

    def current_issuer() -> str:
        if config.issuer:
            return config.issuer.rstrip("/")
        scheme = "https" if request.is_secure else "http"
        return f"{scheme}://{request.host}"

    def oauth_error(error: str, description: str, status: int = 400, headers: dict = None):
        payload = jsonify(error=error, error_description=description)
        return (payload, status) if headers is None else (payload, status, headers)

    def parse_basic_auth(header_value):
        if not header_value or not header_value.lower().startswith("basic "):
            return None, None
        try:
            decoded = base64.b64decode(header_value.split(" ", 1)[1]).decode("utf-8")
            cid, csec = decoded.split(":", 1)
            return cid, csec
        except Exception:
            return None, None

    def extract_client_auth(req):
        cid_basic, csec_basic = parse_basic_auth(req.headers.get("Authorization"))
        form_client_id = req.form.get("client_id")
        form_client_secret = req.form.get("client_secret")

        if cid_basic:
            if form_client_secret:
                return {
                    "error": (
                        "invalid_request",
                        "Multiple client authentication methods supplied.",
                    )
                }
            return {
                "client_id": cid_basic,
                "client_secret": csec_basic,
                "method": "client_secret_basic",
            }

        if form_client_secret:
            if not form_client_id:
                return {
                    "error": (
                        "invalid_client",
                        "client_id required when using client_secret.",
                    )
                }
            return {
                "client_id": form_client_id,
                "client_secret": form_client_secret,
                "method": "client_secret_post",
            }

        if form_client_id:
            return {"client_id": form_client_id, "client_secret": None, "method": "none"}

        return {"client_id": None, "client_secret": None, "method": "none"}

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint for container orchestration."""
        start_time = app.config["MOCK_OIDC_START_TIME"]
        now = datetime.now(timezone.utc)
        uptime_seconds = int((now - start_time).total_seconds())
        return jsonify(status="ok", uptime_seconds=uptime_seconds), 200

    @app.route("/authorize", methods=["GET"])
    def authorize_get():
        if request.args.get("response_type") != "code":
            return make_response("response_type must be 'code'", 400)
        return render_template(
            "login.html",
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

        # If users config is loaded, verify username is known
        if config.users and username not in config.users:
            log.warning(
                "authorize_error",
                error="unknown_user",
                username=username,
            )
            return make_response("Unknown user", 400)

        # Compute stable subject identifier from username
        sub = "user:" + hashlib.sha256(username.encode("utf-8")).hexdigest()[:16]

        code = secrets.token_hex(16)
        client_id = request.form.get("client_id")
        scope = request.form.get("scope") or "openid"
        entry = {
            "client_id": client_id,
            "redirect_uri": request.form.get("redirect_uri"),
            "scope": scope,
            "sub": sub,
            "username": username,
            "exp": now_utc() + timedelta(seconds=config.auth_code_ttl),
            "nonce": request.form.get("nonce") or None,
        }

        pkce_method = None
        # Always store code_challenge if provided, regardless of PKCE config
        cc = request.form.get("code_challenge")
        ccm = request.form.get("code_challenge_method") or "plain"
        if cc:
            entry["code_challenge"] = cc
            entry["code_challenge_method"] = ccm
            pkce_method = ccm

        store.put_code(code, entry)

        # Log authorization code issuance
        log.info(
            "authorize_code_issued",
            sub=sub,
            client_id=client_id,
            scope=scope,
            pkce_method=pkce_method,
        )

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

        auth = extract_client_auth(request)
        if "error" in auth:
            code, desc = auth["error"]
            return oauth_error(code, desc)

        provided_client_id = auth.get("client_id")
        is_confidential = bool(auth.get("client_secret"))

        if grant_type == "authorization_code":
            code_val = request.form.get("code")
            data = store.pop_code(code_val)
            if not data:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_grant",
                    detail="code_invalid_or_used",
                    client_id=provided_client_id,
                )
                return oauth_error(
                    "invalid_grant",
                    "Authorization code is invalid, already used, or was not issued by this server.",
                )
            if now_utc() > data["exp"]:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_grant",
                    detail="code_expired",
                    client_id=provided_client_id,
                )
                return oauth_error("invalid_grant", "Authorization code has expired.")

            client_id = provided_client_id or data["client_id"]
            if provided_client_id and provided_client_id != data["client_id"]:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_grant",
                    detail="client_mismatch",
                    client_id=provided_client_id,
                )
                return oauth_error("invalid_grant", "Code was issued to a different client.")

            must_validate_pkce = False
            if data.get("code_challenge"):
                must_validate_pkce = True
            elif config.pkce and not is_confidential:
                must_validate_pkce = True

            if must_validate_pkce:
                try:
                    validate_pkce(data, request.form.get("code_verifier"))
                except ValueError as e:
                    msg = str(e)
                    if msg == "pkce_required":
                        log.warning(
                            "token_error",
                            grant_type=grant_type,
                            error="invalid_request",
                            detail="pkce_required",
                            client_id=client_id,
                        )
                        return oauth_error(
                            "invalid_request",
                            "PKCE required but no code_challenge associated with this code.",
                        )
                    if msg == "missing_code_verifier":
                        log.warning(
                            "token_error",
                            grant_type=grant_type,
                            error="invalid_request",
                            detail="missing_code_verifier",
                            client_id=client_id,
                        )
                        return oauth_error("invalid_request", "Missing code_verifier.")
                    if msg == "invalid_code_verifier":
                        log.warning(
                            "token_error",
                            grant_type=grant_type,
                            error="invalid_grant",
                            detail="invalid_code_verifier",
                            client_id=client_id,
                        )
                        return oauth_error("invalid_grant", "Invalid code_verifier.")
                    if msg == "unsupported_challenge_method":
                        log.warning(
                            "token_error",
                            grant_type=grant_type,
                            error="invalid_request",
                            detail="unsupported_challenge_method",
                            client_id=client_id,
                        )
                        return oauth_error(
                            "invalid_request", "Unsupported code_challenge_method."
                        )
                    log.warning(
                        "token_error",
                        grant_type=grant_type,
                        error="invalid_request",
                        detail="pkce_validation_failed",
                        client_id=client_id,
                    )
                    return oauth_error("invalid_request", "PKCE validation failed.")

            # Validate redirect_uri matches if provided in authorization
            stored_redirect_uri = data.get("redirect_uri")
            provided_redirect_uri = request.form.get("redirect_uri")
            if stored_redirect_uri and stored_redirect_uri != provided_redirect_uri:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_grant",
                    detail="redirect_uri_mismatch",
                    client_id=client_id,
                )
                return oauth_error("invalid_grant", "redirect_uri mismatch.")

            scope = request.form.get("scope") or data["scope"]

            # Gather user claims if users config is loaded
            user_claims = None
            if config.users and data.get("username") in config.users:
                user_data = config.users[data["username"]]
                user_claims = {}
                if "name" in user_data:
                    user_claims["name"] = user_data["name"]
                if "email" in user_data:
                    user_claims["email"] = user_data["email"]
                # Include any other custom claims (groups, department, etc.)
                for key, val in user_data.items():
                    if key not in ("name", "email", "secret", "redirect_uris", "allowed_grants", "allowed_scopes"):
                        user_claims[key] = val

            tokens = issue_tokens(
                client_id=client_id,
                scope=scope,
                sub=data["sub"],
                iss=current_issuer(),
                store=store,
                config=config,
                nonce=data.get("nonce"),
                user_claims=user_claims,
            )

            # Log successful token issuance
            id_token = tokens.get("id_token")
            try:
                pub_key = load_public_key_from_cert_or_key(config.signing_cert_pem)
                id_claims = pyjwt.decode(
                    id_token,
                    pub_key,
                    algorithms=["RS256"],
                    options={"verify_aud": False},
                )
                sub = id_claims.get("sub", "unknown")
            except Exception:
                sub = "unknown"

            log.info(
                "token_issued",
                grant_type=grant_type,
                client_id=client_id,
                scope=scope,
                sub=sub,
            )

            return jsonify(tokens), 200

        elif grant_type == "refresh_token":
            refresh_token = request.form.get("refresh_token")
            if not refresh_token:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_request",
                    detail="missing_refresh_token",
                    client_id=provided_client_id,
                )
                return oauth_error("invalid_request", "Missing refresh_token.")

            try:
                pub_key = load_public_key_from_cert_or_key(config.signing_cert_pem)
                decoded = pyjwt.decode(
                    refresh_token,
                    pub_key,
                    algorithms=["RS256"],
                    options={"verify_aud": False},
                )
            except Exception:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_grant",
                    detail="malformed_or_invalid_signature",
                    client_id=provided_client_id,
                )
                return oauth_error(
                    "invalid_grant",
                    "Refresh token is malformed or has an invalid signature.",
                )

            jti = decoded.get("jti")
            if not jti:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_grant",
                    detail="no_jti",
                    client_id=provided_client_id,
                )
                return oauth_error(
                    "invalid_grant", "Refresh token has been revoked or already used."
                )

            entry = store.pop_refresh(jti)
            if not entry:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_grant",
                    detail="refresh_revoked_or_used",
                    client_id=provided_client_id,
                )
                return oauth_error(
                    "invalid_grant", "Refresh token has been revoked or already used."
                )

            if now_utc() > entry["exp"]:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_grant",
                    detail="refresh_expired",
                    client_id=provided_client_id,
                )
                return oauth_error("invalid_grant", "Refresh token has expired.")

            client_id = provided_client_id or entry["client_id"]
            if provided_client_id and provided_client_id != entry["client_id"]:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_grant",
                    detail="client_mismatch",
                    client_id=provided_client_id,
                )
                return oauth_error("invalid_grant", "Refresh token audience mismatch.")

            scope = entry["scope"]
            req_scope = request.form.get("scope")
            if req_scope:
                requested = set(req_scope.split())
                original = set(scope.split())
                if not requested.issubset(original):
                    log.warning(
                        "token_error",
                        grant_type=grant_type,
                        error="invalid_scope",
                        detail="scope_expansion",
                        client_id=client_id,
                    )
                    return oauth_error(
                        "invalid_scope",
                        "Requested scope expands the original scope; only narrowing is allowed.",
                    )
                scope = " ".join(sorted(requested))

            tokens = issue_tokens(
                client_id=client_id,
                scope=scope,
                sub=entry["sub"],
                iss=current_issuer(),
                store=store,
                config=config,
                user_claims=None,
            )

            # Log successful token issuance from refresh
            id_token = tokens.get("id_token")
            try:
                pub_key = load_public_key_from_cert_or_key(config.signing_cert_pem)
                id_claims = pyjwt.decode(
                    id_token,
                    pub_key,
                    algorithms=["RS256"],
                    options={"verify_aud": False},
                )
                sub = id_claims.get("sub", "unknown")
            except Exception:
                sub = "unknown"

            log.info(
                "token_issued",
                grant_type=grant_type,
                client_id=client_id,
                scope=scope,
                sub=sub,
            )

            return jsonify(tokens), 200

        elif grant_type == "client_credentials":
            # RFC 6749 Section 4.4: Client Credentials Grant
            if not is_confidential:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_client",
                    detail="confidential_client_required",
                    client_id=provided_client_id,
                )
                return oauth_error(
                    "invalid_client",
                    "client_credentials requires client_secret authentication.",
                )

            scope = request.form.get("scope", "")
            if not scope:
                log.warning(
                    "token_error",
                    grant_type=grant_type,
                    error="invalid_request",
                    detail="missing_scope",
                    client_id=provided_client_id,
                )
                return oauth_error("invalid_request", "scope is required for client_credentials.")

            # Per RFC 6749 Section 4.4.3, sub equals client_id
            tokens = issue_tokens(
                client_id=provided_client_id,
                scope=scope,
                sub=provided_client_id,
                iss=current_issuer(),
                store=store,
                config=config,
                only_access=True,
            )

            log.info(
                "token_issued",
                grant_type=grant_type,
                client_id=provided_client_id,
                scope=scope,
                sub=provided_client_id,
            )

            return jsonify(tokens), 200

        else:
            log.warning(
                "token_error",
                grant_type=grant_type,
                error="unsupported_grant_type",
                detail="unsupported",
                client_id=provided_client_id,
            )
            return oauth_error(
                "unsupported_grant_type",
                "Grant type must be 'authorization_code', 'refresh_token', or 'client_credentials'.",
                400,
            )

    @app.route("/.well-known/openid-configuration", methods=["GET"])
    def well_known():
        iss = current_issuer()

        # Build dynamic claims_supported based on loaded users
        claims_supported = ["sub", "iss", "aud", "iat", "exp", "nbf", "name", "email", "nonce", "at_hash"]
        if config.users:
            # Collect all custom claim keys from user data
            for user_data in config.users.values():
                for key in user_data.keys():
                    if key not in ("name", "email", "secret", "redirect_uris", "allowed_grants", "allowed_scopes") and key not in claims_supported:
                        claims_supported.append(key)

        return jsonify(
            {
                "issuer": iss,
                "authorization_endpoint": f"{iss}/authorize",
                "token_endpoint": f"{iss}/token",
                "introspection_endpoint": f"{iss}/introspect",
                "revocation_endpoint": f"{iss}/revoke",
                "userinfo_endpoint": f"{iss}/userinfo",
                "jwks_uri": f"{iss}/jwks.json",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["S256", "plain"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                    "none",
                ],
                "subject_types_supported": ["public"],
                "scopes_supported": ["openid", "profile", "email", "offline_access"],
                "claims_supported": claims_supported,
            }
        )

    @app.route("/jwks.json", methods=["GET"])
    def jwks():
        return jsonify(jwks_dict(config)), 200

    @app.route("/userinfo", methods=["GET", "POST"])
    def userinfo():
        """OIDC Core Section 5.3: UserInfo endpoint returns claims about authenticated user."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.lower().startswith("bearer "):
            headers = {
                "WWW-Authenticate": 'Bearer error="missing_token", error_description="Bearer token required"'
            }
            return ("", 401, headers)

        token_str = auth_header.split(" ", 1)[1].strip()
        try:
            pub_key = load_public_key_from_cert_or_key(config.signing_cert_pem)
            claims = pyjwt.decode(
                token_str,
                pub_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        except pyjwt.ExpiredSignatureError:
            headers = {
                "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Access token has expired"'
            }
            return ("", 401, headers)
        except Exception:
            headers = {
                "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Access token is invalid"'
            }
            return ("", 401, headers)

        scope_set = set(claims.get("scope", "").split()) if claims.get("scope") else set()
        sub = claims.get("sub")
        response_claims = {"sub": sub}

        # Check if we have user claims from config (for non-client_credentials flows)
        # User claims were merged into ID token during issue_tokens, so we check that path
        # For now, return claims that were in the token itself (they came from user config)
        # Plus add claims based on scopes
        if "profile" in scope_set:
            if "name" in claims:
                response_claims["name"] = claims["name"]
            else:
                response_claims["name"] = "Max Musterman"
        if "email" in scope_set:
            if "email" in claims:
                response_claims["email"] = claims["email"]
            else:
                response_claims["email"] = "max@example.com"

        # Add any custom claims that were in the token
        for key in claims:
            if key not in ("sub", "iss", "aud", "iat", "exp", "nbf", "name", "email", "nonce", "at_hash", "scope", "jti", "typ"):
                response_claims[key] = claims[key]

        return jsonify(response_claims), 200

    @app.route("/callback", methods=["GET"])
    def callback():
        code = request.args.get("code")
        state = request.args.get("state")
        return render_template("callback.html", code=code, state=state)

    @app.route("/introspect", methods=["POST"])
    def introspect():
        """RFC 7662: Token Introspection endpoint."""
        token = request.form.get("token")
        if not token:
            log.warning("introspect_error", error="missing_token")
            return oauth_error("invalid_request", "Missing token parameter.", 400)

        # Require client authentication
        auth = extract_client_auth(request)
        if "error" in auth:
            code, desc = auth["error"]
            return oauth_error(code, desc, 401)

        client_id = auth.get("client_id")
        client_secret = auth.get("client_secret")

        if not client_id:
            log.warning("introspect_error", error="missing_client_id")
            return oauth_error("invalid_client", "Missing client_id.", 401)

        # Try to decode the token
        try:
            pub_key = load_public_key_from_cert_or_key(config.signing_cert_pem)
            claims = pyjwt.decode(
                token,
                pub_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        except pyjwt.ExpiredSignatureError:
            # Expired tokens return active: false, not an error
            log.info("introspect_inactive", reason="expired_token")
            return jsonify({"active": False}), 200
        except Exception:
            # Invalid/malformed tokens return active: false, not an error
            log.info("introspect_inactive", reason="invalid_token")
            return jsonify({"active": False}), 200

        # Token is valid and active
        response = {
            "active": True,
            "sub": claims.get("sub"),
            "scope": claims.get("scope"),
            "client_id": claims.get("aud"),
            "exp": claims.get("exp"),
            "iat": claims.get("iat"),
            "token_type": "Bearer",
            "jti": claims.get("jti"),
        }

        log.info("introspect_success", client_id=client_id, sub=response.get("sub"))
        return jsonify(response), 200

    @app.route("/revoke", methods=["POST"])
    def revoke():
        """RFC 7009: Token Revocation endpoint.

        Returns empty 200 response for any input (no error responses per spec).
        """
        token = request.form.get("token")
        token_type_hint = request.form.get("token_type_hint")

        # Require client authentication
        auth = extract_client_auth(request)
        if "error" in auth:
            # Per RFC 7009, return 401 if client auth fails
            code, desc = auth["error"]
            return oauth_error(code, desc, 401)

        client_id = auth.get("client_id")
        if not client_id:
            # Per RFC 7009, return 401 if no client_id
            return oauth_error("invalid_client", "Missing client_id.", 401)

        # If no token, still return 200 (per spec, silently ignore)
        if not token:
            log.info("revoke_no_token", client_id=client_id)
            return "", 200

        # Try to decode token to get jti (for refresh tokens)
        try:
            pub_key = load_public_key_from_cert_or_key(config.signing_cert_pem)
            claims = pyjwt.decode(
                token,
                pub_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
            jti = claims.get("jti")
            if jti and token_type_hint != "access_token":
                # Try to revoke the refresh token
                was_revoked = store.revoke_refresh(jti)
                log.info(
                    "revoke_token",
                    client_id=client_id,
                    jti=jti,
                    was_revoked=was_revoked,
                )
        except Exception:
            # Invalid token - still return 200 per spec
            log.info("revoke_invalid_token", client_id=client_id)

        # Always return empty 200 response per RFC 7009
        return "", 200

    return app
