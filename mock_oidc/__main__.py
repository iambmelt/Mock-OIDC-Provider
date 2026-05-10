import argparse

from mock_oidc.config import AppConfig
from mock_oidc.crypto import (
    load_signing_keys_from_files,
    setup_quickboot_ssl,
    setup_signing_keys,
)
from mock_oidc.provider import create_app


def parse_args():
    p = argparse.ArgumentParser(
        description="Mock OIDC Provider (Flask)",
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
    p.add_argument("--cert", type=str, help="Certificate PEM for token signing")
    p.add_argument("--key", type=str, help="Private key PEM for token signing")
    p.add_argument("--ssl-cert", type=str, help="SSL certificate PEM for the service")
    p.add_argument("--ssl-key", type=str, help="SSL private key PEM for the service")
    p.add_argument(
        "--ssl-quickboot",
        action="store_true",
        help="Generate ephemeral self-signed SSL cert and RSA keypair",
    )
    p.add_argument("--issuer", type=str, help="Override issuer URI")
    p.add_argument(
        "--pkce",
        action="store_true",
        help="Require PKCE for authorization_code exchanges",
    )
    return p.parse_args()


def main():
    args = parse_args()
    config = AppConfig(
        port=args.port,
        auth_code_ttl=args.auth_code_ttl,
        access_token_ttl=args.access_token_ttl,
        id_token_ttl=args.id_token_ttl,
        refresh_ttl=args.refresh_ttl,
        issuer=args.issuer,
        pkce=args.pkce,
    )

    if args.key and args.cert:
        load_signing_keys_from_files(args.cert, args.key, config)
    else:
        setup_signing_keys(config)

    if args.ssl_quickboot:
        setup_quickboot_ssl(config)
    elif args.ssl_cert and args.ssl_key:
        config.ssl_context = (args.ssl_cert, args.ssl_key)

    app = create_app(config)
    app.run(host="0.0.0.0", port=config.port, ssl_context=config.ssl_context)  # nosec B104 - intentional for mock testing


if __name__ == "__main__":
    main()
