import atexit
import base64
import os
import tempfile
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

KID = "mock-oidc-key"


def base64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def base64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def generate_rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem_bytes_private(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def pem_bytes_public_cert_from_key(key, cn: str = "MockOIDC Signing") -> bytes:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def load_public_key_from_cert_or_key(pem_bytes: bytes):
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
        return cert.public_key()
    except Exception:
        return serialization.load_pem_public_key(pem_bytes)


def setup_signing_keys(config) -> None:
    """Populate config with ephemeral RSA signing keys. Idempotent if keys already set."""
    if config.signing_priv_pem is not None:
        if config.signing_priv_key is None:
            config.signing_priv_key = serialization.load_pem_private_key(
                config.signing_priv_pem, password=None
            )
        return
    config.signing_priv_key = generate_rsa_keypair()
    config.signing_priv_pem = pem_bytes_private(config.signing_priv_key)
    config.signing_cert_pem = pem_bytes_public_cert_from_key(config.signing_priv_key)


def load_signing_keys_from_files(cert_path: str, key_path: str, config) -> None:
    """Load RSA signing keys from PEM files."""
    with open(key_path, "rb") as f:
        config.signing_priv_pem = f.read()
    config.signing_priv_key = serialization.load_pem_private_key(
        config.signing_priv_pem, password=None
    )
    with open(cert_path, "rb") as f:
        config.signing_cert_pem = f.read()


def setup_quickboot_ssl(config) -> None:
    """Generate ephemeral SSL cert/key pair for service HTTPS and register cleanup."""
    svc_key = generate_rsa_keypair()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "MockOIDC Service")]
    )
    now = datetime.now(timezone.utc)
    svc_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(svc_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=svc_key, algorithm=hashes.SHA256())
    )
    kf = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    cf = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    kf.write(pem_bytes_private(svc_key))
    kf.flush()
    cf.write(svc_cert.public_bytes(serialization.Encoding.PEM))
    cf.flush()
    kf.close()
    cf.close()

    temp_files = [kf.name, cf.name]

    def _cleanup():
        for f in temp_files:
            try:
                os.remove(f)
            except Exception:  # nosec B110 - cleanup ignores errors intentionally
                pass

    atexit.register(_cleanup)
    config.ssl_context = (cf.name, kf.name)


def jwks_dict(config) -> dict:
    """Return JWKS dictionary for the public key."""
    pub = load_public_key_from_cert_or_key(config.signing_cert_pem)
    numbers = pub.public_numbers()
    return {
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
