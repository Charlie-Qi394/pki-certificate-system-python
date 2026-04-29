"""Certificate loading, key loading, and chain validation helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .revocation import is_certificate_revoked


def load_private_key(path: str | Path):
    with Path(path).open("rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)


def load_cert(path: str | Path) -> x509.Certificate:
    with Path(path).open("rb") as cert_file:
        return x509.load_pem_x509_certificate(cert_file.read())


def save_private_key(private_key, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def save_cert(cert: x509.Certificate, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def verify_cert_signature(child_cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    issuer_cert.public_key().verify(
        child_cert.signature,
        child_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        child_cert.signature_hash_algorithm,
    )


def validate_cert_chain(
    client_cert_path: str | Path,
    sub_ca_cert_path: str | Path,
    root_ca_cert_path: str | Path,
    *,
    store_dir: str | Path | None = None,
    verbose: bool = True,
) -> bool:
    """Validate Client -> Sub-CA -> Root CA trust, expiry, and revocation."""
    client_cert_path = Path(client_cert_path)
    sub_ca_cert_path = Path(sub_ca_cert_path)
    root_ca_cert_path = Path(root_ca_cert_path)

    if verbose:
        print(f"Validating certificate chain for {client_cert_path}")

    try:
        client_cert = load_cert(client_cert_path)
        sub_ca_cert = load_cert(sub_ca_cert_path)
        root_cert = load_cert(root_ca_cert_path)
        sub_ca_name = sub_ca_cert_path.parent.name

        if is_certificate_revoked(sub_ca_name, client_cert.serial_number, store_dir=store_dir):
            raise ValueError(f"Client certificate has been revoked by {sub_ca_name}.")

        if client_cert.issuer != sub_ca_cert.subject:
            raise ValueError("Client certificate issuer does not match Sub-CA subject.")
        if sub_ca_cert.issuer != root_cert.subject:
            raise ValueError("Sub-CA certificate issuer does not match Root CA subject.")

        verify_cert_signature(client_cert, sub_ca_cert)
        verify_cert_signature(sub_ca_cert, root_cert)

        now = datetime.now(timezone.utc)
        for name, cert in (("client", client_cert), ("sub_ca", sub_ca_cert), ("root", root_cert)):
            if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
                raise ValueError(f"{name} certificate is outside its validity period.")

        if verbose:
            print("Certificate chain is trusted.")
        return True
    except Exception as exc:
        if verbose:
            print(f"Validation failed: {exc}")
        return False
