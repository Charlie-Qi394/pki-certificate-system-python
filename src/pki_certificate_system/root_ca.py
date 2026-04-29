"""Generate a Root CA key pair and self-signed X.509 certificate."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .cert_utils import save_cert, save_private_key
from .paths import root_dir


def generate_root_ca(store_dir: str | None = None) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Victoria"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Melbourne"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Educational Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "rootca.example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=5 * 365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    output_dir = root_dir(store_dir)
    key_path = output_dir / "root_private_key.pem"
    cert_path = output_dir / "root_cert.pem"
    save_private_key(private_key, key_path)
    save_cert(cert, cert_path)
    return str(key_path), str(cert_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the Root CA key and certificate.")
    parser.add_argument("--store-dir", default=None, help="Generated artifact directory.")
    args = parser.parse_args()

    key_path, cert_path = generate_root_ca(args.store_dir)
    print(f"Root CA private key saved to {key_path}")
    print(f"Root CA certificate saved to {cert_path}")


if __name__ == "__main__":
    main()
