"""Generate a Sub-CA key pair and Root-CA-signed certificate."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .cert_utils import load_cert, load_private_key, save_cert, save_private_key
from .paths import root_dir, sub_ca_dir


def generate_sub_ca(sub_ca_name: str, store_dir: str | None = None) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Victoria"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Melbourne"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, sub_ca_name.upper()),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{sub_ca_name}.example.com"),
        ]
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())

    root_private_key = load_private_key(root_dir(store_dir) / "root_private_key.pem")
    root_cert = load_cert(root_dir(store_dir) / "root_cert.pem")
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(root_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3 * 365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_private_key, hashes.SHA256())
    )

    output_dir = sub_ca_dir(sub_ca_name, store_dir)
    key_path = output_dir / f"{sub_ca_name}_private_key.pem"
    cert_path = output_dir / f"{sub_ca_name}_cert.pem"
    save_private_key(private_key, key_path)
    save_cert(cert, cert_path)
    return str(key_path), str(cert_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Sub-CA key and Root-signed certificate.")
    parser.add_argument("sub_ca_name", help="Sub-CA identifier, for example sub_ca_1.")
    parser.add_argument("--store-dir", default=None, help="Generated artifact directory.")
    args = parser.parse_args()

    key_path, cert_path = generate_sub_ca(args.sub_ca_name, args.store_dir)
    print(f"Sub-CA private key saved to {key_path}")
    print(f"Sub-CA certificate saved to {cert_path}")


if __name__ == "__main__":
    main()
