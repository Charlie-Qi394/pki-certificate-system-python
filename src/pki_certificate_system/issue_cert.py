"""Decrypt a client CSR and issue a Sub-CA-signed certificate."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .cert_utils import load_cert, load_private_key, save_cert
from .paths import client_dir, sub_ca_dir


def issue_certificate(client_id: str, sub_ca_name: str, store_dir: str | None = None) -> str:
    client_output_dir = client_dir(client_id, store_dir)
    sub_ca_output_dir = sub_ca_dir(sub_ca_name, store_dir)

    sub_ca_private_key = load_private_key(sub_ca_output_dir / f"{sub_ca_name}_private_key.pem")
    encrypted_aes_key = (client_output_dir / "encrypted_key.bin").read_bytes()
    aes_key = sub_ca_private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    iv = (client_output_dir / "iv.bin").read_bytes()
    encrypted_csr = (client_output_dir / "encrypted_csr.bin").read_bytes()
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded_csr = decryptor.update(encrypted_csr) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    csr_bytes = unpadder.update(padded_csr) + unpadder.finalize()
    csr = x509.load_pem_x509_csr(csr_bytes)

    sub_ca_cert = load_cert(sub_ca_output_dir / f"{sub_ca_name}_cert.pem")
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(sub_ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=sub_ca_private_key, algorithm=hashes.SHA256())
    )

    cert_path = client_output_dir / "client_cert.pem"
    save_cert(cert, cert_path)
    return str(cert_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a certificate from a hybrid-encrypted client CSR.")
    parser.add_argument("client_id", help="Client identifier, for example client_1.")
    parser.add_argument("sub_ca_name", help="Issuing Sub-CA identifier, for example sub_ca_1.")
    parser.add_argument("--store-dir", default=None, help="Generated artifact directory.")
    args = parser.parse_args()

    cert_path = issue_certificate(args.client_id, args.sub_ca_name, args.store_dir)
    print(f"Client certificate saved to {cert_path}")


if __name__ == "__main__":
    main()
