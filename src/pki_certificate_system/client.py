"""Generate a client key pair and submit a hybrid-encrypted CSR."""

from __future__ import annotations

import argparse
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID

from .cert_utils import load_cert, save_private_key
from .paths import client_dir, sub_ca_dir


def create_encrypted_csr(client_id: str, sub_ca_name: str, store_dir: str | None = None) -> dict[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    output_dir = client_dir(client_id, store_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    private_key_path = output_dir / "client_private_key.pem"
    save_private_key(private_key, private_key_path)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Victoria"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, client_id.upper()),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{client_id}.example.com"),
        ]
    )
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    csr_bytes = csr.public_bytes(serialization.Encoding.PEM)

    aes_key = os.urandom(32)
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_csr = padder.update(csr_bytes) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    encrypted_csr = encryptor.update(padded_csr) + encryptor.finalize()

    sub_ca_cert = load_cert(sub_ca_dir(sub_ca_name, store_dir) / f"{sub_ca_name}_cert.pem")
    encrypted_aes_key = sub_ca_cert.public_key().encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    encrypted_key_path = output_dir / "encrypted_key.bin"
    iv_path = output_dir / "iv.bin"
    encrypted_csr_path = output_dir / "encrypted_csr.bin"
    encrypted_key_path.write_bytes(encrypted_aes_key)
    iv_path.write_bytes(iv)
    encrypted_csr_path.write_bytes(encrypted_csr)

    return {
        "private_key": str(private_key_path),
        "encrypted_key": str(encrypted_key_path),
        "iv": str(iv_path),
        "encrypted_csr": str(encrypted_csr_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a client key pair and hybrid-encrypted CSR.")
    parser.add_argument("client_id", help="Client identifier, for example client_1.")
    parser.add_argument("sub_ca_name", help="Issuing Sub-CA identifier, for example sub_ca_1.")
    parser.add_argument("--store-dir", default=None, help="Generated artifact directory.")
    args = parser.parse_args()

    outputs = create_encrypted_csr(args.client_id, args.sub_ca_name, args.store_dir)
    for label, path in outputs.items():
        print(f"{label}: {path}")


if __name__ == "__main__":
    main()
