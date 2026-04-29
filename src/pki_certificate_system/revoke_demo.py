"""Revoke a generated client certificate."""

from __future__ import annotations

import argparse

from .cert_utils import load_cert
from .paths import client_dir
from .revocation import revoke_certificate


def revoke_client_certificate(client_id: str, sub_ca_name: str, store_dir: str | None = None) -> int:
    cert = load_cert(client_dir(client_id, store_dir) / "client_cert.pem")
    revoke_certificate(sub_ca_name, cert.serial_number, store_dir=store_dir)
    return cert.serial_number


def main() -> None:
    parser = argparse.ArgumentParser(description="Add a client certificate serial number to a Sub-CA CRL.")
    parser.add_argument("client_id", help="Client identifier, for example client_1.")
    parser.add_argument("sub_ca_name", help="Issuing Sub-CA identifier, for example sub_ca_1.")
    parser.add_argument("--store-dir", default=None, help="Generated artifact directory.")
    args = parser.parse_args()

    serial = revoke_client_certificate(args.client_id, args.sub_ca_name, args.store_dir)
    print(f"Revoked certificate serial {serial} under {args.sub_ca_name}")


if __name__ == "__main__":
    main()
