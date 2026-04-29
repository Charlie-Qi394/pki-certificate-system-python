"""Validate generated certificate chains."""

from __future__ import annotations

import argparse

from .cert_utils import validate_cert_chain
from .paths import client_dir, root_dir, sub_ca_dir

DEFAULT_CLIENTS = (("client_1", "sub_ca_1"), ("client_2", "sub_ca_1"), ("client_3", "sub_ca_2"))


def validate_client(client_id: str, sub_ca_name: str, store_dir: str | None = None, verbose: bool = True) -> bool:
    return validate_cert_chain(
        client_dir(client_id, store_dir) / "client_cert.pem",
        sub_ca_dir(sub_ca_name, store_dir) / f"{sub_ca_name}_cert.pem",
        root_dir(store_dir) / "root_cert.pem",
        store_dir=store_dir,
        verbose=verbose,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate one or more generated client certificate chains.")
    parser.add_argument("--client-id", help="Client identifier. If omitted, the demo validates default clients.")
    parser.add_argument("--sub-ca-name", help="Sub-CA identifier for --client-id.")
    parser.add_argument("--store-dir", default=None, help="Generated artifact directory.")
    args = parser.parse_args()

    if bool(args.client_id) != bool(args.sub_ca_name):
        parser.error("--client-id and --sub-ca-name must be provided together.")

    pairs = ((args.client_id, args.sub_ca_name),) if args.client_id else DEFAULT_CLIENTS
    results = [validate_client(client_id, sub_ca_name, args.store_dir) for client_id, sub_ca_name in pairs]
    raise SystemExit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
