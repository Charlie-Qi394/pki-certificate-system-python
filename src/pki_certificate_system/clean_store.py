"""Remove generated PKI artifacts from a certificate store."""

from __future__ import annotations

import argparse
import shutil

from .paths import cert_store


def clean_store(store_dir: str | None = None) -> None:
    store_path = cert_store(store_dir)
    if store_path.exists():
        shutil.rmtree(store_path)
    store_path.mkdir(parents=True, exist_ok=True)
    (store_path / ".gitkeep").touch()


def main() -> None:
    parser = argparse.ArgumentParser(description="Delete generated keys, certs, encrypted CSRs, and CRLs.")
    parser.add_argument("--store-dir", default=None, help="Generated artifact directory.")
    args = parser.parse_args()
    clean_store(args.store_dir)
    print(f"Cleaned {cert_store(args.store_dir)}")


if __name__ == "__main__":
    main()
