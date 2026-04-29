"""Path helpers for generated PKI artifacts."""

from __future__ import annotations

import os
from pathlib import Path


def cert_store(store_dir: str | Path | None = None) -> Path:
    return Path(store_dir or os.environ.get("PKI_CERT_STORE", "cert_store"))


def root_dir(store_dir: str | Path | None = None) -> Path:
    return cert_store(store_dir) / "root_ca"


def sub_ca_dir(sub_ca_name: str, store_dir: str | Path | None = None) -> Path:
    return cert_store(store_dir) / sub_ca_name


def client_dir(client_id: str, store_dir: str | Path | None = None) -> Path:
    return cert_store(store_dir) / "clients" / client_id
