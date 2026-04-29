"""Simple text-file CRL helpers for educational certificate revocation."""

from __future__ import annotations

from pathlib import Path

from .paths import sub_ca_dir


def get_crl_path(sub_ca_name: str, store_dir: str | Path | None = None) -> Path:
    return sub_ca_dir(sub_ca_name, store_dir) / "crl.txt"


def revoke_certificate(sub_ca_name: str, cert_serial_number: int, store_dir: str | Path | None = None) -> None:
    crl_path = get_crl_path(sub_ca_name, store_dir)
    crl_path.parent.mkdir(parents=True, exist_ok=True)
    existing_serials = set()
    if crl_path.exists():
        existing_serials = {line.strip() for line in crl_path.read_text().splitlines() if line.strip()}
    existing_serials.add(str(cert_serial_number))
    crl_path.write_text("\n".join(sorted(existing_serials)) + "\n")


def is_certificate_revoked(sub_ca_name: str, cert_serial_number: int, store_dir: str | Path | None = None) -> bool:
    crl_path = get_crl_path(sub_ca_name, store_dir)
    if not crl_path.exists():
        return False
    revoked_serials = {line.strip() for line in crl_path.read_text().splitlines() if line.strip()}
    return str(cert_serial_number) in revoked_serials
