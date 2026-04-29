from pathlib import Path

from pki_certificate_system.cert_utils import validate_cert_chain
from pki_certificate_system.client import create_encrypted_csr
from pki_certificate_system.issue_cert import issue_certificate
from pki_certificate_system.paths import client_dir, root_dir, sub_ca_dir
from pki_certificate_system.revocation import revoke_certificate
from pki_certificate_system.root_ca import generate_root_ca
from pki_certificate_system.sub_ca import generate_sub_ca


def test_full_certificate_chain_validates(tmp_path: Path) -> None:
    store_dir = tmp_path / "cert_store"

    generate_root_ca(str(store_dir))
    generate_sub_ca("sub_ca_1", str(store_dir))
    create_encrypted_csr("client_1", "sub_ca_1", str(store_dir))
    issue_certificate("client_1", "sub_ca_1", str(store_dir))

    assert validate_cert_chain(
        client_dir("client_1", store_dir) / "client_cert.pem",
        sub_ca_dir("sub_ca_1", store_dir) / "sub_ca_1_cert.pem",
        root_dir(store_dir) / "root_cert.pem",
        store_dir=store_dir,
        verbose=False,
    )


def test_revoked_certificate_fails_validation(tmp_path: Path) -> None:
    store_dir = tmp_path / "cert_store"

    generate_root_ca(str(store_dir))
    generate_sub_ca("sub_ca_1", str(store_dir))
    create_encrypted_csr("client_1", "sub_ca_1", str(store_dir))
    cert_path = issue_certificate("client_1", "sub_ca_1", str(store_dir))

    from pki_certificate_system.cert_utils import load_cert

    revoke_certificate("sub_ca_1", load_cert(cert_path).serial_number, store_dir=store_dir)

    assert not validate_cert_chain(
        cert_path,
        sub_ca_dir("sub_ca_1", store_dir) / "sub_ca_1_cert.pem",
        root_dir(store_dir) / "root_cert.pem",
        store_dir=store_dir,
        verbose=False,
    )
