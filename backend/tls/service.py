from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from ca.service import CertificateRequest, ca_certificate_pem, ensure_intermediate_ca, issue_certificate


DEFAULT_TLS_HOSTNAME = "edupkimanager.com"
DEFAULT_TLS_SANS = ("edupkimanager.com", "www.edupkimanager.com", "localhost", "127.0.0.1")


def ensure_tls_server_bundle(
    hostname: str = DEFAULT_TLS_HOSTNAME,
    output_dir: str | Path = "backend/data/tls",
    alternative_names: tuple[str, ...] = DEFAULT_TLS_SANS,
) -> dict[str, str]:
    output = Path(output_dir)
    paths = _bundle_paths(output)
    if _existing_bundle_is_usable(hostname, alternative_names, paths):
        paths["ca_certificate"].write_text(ca_certificate_pem(), encoding="ascii")
        return {key: str(value) for key, value in paths.items()}
    return issue_tls_server_bundle(hostname, output, alternative_names)


def issue_tls_server_bundle(
    hostname: str = "localhost",
    output_dir: str | Path = "backend/data/tls",
    alternative_names: tuple[str, ...] | None = None,
) -> dict[str, str]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    names = _normalized_sans(hostname, alternative_names)
    issued = issue_certificate(
        CertificateRequest(
            common_name=hostname,
            certificate_type="server",
            sans=names,
            validity_days=397,
            key_algorithm="rsa-2048",
        )
    )
    paths = _bundle_paths(output)
    cert_path = paths["certificate"]
    key_path = paths["private_key"]
    ca_path = paths["ca_certificate"]
    cert_path.write_text(issued.certificate_pem + issued.issuer_certificate_pem, encoding="ascii")
    key_path.write_text(issued.private_key_pem, encoding="ascii")
    ca_path.write_text(ca_certificate_pem(), encoding="ascii")
    return {"certificate": str(cert_path), "private_key": str(key_path), "ca_certificate": str(ca_path)}


def tls13_context(cert_path: str | Path, key_path: str | Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def _bundle_paths(output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    return {
        "certificate": output_dir / "server_cert.pem",
        "private_key": output_dir / "server_key.pem",
        "ca_certificate": output_dir / "root_ca_cert.pem",
    }


def _existing_bundle_is_usable(hostname: str, alternative_names: tuple[str, ...], paths: dict[str, Path]) -> bool:
    if not all(path.exists() for path in paths.values()):
        return False
    try:
        certificate = _load_leaf_certificate(paths["certificate"])
        sans = _certificate_sans(certificate)
        current_intermediate = ensure_intermediate_ca().certificate
        current_root_pem = ca_certificate_pem()
        bundle_root_pem = paths["ca_certificate"].read_text(encoding="ascii")
        leaf_authority_key = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
        intermediate_subject_key = current_intermediate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
    except (ValueError, OSError, x509.ExtensionNotFound):
        return False

    required_names = set(_normalized_sans(hostname, alternative_names))
    not_expiring = certificate.not_valid_after_utc > datetime.now(timezone.utc) + timedelta(days=7)
    issuer_matches = certificate.issuer == current_intermediate.subject
    authority_matches = leaf_authority_key == intermediate_subject_key
    root_matches = bundle_root_pem == current_root_pem
    return not_expiring and issuer_matches and authority_matches and root_matches and required_names.issubset(sans)


def _load_leaf_certificate(path: Path) -> x509.Certificate:
    data = path.read_text(encoding="ascii")
    marker = "-----END CERTIFICATE-----"
    end = data.index(marker) + len(marker)
    return x509.load_pem_x509_certificate((data[:end] + "\n").encode("ascii"))


def _certificate_sans(certificate: x509.Certificate) -> set[str]:
    extension = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    values = set(extension.get_values_for_type(x509.DNSName))
    values.update(str(item) for item in extension.get_values_for_type(x509.IPAddress))
    return values


def _normalized_sans(hostname: str, alternative_names: tuple[str, ...] | None) -> tuple[str, ...]:
    names: list[str] = []
    for value in (hostname, *(alternative_names or (hostname, "127.0.0.1"))):
        if value and value not in names:
            names.append(value)
    return tuple(names)
