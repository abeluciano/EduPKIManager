from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID

from ca.service import ensure_intermediate_ca


_REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
}


def generate_crl(revoked_certificates: Iterable[Mapping[str, object]], crl_number: int = 1) -> x509.CertificateRevocationList:
    ca = ensure_intermediate_ca()
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.certificate.subject)
        .last_update(now)
        .next_update(now + timedelta(hours=12))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.private_key.public_key()),
            critical=False,
        )
    )

    for item in revoked_certificates:
        serial = int(str(item["serial_number"]), 0)
        revoked_at = item.get("revoked_at") or now
        if isinstance(revoked_at, str):
            revoked_at = datetime.fromisoformat(revoked_at.replace("Z", "+00:00"))
        reason_name = str(item.get("reason") or "unspecified")
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
            .add_extension(x509.CRLReason(_REASONS.get(reason_name, x509.ReasonFlags.unspecified)), critical=False)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    return builder.sign(private_key=ca.private_key, algorithm=hashes.SHA256())


def crl_pem(revoked_certificates: Iterable[Mapping[str, object]], crl_number: int = 1) -> bytes:
    return generate_crl(revoked_certificates, crl_number).public_bytes(serialization.Encoding.PEM)


def crl_der(revoked_certificates: Iterable[Mapping[str, object]], crl_number: int = 1) -> bytes:
    return generate_crl(revoked_certificates, crl_number).public_bytes(serialization.Encoding.DER)


def crl_number(crl: x509.CertificateRevocationList) -> int | None:
    try:
        return crl.extensions.get_extension_for_oid(ExtensionOID.CRL_NUMBER).value.crl_number
    except x509.ExtensionNotFound:
        return None
