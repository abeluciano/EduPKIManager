from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from ca.service import ensure_intermediate_ca, parse_certificate


@dataclass(frozen=True)
class OcspCertificateState:
    certificate_pem: str | bytes | None
    status: str
    revoked_at: datetime | None = None
    reason: str = "key_compromise"


_STATUS = {
    "good": ocsp.OCSPCertStatus.GOOD,
    "revoked": ocsp.OCSPCertStatus.REVOKED,
    "unknown": ocsp.OCSPCertStatus.UNKNOWN,
}

_REASONS = {
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
}


def build_unsuccessful_ocsp_response(response_status: ocsp.OCSPResponseStatus) -> bytes:
    return ocsp.OCSPResponseBuilder.build_unsuccessful(response_status).public_bytes(serialization.Encoding.DER)


def build_standard_ocsp_response(request_der: bytes, state: OcspCertificateState | None) -> bytes:
    ocsp_request = ocsp.load_der_ocsp_request(request_der)
    ca = ensure_intermediate_ca()
    now = datetime.now(timezone.utc)
    cert_status_name = state.status if state else "unknown"
    cert_status = _STATUS.get(cert_status_name, ocsp.OCSPCertStatus.UNKNOWN)
    certificate = parse_certificate(state.certificate_pem) if state and state.certificate_pem else _dummy_certificate(ocsp_request.serial_number)

    if not _request_matches_issuer(ocsp_request, certificate):
        return ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED
        ).public_bytes(serialization.Encoding.DER)

    revocation_time = (state.revoked_at or now) if state and cert_status is ocsp.OCSPCertStatus.REVOKED else None
    revocation_reason = _REASONS.get(state.reason, x509.ReasonFlags.key_compromise) if revocation_time else None
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=certificate,
            issuer=ca.certificate,
            algorithm=ocsp_request.hash_algorithm,
            cert_status=cert_status,
            this_update=now,
            next_update=now + timedelta(minutes=10),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, ca.certificate)
        .sign(ca.private_key, hashes.SHA256())
    )
    return response.public_bytes(serialization.Encoding.DER)


def build_ocsp_response(certificate_pem: str | bytes, status: str, revoked_at: datetime | None = None, reason: str = "key_compromise") -> bytes:
    ca = ensure_intermediate_ca()
    certificate = parse_certificate(certificate_pem)
    now = datetime.now(timezone.utc)
    cert_status = _STATUS.get(status, ocsp.OCSPCertStatus.UNKNOWN)
    revocation_time = (revoked_at or now) if cert_status is ocsp.OCSPCertStatus.REVOKED else None
    revocation_reason = _REASONS.get(reason, x509.ReasonFlags.key_compromise) if revocation_time else None

    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=certificate,
            issuer=ca.certificate,
            algorithm=hashes.SHA256(),
            cert_status=cert_status,
            this_update=now,
            next_update=now + timedelta(minutes=10),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, ca.certificate)
        .sign(ca.private_key, hashes.SHA256())
    )
    return response.public_bytes(serialization.Encoding.DER)


def inspect_ocsp_response(response_der: bytes) -> dict[str, str]:
    response = ocsp.load_der_ocsp_response(response_der)
    return {
        "response_status": response.response_status.name,
        "certificate_status": response.certificate_status.name,
        "serial_number": str(response.serial_number),
        "hash_algorithm": response.hash_algorithm.name,
    }


def _request_matches_issuer(ocsp_request: ocsp.OCSPRequest, certificate: x509.Certificate) -> bool:
    ca = ensure_intermediate_ca()
    expected = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(certificate, ca.certificate, ocsp_request.hash_algorithm)
        .build()
    )
    return (
        expected.serial_number == ocsp_request.serial_number
        and expected.issuer_name_hash == ocsp_request.issuer_name_hash
        and expected.issuer_key_hash == ocsp_request.issuer_key_hash
    )


def _dummy_certificate(serial_number: int) -> x509.Certificate:
    ca = ensure_intermediate_ca()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EduPKIManager"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"unknown-{serial_number}"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca.private_key, algorithm=hashes.SHA256())
    )
