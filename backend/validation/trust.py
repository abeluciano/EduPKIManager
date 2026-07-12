from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Mapping

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import CRLEntryExtensionOID, ExtendedKeyUsageOID, ExtensionOID

from ca.service import ensure_intermediate_ca, ensure_root_ca, parse_certificate
from crl.service import generate_crl


_PURPOSES = {"document_signing", "server_auth", "client_auth", "device_auth", "any"}


def validate_certificate_trust(
    certificate_pem: str | bytes,
    *,
    purpose: str = "document_signing",
    revocation_records: Iterable[Mapping[str, object]] | None = None,
    known_status: str | None = None,
    crl_der: bytes | None = None,
    ocsp_der: bytes | None = None,
    validation_time: datetime | None = None,
) -> dict[str, object]:
    """Validate an issued certificate against the EduPKIManager trust chain."""
    checked_at = validation_time or datetime.now(timezone.utc)
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    normalized_purpose = purpose if purpose in _PURPOSES else "any"

    certificate = parse_certificate(certificate_pem)
    root = ensure_root_ca().certificate
    intermediate = ensure_intermediate_ca().certificate
    errors: list[str] = []

    chain = _validate_chain(certificate, intermediate, root)
    errors.extend(chain["errors"])
    validity = _validate_validity(certificate, checked_at)
    errors.extend(validity["errors"])
    basic_constraints = _validate_basic_constraints(certificate)
    errors.extend(basic_constraints["errors"])
    key_usage = _validate_key_usage(certificate, normalized_purpose)
    errors.extend(key_usage["errors"])
    extended_key_usage = _validate_extended_key_usage(certificate, normalized_purpose)
    errors.extend(extended_key_usage["errors"])
    policies = _validate_certificate_policies(certificate)
    errors.extend(policies["errors"])
    revocation = _validate_revocation(
        certificate,
        intermediate,
        checked_at,
        list(revocation_records or []),
        known_status,
        crl_der,
        ocsp_der,
    )
    errors.extend(revocation["errors"])

    valid = not errors
    return {
        "valid": valid,
        "purpose": normalized_purpose,
        "checked_at": checked_at.isoformat(),
        "certificate": {
            "serial_number": str(certificate.serial_number),
            "subject": certificate.subject.rfc4514_string(),
            "issuer": certificate.issuer.rfc4514_string(),
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": certificate.not_valid_after_utc.isoformat(),
        },
        "chain": chain,
        "validity": validity,
        "basic_constraints": basic_constraints,
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
        "certificate_policies": policies,
        "revocation": revocation,
        "errors": errors,
    }


def _validate_chain(certificate: x509.Certificate, intermediate: x509.Certificate, root: x509.Certificate) -> dict[str, object]:
    leaf_issuer_matches = certificate.issuer == intermediate.subject
    intermediate_issuer_matches = intermediate.issuer == root.subject
    leaf_signature_valid = leaf_issuer_matches and _verify_signed_object(certificate, intermediate.public_key())
    intermediate_signature_valid = intermediate_issuer_matches and _verify_signed_object(intermediate, root.public_key())
    root_self_signed = root.issuer == root.subject and _verify_signed_object(root, root.public_key())
    errors: list[str] = []

    if not leaf_issuer_matches:
        errors.append("certificate issuer does not match EduPKIManager Intermediate CA")
    if not leaf_signature_valid:
        errors.append("certificate signature was not verified by the Intermediate CA")
    if not intermediate_issuer_matches:
        errors.append("Intermediate CA issuer does not match EduPKIManager Root CA")
    if not intermediate_signature_valid:
        errors.append("Intermediate CA signature was not verified by the Root CA")
    if not root_self_signed:
        errors.append("Root CA self-signature is invalid")

    return {
        "valid": not errors,
        "leaf_issuer_matches_intermediate": leaf_issuer_matches,
        "leaf_signature_valid": leaf_signature_valid,
        "intermediate_issuer_matches_root": intermediate_issuer_matches,
        "intermediate_signature_valid": intermediate_signature_valid,
        "root_self_signed": root_self_signed,
        "intermediate_subject": intermediate.subject.rfc4514_string(),
        "trust_anchor": root.subject.rfc4514_string(),
        "errors": errors,
    }


def _validate_validity(certificate: x509.Certificate, checked_at: datetime) -> dict[str, object]:
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    active = not_before <= checked_at <= not_after
    errors = [] if active else ["certificate is outside its validity period"]
    return {
        "valid": active,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "errors": errors,
    }


def _validate_basic_constraints(certificate: x509.Certificate) -> dict[str, object]:
    try:
        value = certificate.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        return {"valid": False, "ca": None, "errors": ["missing BasicConstraints extension"]}
    errors = [] if value.ca is False else ["end-entity certificate must not be a CA"]
    return {"valid": not errors, "ca": value.ca, "path_length": value.path_length, "errors": errors}


def _validate_key_usage(certificate: x509.Certificate, purpose: str) -> dict[str, object]:
    try:
        value = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return {"valid": False, "errors": ["missing KeyUsage extension"]}

    errors: list[str] = []
    if not value.digital_signature:
        errors.append("KeyUsage.digital_signature is required")
    if purpose == "document_signing" and not value.content_commitment:
        errors.append("KeyUsage.content_commitment is required for document signing")
    if purpose == "server_auth" and not (value.digital_signature or value.key_encipherment):
        errors.append("server authentication requires digital_signature or key_encipherment")

    return {
        "valid": not errors,
        "digital_signature": value.digital_signature,
        "content_commitment": value.content_commitment,
        "key_encipherment": value.key_encipherment,
        "key_cert_sign": value.key_cert_sign,
        "crl_sign": value.crl_sign,
        "errors": errors,
    }


def _validate_extended_key_usage(certificate: x509.Certificate, purpose: str) -> dict[str, object]:
    try:
        value = certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        return {"valid": purpose == "any", "oids": [], "names": [], "errors": [] if purpose == "any" else ["missing ExtendedKeyUsage extension"]}

    expected = {
        "document_signing": {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION},
        "server_auth": {ExtendedKeyUsageOID.SERVER_AUTH},
        "client_auth": {ExtendedKeyUsageOID.CLIENT_AUTH},
        "device_auth": {ExtendedKeyUsageOID.CLIENT_AUTH},
    }.get(purpose, set())
    actual = set(value)
    errors: list[str] = []
    if expected and not actual.intersection(expected):
        errors.append(f"ExtendedKeyUsage does not allow {purpose}")

    return {
        "valid": not errors,
        "oids": [oid.dotted_string for oid in value],
        "names": [_oid_name(oid) for oid in value],
        "errors": errors,
    }


def _validate_certificate_policies(certificate: x509.Certificate) -> dict[str, object]:
    try:
        value = certificate.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
    except x509.ExtensionNotFound:
        return {"valid": False, "present": False, "oids": [], "errors": ["missing CertificatePolicies extension"]}
    oids = [policy.policy_identifier.dotted_string for policy in value]
    errors = [] if oids else ["CertificatePolicies extension is empty"]
    return {"valid": not errors, "present": True, "oids": oids, "errors": errors}


def _validate_revocation(
    certificate: x509.Certificate,
    intermediate: x509.Certificate,
    checked_at: datetime,
    revocation_records: list[Mapping[str, object]],
    known_status: str | None,
    crl_der: bytes | None,
    ocsp_der: bytes | None,
) -> dict[str, object]:
    errors: list[str] = []
    serial = certificate.serial_number
    database_match = _find_serial(revocation_records, serial)
    revoked_by_database = database_match is not None
    if known_status in {"revoked", "suspended"}:
        revoked_by_database = True
    if known_status and known_status != "issued":
        errors.append(f"certificate local status is {known_status}")
    if revoked_by_database:
        errors.append("certificate is revoked or suspended in the local registry")

    crl_info = _inspect_crl(serial, intermediate, checked_at, revocation_records, crl_der)
    if crl_info["revoked"]:
        errors.append("certificate serial number is present in the current CRL")
    errors.extend(crl_info["errors"])

    ocsp_info = _inspect_ocsp(serial, intermediate, ocsp_der)
    if ocsp_info["status"] == "REVOKED":
        errors.append("OCSP reports the certificate as revoked")
    if ocsp_info["status"] == "UNKNOWN":
        errors.append("OCSP reports the certificate as unknown")
    errors.extend(ocsp_info["errors"])

    status = "revoked" if revoked_by_database or crl_info["revoked"] or ocsp_info["status"] == "REVOKED" else "good"
    if ocsp_info["status"] == "UNKNOWN":
        status = "unknown"

    return {
        "valid": not errors,
        "status": status,
        "local_status": known_status,
        "revoked_by_database": revoked_by_database,
        "revoked_by_crl": crl_info["revoked"],
        "crl": crl_info,
        "ocsp": ocsp_info,
        "database_record": _serialize_record(database_match),
        "errors": errors,
    }


def _inspect_crl(
    serial_number: int,
    intermediate: x509.Certificate,
    checked_at: datetime,
    revocation_records: list[Mapping[str, object]],
    crl_der: bytes | None,
) -> dict[str, object]:
    errors: list[str] = []
    if crl_der is None:
        crl_der = generate_crl(revocation_records).public_bytes(serialization.Encoding.DER)
    crl = x509.load_der_x509_crl(crl_der)
    issuer_matches = crl.issuer == intermediate.subject
    signature_valid = issuer_matches and _verify_signed_object(crl, intermediate.public_key())
    if not issuer_matches:
        errors.append("CRL issuer does not match EduPKIManager Intermediate CA")
    if not signature_valid:
        errors.append("CRL signature is invalid")
    if crl.next_update_utc <= checked_at:
        errors.append("CRL is expired")
    revoked = crl.get_revoked_certificate_by_serial_number(serial_number)
    reason = _revoked_reason(revoked) if revoked else None
    return {
        "valid": not errors,
        "issuer_matches_intermediate": issuer_matches,
        "signature_valid": signature_valid,
        "last_update": crl.last_update_utc.isoformat(),
        "next_update": crl.next_update_utc.isoformat(),
        "revoked": revoked is not None,
        "revocation_reason": reason,
        "errors": errors,
    }


def _inspect_ocsp(serial_number: int, intermediate: x509.Certificate, ocsp_der: bytes | None) -> dict[str, object]:
    if ocsp_der is None:
        return {"checked": False, "valid": True, "response_status": None, "status": None, "signature_valid": None, "errors": []}

    errors: list[str] = []
    response = ocsp.load_der_ocsp_response(ocsp_der)
    response_status = response.response_status.name
    status = None
    signature_valid = None
    if response.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
        errors.append(f"OCSP response status is {response_status}")
    else:
        status = response.certificate_status.name
        signature_valid = _verify_ocsp_signature(response, intermediate)
        if not signature_valid:
            errors.append("OCSP response signature is invalid")
        if response.serial_number != serial_number:
            errors.append("OCSP response serial number does not match certificate")
    return {
        "checked": True,
        "valid": not errors,
        "response_status": response_status,
        "status": status,
        "serial_number": str(response.serial_number) if response.response_status is ocsp.OCSPResponseStatus.SUCCESSFUL else None,
        "this_update": response.this_update_utc.isoformat() if response.response_status is ocsp.OCSPResponseStatus.SUCCESSFUL else None,
        "next_update": response.next_update_utc.isoformat() if response.response_status is ocsp.OCSPResponseStatus.SUCCESSFUL and response.next_update_utc else None,
        "signature_valid": signature_valid,
        "errors": errors,
    }


def _verify_signed_object(signed_object, public_key) -> bool:
    try:
        payload = getattr(signed_object, "tbs_certificate_bytes", None)
        if payload is None:
            payload = getattr(signed_object, "tbs_certlist_bytes")
        _verify_signature(public_key, signed_object.signature, payload, signed_object.signature_hash_algorithm)
    except (InvalidSignature, AttributeError, TypeError, ValueError):
        return False
    return True


def _verify_ocsp_signature(response: ocsp.OCSPResponse, intermediate: x509.Certificate) -> bool:
    try:
        _verify_signature(
            intermediate.public_key(),
            response.signature,
            response.tbs_response_bytes,
            response.signature_hash_algorithm,
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _verify_signature(public_key, signature: bytes, payload: bytes, signature_hash_algorithm) -> None:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, payload, ec.ECDSA(signature_hash_algorithm))
        return
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, payload, padding.PKCS1v15(), signature_hash_algorithm)
        return
    raise TypeError("unsupported public key type")


def _find_serial(records: list[Mapping[str, object]], serial_number: int) -> Mapping[str, object] | None:
    for record in records:
        if int(str(record["serial_number"]), 0) == serial_number:
            return record
    return None


def _serialize_record(record: Mapping[str, object] | None) -> dict[str, object] | None:
    if record is None:
        return None
    revoked_at = record.get("revoked_at")
    if isinstance(revoked_at, datetime):
        revoked_at = revoked_at.isoformat()
    return {
        "serial_number": str(record.get("serial_number")),
        "status": str(record.get("status") or "revoked"),
        "reason": str(record.get("reason") or "unspecified"),
        "revoked_at": revoked_at,
    }


def _revoked_reason(revoked: x509.RevokedCertificate | None) -> str | None:
    if revoked is None:
        return None
    try:
        reason = revoked.extensions.get_extension_for_oid(CRLEntryExtensionOID.CRL_REASON).value
    except x509.ExtensionNotFound:
        return None
    return reason.reason.name


def _oid_name(oid: x509.ObjectIdentifier) -> str:
    return getattr(oid, "_name", oid.dotted_string)
