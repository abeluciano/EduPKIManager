from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from ca.service import ca_certificate_pem, intermediate_ca_certificate_pem, parse_certificate


def sign_pdf_bytes(pdf_bytes: bytes, certificate_pem: str, private_key_pem: str, actor: str = "system") -> dict[str, Any]:
    private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
    digest = _sha256(pdf_bytes)
    signature = _sign(private_key, digest)
    certificate = parse_certificate(certificate_pem)
    return {
        "format": "EduPKIManager detached PDF signature v1",
        "actor": actor,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "document_sha256": digest.hex(),
        "certificate_serial_number": str(certificate.serial_number),
        "certificate_fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "certificate_pem": certificate_pem,
        "issuer_certificate_pem": intermediate_ca_certificate_pem(),
        "ca_certificate_pem": ca_certificate_pem(),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "signature_algorithm": _algorithm_name(private_key),
    }


def verify_pdf_signature(pdf_bytes: bytes, signature_envelope: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(signature_envelope, str):
        signature_envelope = json.loads(signature_envelope)
    certificate = parse_certificate(signature_envelope["certificate_pem"])
    ca_certificate = parse_certificate(signature_envelope["ca_certificate_pem"])
    issuer_pem = signature_envelope.get("issuer_certificate_pem")
    issuer_certificate = parse_certificate(issuer_pem) if issuer_pem else ca_certificate
    digest = _sha256(pdf_bytes)
    signature = base64.b64decode(signature_envelope["signature_base64"])
    valid_digest = digest.hex() == signature_envelope["document_sha256"]
    try:
        _verify(certificate.public_key(), signature, digest, signature_envelope["signature_algorithm"])
        valid_signature = True
    except InvalidSignature:
        valid_signature = False
    valid_chain = _verify_certificate_chain(certificate, issuer_certificate) and (
        issuer_certificate == ca_certificate or _verify_certificate_chain(issuer_certificate, ca_certificate)
    )
    return {
        "valid": valid_digest and valid_signature and valid_chain,
        "valid_digest": valid_digest,
        "valid_signature": valid_signature,
        "valid_chain": valid_chain,
        "certificate_serial_number": str(certificate.serial_number),
        "chain_trust_anchor": ca_certificate.subject.rfc4514_string(),
    }


def envelope_to_json(envelope: dict[str, Any]) -> str:
    return json.dumps(envelope, indent=2, sort_keys=True)


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def _sign(private_key, digest: bytes) -> bytes:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
    return private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())


def _verify(public_key, signature: bytes, digest: bytes, algorithm_name: str) -> None:
    if algorithm_name == "ECDSA-SHA256":
        public_key.verify(signature, digest, ec.ECDSA(hashes.SHA256()))
    else:
        public_key.verify(signature, digest, padding.PKCS1v15(), hashes.SHA256())


def _verify_certificate_chain(certificate: x509.Certificate, ca_certificate: x509.Certificate) -> bool:
    if certificate.issuer != ca_certificate.subject:
        return False
    public_key = ca_certificate.public_key()
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        else:
            return False
    except InvalidSignature:
        return False
    return True


def _algorithm_name(private_key) -> str:
    return "ECDSA-SHA256" if isinstance(private_key, ec.EllipticCurvePrivateKey) else "RSA-PKCS1v15-SHA256"
