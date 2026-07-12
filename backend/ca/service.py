from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID


_STORAGE_DIR = Path(os.getenv("EDUPKI_DATA_DIR", Path(__file__).resolve().parents[1] / "data"))


@dataclass(frozen=True)
class CertificateRequest:
    common_name: str
    certificate_type: str = "user"
    organization: str = "EduPKIManager"
    organizational_unit: str = "Education PKI"
    country: str = "PE"
    sans: tuple[str, ...] = ()
    validity_days: int = 365
    key_algorithm: str = "rsa-2048"


@dataclass(frozen=True)
class RootCA:
    private_key: rsa.RSAPrivateKey
    certificate: x509.Certificate
    key_path: Path
    certificate_path: Path


@dataclass(frozen=True)
class IntermediateCA:
    private_key: rsa.RSAPrivateKey
    certificate: x509.Certificate
    issuer_certificate: x509.Certificate
    key_path: Path
    certificate_path: Path


@dataclass(frozen=True)
class IssuedCertificate:
    serial_number: int
    certificate_pem: str
    private_key_pem: str
    fingerprint_sha256: str
    subject: str
    not_before: datetime
    not_after: datetime
    issuer_certificate_pem: str
    certificate_chain_pem: str


def set_storage_dir(path: str | Path) -> None:
    """Override storage during tests or local demos."""
    global _STORAGE_DIR
    _STORAGE_DIR = Path(path)


def storage_dir() -> Path:
    _STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return _STORAGE_DIR


def _root_key_path() -> Path:
    return storage_dir() / "root_ca_key.pem"


def _root_cert_path() -> Path:
    return storage_dir() / "root_ca_cert.pem"


def _intermediate_key_path() -> Path:
    return storage_dir() / "intermediate_ca_key.pem"


def _intermediate_cert_path() -> Path:
    return storage_dir() / "intermediate_ca_cert.pem"


def _password() -> bytes:
    return os.getenv("CA_KEY_PASSWORD", "change-me-dev-password").encode("utf-8")


def _public_base_url() -> str:
    return os.getenv("EDUPKI_PUBLIC_BASE_URL", "http://localhost:8000/api").rstrip("/")


def ensure_root_ca(common_name: str = "EduPKIManager Root CA") -> RootCA:
    if _root_key_path().exists() and _root_cert_path().exists():
        return load_root_ca()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EduPKIManager"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Root Certification Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(_certificate_policies(), critical=False)
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )

    _root_key_path().write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(_password()),
        )
    )
    _root_cert_path().write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return RootCA(private_key, certificate, _root_key_path(), _root_cert_path())


def load_root_ca() -> RootCA:
    private_key = serialization.load_pem_private_key(_root_key_path().read_bytes(), password=_password())
    certificate = x509.load_pem_x509_certificate(_root_cert_path().read_bytes())
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Root CA key must be RSA.")
    return RootCA(private_key, certificate, _root_key_path(), _root_cert_path())


def ensure_intermediate_ca(common_name: str = "EduPKIManager Intermediate CA") -> IntermediateCA:
    if _intermediate_key_path().exists() and _intermediate_cert_path().exists():
        return load_intermediate_ca()

    root = ensure_root_ca()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EduPKIManager"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Intermediate Certification Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root.certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root.private_key.public_key()),
            critical=False,
        )
        .add_extension(_certificate_policies(), critical=False)
        .add_extension(_aia_extension(include_ocsp=False), critical=False)
        .sign(private_key=root.private_key, algorithm=hashes.SHA256())
    )

    _intermediate_key_path().write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(_password()),
        )
    )
    _intermediate_cert_path().write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return IntermediateCA(private_key, certificate, root.certificate, _intermediate_key_path(), _intermediate_cert_path())


def load_intermediate_ca() -> IntermediateCA:
    root = ensure_root_ca()
    private_key = serialization.load_pem_private_key(_intermediate_key_path().read_bytes(), password=_password())
    certificate = x509.load_pem_x509_certificate(_intermediate_cert_path().read_bytes())
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Intermediate CA key must be RSA.")
    return IntermediateCA(private_key, certificate, root.certificate, _intermediate_key_path(), _intermediate_cert_path())


def issue_certificate(request: CertificateRequest) -> IssuedCertificate:
    _validate_request(request)
    ca = ensure_intermediate_ca()
    leaf_key = _generate_leaf_key(request.key_algorithm)
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, request.country[:2].upper()),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, request.organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, request.organizational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, request.common_name),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=request.validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage_for(request.certificate_type), critical=True)
        .add_extension(_extended_key_usage_for(request.certificate_type), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.private_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(_crl_distribution_points(), critical=False)
        .add_extension(_aia_extension(include_ocsp=True), critical=False)
        .add_extension(_certificate_policies(), critical=False)
    )

    san_values = list(_san_entries([request.common_name, *request.sans]))
    if san_values:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_values), critical=False)

    certificate = builder.sign(private_key=ca.private_key, algorithm=hashes.SHA256())
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    issuer_pem = ca.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    root_pem = ca.issuer_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")

    return IssuedCertificate(
        serial_number=certificate.serial_number,
        certificate_pem=cert_pem,
        private_key_pem=key_pem,
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        subject=certificate.subject.rfc4514_string(),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        issuer_certificate_pem=issuer_pem,
        certificate_chain_pem=cert_pem + issuer_pem + root_pem,
    )


def parse_certificate(pem: str | bytes) -> x509.Certificate:
    data = pem.encode("ascii") if isinstance(pem, str) else pem
    return x509.load_pem_x509_certificate(data)


def ca_certificate_pem() -> str:
    return ensure_root_ca().certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def intermediate_ca_certificate_pem() -> str:
    return ensure_intermediate_ca().certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def ca_chain_pem() -> str:
    return intermediate_ca_certificate_pem() + ca_certificate_pem()


def _validate_request(request: CertificateRequest) -> None:
    if not request.common_name.strip():
        raise ValueError("common_name is required.")
    if request.certificate_type not in {"user", "server", "device"}:
        raise ValueError("certificate_type must be user, server or device.")
    if len(request.country) != 2 or not request.country.isalpha():
        raise ValueError("country must be a two-letter country code.")
    max_days = 397 if request.certificate_type == "server" else 825
    if request.validity_days < 1 or request.validity_days > max_days:
        raise ValueError(f"validity_days must be between 1 and {max_days}.")


def _generate_leaf_key(algorithm: str):
    normalized = algorithm.lower()
    if normalized in {"rsa", "rsa-2048"}:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if normalized == "rsa-4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if normalized in {"ecdsa", "ecdsa-p256", "p-256"}:
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError(f"Unsupported key algorithm: {algorithm}")


def _key_usage_for(certificate_type: str) -> x509.KeyUsage:
    is_server = certificate_type == "server"
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=certificate_type == "user",
        key_encipherment=is_server,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _extended_key_usage_for(certificate_type: str) -> x509.ExtendedKeyUsage:
    usages = {
        "server": [ExtendedKeyUsageOID.SERVER_AUTH],
        "device": [ExtendedKeyUsageOID.CLIENT_AUTH],
        "user": [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION],
    }.get(certificate_type, [ExtendedKeyUsageOID.CLIENT_AUTH])
    return x509.ExtendedKeyUsage(usages)


def _san_entries(values: Iterable[str]) -> Iterable[x509.GeneralName]:
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        if "@" in value:
            yield x509.RFC822Name(value)
            continue
        try:
            yield x509.IPAddress(ipaddress.ip_address(value))
        except ValueError:
            yield x509.DNSName(value)


def _crl_distribution_points() -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(f"{_public_base_url()}/crl.der")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )


def _aia_extension(include_ocsp: bool) -> x509.AuthorityInformationAccess:
    descriptions = [
        x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(f"{_public_base_url()}/ca/root/"),
        )
    ]
    if include_ocsp:
        descriptions.insert(
            0,
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(f"{_public_base_url()}/ocsp/"),
            ),
        )
    return x509.AuthorityInformationAccess(descriptions)


def _certificate_policies() -> x509.CertificatePolicies:
    return x509.CertificatePolicies(
        [
            x509.PolicyInformation(
                x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.1"),
                None,
            )
        ]
    )
