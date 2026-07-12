from __future__ import annotations

import base64
import os
import sys

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp


BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/api"


def auth_headers(username: str, password: str) -> dict[str, str]:
    response = requests.post(
        f"{BASE_URL}/auth/login/",
        json={"username": username, "password": password},
        timeout=10,
    )
    response.raise_for_status()
    session = response.json()
    return {"Authorization": f"Bearer {session['token']}", "X-Actor": session["actor"]}


def main() -> None:
    health = requests.get(f"{BASE_URL}/health/", timeout=10)
    health.raise_for_status()
    readiness = requests.get(f"{BASE_URL}/readiness/", timeout=10)
    readiness.raise_for_status()
    assert readiness.json()["status"] == "ready"
    root = requests.get(f"{BASE_URL}/ca/root/", timeout=10)
    root.raise_for_status()
    root_pem = requests.get(f"{BASE_URL}/ca/root.pem", timeout=10)
    root_pem.raise_for_status()
    assert "BEGIN CERTIFICATE" in root_pem.text
    chain_pem = requests.get(f"{BASE_URL}/ca/chain.pem", timeout=10)
    chain_pem.raise_for_status()
    assert chain_pem.text.count("BEGIN CERTIFICATE") >= 2

    admin_headers = auth_headers("admin", os.getenv("EDUPKI_ADMIN_PASSWORD", "admin123"))
    user_headers = auth_headers("user", os.getenv("EDUPKI_USER_PASSWORD", "user123"))

    issued = requests.post(
        f"{BASE_URL}/certificates/",
        json={
            "common_name": "portal.edu.local",
            "certificate_type": "server",
            "sans": ["portal.edu.local", "127.0.0.1"],
            "validity_days": 365,
        },
        headers=admin_headers,
        timeout=30,
    )
    issued.raise_for_status()
    certificate = issued.json()
    assert certificate["owner"] == "admin"

    listed = requests.get(f"{BASE_URL}/certificates/", headers=admin_headers, timeout=10)
    listed.raise_for_status()
    assert any(item["serial_number"] == certificate["serial_number"] for item in listed.json())
    detail = requests.get(f"{BASE_URL}/certificates/{certificate['id']}/", headers=admin_headers, timeout=10)
    detail.raise_for_status()
    assert detail.json()["serial_number"] == certificate["serial_number"]

    forbidden_user_server = requests.post(
        f"{BASE_URL}/certificates/",
        json={
            "common_name": "forbidden-server.edu.local",
            "certificate_type": "server",
            "sans": ["forbidden-server.edu.local"],
            "validity_days": 365,
        },
        headers=user_headers,
        timeout=30,
    )
    assert forbidden_user_server.status_code == 403

    user_issued = requests.post(
        f"{BASE_URL}/certificates/",
        json={
            "common_name": "student.edu.local",
            "certificate_type": "user",
            "sans": ["student.edu.local"],
            "validity_days": 365,
        },
        headers=user_headers,
        timeout=30,
    )
    user_issued.raise_for_status()
    user_certificate = user_issued.json()
    assert user_certificate["owner"] == "user"

    own_list = requests.get(f"{BASE_URL}/certificates/", headers=user_headers, timeout=10)
    own_list.raise_for_status()
    assert all(item["owner"] == "user" for item in own_list.json())

    forbidden_detail = requests.get(f"{BASE_URL}/certificates/{certificate['id']}/", headers=user_headers, timeout=10)
    assert forbidden_detail.status_code == 403

    ocsp_good = requests.post(
        f"{BASE_URL}/ocsp/status/",
        json={"serial_number": user_certificate["serial_number"]},
        timeout=30,
    )
    ocsp_good.raise_for_status()
    assert ocsp_good.json()["status"] == "good"

    trust_good = requests.post(
        f"{BASE_URL}/certificates/validate/",
        json={"serial_number": user_certificate["serial_number"], "purpose": "document_signing"},
        headers=user_headers,
        timeout=30,
    )
    trust_good.raise_for_status()
    assert trust_good.json()["valid"] is True

    ca_response = requests.get(f"{BASE_URL}/ca/root/", timeout=10)
    ca_response.raise_for_status()
    leaf = x509.load_pem_x509_certificate(user_certificate["certificate_pem"].encode("ascii"))
    issuer = x509.load_pem_x509_certificate(ca_response.json()["intermediate_certificate_pem"].encode("ascii"))
    ocsp_request_der = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(leaf, issuer, hashes.SHA1())
        .build()
        .public_bytes(serialization.Encoding.DER)
    )
    standard_ocsp_good = requests.post(
        f"{BASE_URL}/ocsp/",
        data=ocsp_request_der,
        headers={"Content-Type": "application/ocsp-request"},
        timeout=30,
    )
    standard_ocsp_good.raise_for_status()
    parsed_standard_good = ocsp.load_der_ocsp_response(standard_ocsp_good.content)
    assert parsed_standard_good.certificate_status == ocsp.OCSPCertStatus.GOOD

    pdf_base64 = base64.b64encode(_minimal_pdf()).decode("ascii")
    signature = requests.post(
        f"{BASE_URL}/pdf/sign/",
        json={"serial_number": user_certificate["serial_number"], "pdf_base64": pdf_base64},
        headers=user_headers,
        timeout=30,
    )
    signature.raise_for_status()

    verification = requests.post(
        f"{BASE_URL}/pdf/verify/",
        json={"pdf_base64": pdf_base64, "signature_envelope": signature.json()},
        headers=user_headers,
        timeout=30,
    )
    verification.raise_for_status()
    assert verification.json()["valid"] is True

    embedded_signature = requests.post(
        f"{BASE_URL}/pdf/sign-embedded/",
        json={"serial_number": user_certificate["serial_number"], "pdf_base64": pdf_base64},
        headers=user_headers,
        timeout=60,
    )
    embedded_signature.raise_for_status()
    signed_pdf_base64 = embedded_signature.json()["signed_pdf_base64"]
    embedded_verification = requests.post(
        f"{BASE_URL}/pdf/verify-embedded/",
        json={"signed_pdf_base64": signed_pdf_base64},
        headers=user_headers,
        timeout=60,
    )
    embedded_verification.raise_for_status()
    assert embedded_verification.json()["valid"] is True

    renewed = requests.post(
        f"{BASE_URL}/certificates/{certificate['id']}/renew/",
        json={"validity_days": 365},
        headers=admin_headers,
        timeout=30,
    )
    renewed.raise_for_status()

    suspended = requests.post(
        f"{BASE_URL}/certificates/{user_certificate['id']}/suspend/",
        json={},
        headers=admin_headers,
        timeout=30,
    )
    suspended.raise_for_status()

    trust_suspended = requests.post(
        f"{BASE_URL}/certificates/validate/",
        json={"serial_number": user_certificate["serial_number"], "purpose": "document_signing"},
        headers=user_headers,
        timeout=30,
    )
    trust_suspended.raise_for_status()
    assert trust_suspended.json()["valid"] is False
    assert trust_suspended.json()["revocation"]["status"] == "revoked"

    revoked_candidate = requests.post(
        f"{BASE_URL}/certificates/",
        json={
            "common_name": "revoked.edu.local",
            "certificate_type": "device",
            "sans": ["revoked.edu.local"],
            "validity_days": 365,
        },
        headers=admin_headers,
        timeout=30,
    )
    revoked_candidate.raise_for_status()
    revoked = requests.post(
        f"{BASE_URL}/certificates/{revoked_candidate.json()['id']}/revoke/",
        json={"reason": "key_compromise"},
        headers=admin_headers,
        timeout=30,
    )
    revoked.raise_for_status()

    ocsp_revoked = requests.post(
        f"{BASE_URL}/ocsp/status/",
        json={"serial_number": user_certificate["serial_number"]},
        timeout=30,
    )
    ocsp_revoked.raise_for_status()
    assert ocsp_revoked.json()["status"] == "revoked"

    standard_ocsp_revoked = requests.post(
        f"{BASE_URL}/ocsp/",
        data=ocsp_request_der,
        headers={"Content-Type": "application/ocsp-request"},
        timeout=30,
    )
    standard_ocsp_revoked.raise_for_status()
    parsed_standard_revoked = ocsp.load_der_ocsp_response(standard_ocsp_revoked.content)
    assert parsed_standard_revoked.certificate_status == ocsp.OCSPCertStatus.REVOKED

    crl = requests.get(f"{BASE_URL}/crl.pem", timeout=10)
    crl.raise_for_status()
    assert "BEGIN X509 CRL" in crl.text
    crl_der = requests.get(f"{BASE_URL}/crl.der", timeout=10)
    crl_der.raise_for_status()
    assert len(crl_der.content) > 0
    crl_manifest = requests.get(f"{BASE_URL}/crl/manifest/", timeout=10)
    crl_manifest.raise_for_status()
    current_crl = crl_manifest.json()["current_number"]
    assert current_crl >= 1
    crl_version = requests.get(f"{BASE_URL}/crl/{current_crl}.pem", timeout=10)
    crl_version.raise_for_status()
    assert "BEGIN X509 CRL" in crl_version.text

    tls = requests.get(f"{BASE_URL}/tls/demo/", headers=admin_headers, timeout=30)
    tls.raise_for_status()
    assert tls.json()["client_tls_version"] == "TLSv1.3"
    assert tls.json()["hostname"] == "edupkimanager.com"

    audit = requests.get(f"{BASE_URL}/audit/", headers=admin_headers, timeout=10)
    audit.raise_for_status()
    assert audit.json()["valid_chain"] is True
    assert audit.json()["verification"]["entry_count"] >= 1
    assert audit.json()["verification"]["last_hash"]
    print("API smoke test completed.")


def _minimal_pdf() -> bytes:
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 160] /Resources << >> /Contents 4 0 R >>",
        b"<< /Length 0 >>\nstream\n\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


if __name__ == "__main__":
    main()
