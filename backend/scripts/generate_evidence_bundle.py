from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from verify_https_tls import verify_https_tls


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a full delivery evidence bundle from a running EduPKIManager deployment.")
    parser.add_argument("--api-base-url", default="http://127.0.0.1:8000/api")
    parser.add_argument("--frontend-url", default="http://localhost:3000")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/evidence"))
    parser.add_argument("--https-connect-host", default="127.0.0.1")
    parser.add_argument("--https-port", type=int, default=443)
    parser.add_argument("--https-server-name", default="edupkimanager.com")
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-password", default=os.getenv("EDUPKI_ADMIN_PASSWORD", "admin123"))
    parser.add_argument("--user-name", default="abel.aragon")
    parser.add_argument("--user-password", default="abel123")
    parser.add_argument("--user-owner", default="Abel Aragon")
    args = parser.parse_args()

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = args.output_dir / run_id
    evidence_dir.mkdir(parents=True, exist_ok=True)

    api_base = args.api_base_url.rstrip("/")
    frontend = args.frontend_url.rstrip("/")
    results: list[dict[str, Any]] = []
    artifacts: list[dict[str, str]] = []

    def record(name: str, status: str, detail: str, artifact: Path | None = None) -> None:
        item: dict[str, Any] = {"name": name, "status": status, "detail": detail}
        if artifact is not None:
            item["artifact"] = artifact.name
            artifacts.append({"name": name, "file": artifact.name})
        results.append(item)

    def checked(response: requests.Response, expected: tuple[int, ...] = (200,)) -> requests.Response:
        if response.status_code not in expected:
            body = response.text[:1000]
            raise RuntimeError(f"{response.request.method} {response.url} returned {response.status_code}: {body}")
        return response

    def write_json(name: str, payload: Any) -> Path:
        target = evidence_dir / name
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return target

    def write_text(name: str, payload: str) -> Path:
        target = evidence_dir / name
        target.write_text(payload, encoding="utf-8")
        return target

    def write_bytes(name: str, payload: bytes) -> Path:
        target = evidence_dir / name
        target.write_bytes(payload)
        return target

    def auth_headers(username: str, password: str) -> dict[str, str]:
        response = checked(
            requests.post(
                f"{api_base}/auth/login/",
                json={"username": username, "password": password},
                timeout=10,
            )
        )
        session = response.json()
        return {"Authorization": f"Bearer {session['token']}", "X-Actor": session["actor"]}

    health = checked(requests.get(f"{api_base}/health/", timeout=10)).json()
    readiness = checked(requests.get(f"{api_base}/readiness/", timeout=10)).json()
    if readiness["status"] != "ready":
        raise RuntimeError(f"Deployment is not ready: {readiness}")
    record("Readiness", "pass", "API health and readiness returned ok.", write_json("readiness.json", {"health": health, "readiness": readiness}))

    frontend_health = checked(requests.get(f"{frontend}/healthz", timeout=10)).text.strip()
    if frontend_health != "ok":
        raise RuntimeError(f"Unexpected frontend health response: {frontend_health!r}")
    record("Frontend health", "pass", f"{frontend}/healthz returned ok.")

    ca_json = checked(requests.get(f"{api_base}/ca/root/", timeout=10)).json()
    root_pem = checked(requests.get(f"{api_base}/ca/root.pem", timeout=10)).text
    chain_pem = checked(requests.get(f"{api_base}/ca/chain.pem", timeout=10)).text
    root_path = write_text("root-ca.pem", root_pem)
    chain_path = write_text("ca-chain.pem", chain_pem)
    record("CA chain", "pass", "Root CA and CA chain were downloaded.", root_path)
    artifacts.append({"name": "CA chain PEM", "file": chain_path.name})

    admin_headers = auth_headers(args.admin_user, args.admin_password)
    user_headers = auth_headers(args.user_name, args.user_password)
    record("Authentication", "pass", "Admin and fixed owner account authenticated successfully.")

    common_name = f"evidence-{run_id.lower()}.edu.local"
    issued = checked(
        requests.post(
            f"{api_base}/certificates/",
            json={
                "common_name": common_name,
                "certificate_type": "user",
                "organization": "EduPKIManager",
                "organizational_unit": "Evidence",
                "country": "PE",
                "owner": args.user_owner,
                "sans": [common_name],
                "validity_days": 90,
                "key_algorithm": "rsa-2048",
            },
            headers=admin_headers,
            timeout=30,
        ),
        expected=(201,),
    ).json()
    issued_public = dict(issued)
    issued_public["private_key_pem"] = "<redacted>"
    cert_json_path = write_json("issued-certificate.json", issued_public)
    cert_pem_path = write_text("issued-certificate.pem", issued["certificate_pem"])
    record("Certificate issuance", "pass", f"Admin issued user certificate serial {issued['serial_number']} for {args.user_owner}.", cert_json_path)
    artifacts.append({"name": "Issued certificate PEM", "file": cert_pem_path.name})

    trust_good = checked(
        requests.post(
            f"{api_base}/certificates/validate/",
            json={"serial_number": issued["serial_number"], "purpose": "document_signing"},
            headers=user_headers,
            timeout=30,
        )
    ).json()
    if trust_good["valid"] is not True:
        raise RuntimeError(f"Issued certificate did not validate: {trust_good}")
    record("Trust validation", "pass", "Issued certificate validates for document_signing.", write_json("trust-valid-issued.json", trust_good))

    pdf_bytes = _minimal_pdf()
    pdf_path = write_bytes("original-demo.pdf", pdf_bytes)
    pdf_base64 = base64.b64encode(pdf_bytes).decode("ascii")
    record("Demo PDF", "pass", "Created a minimal PDF for signing.", pdf_path)

    detached_signature = checked(
        requests.post(
            f"{api_base}/pdf/sign/",
            json={"serial_number": issued["serial_number"], "pdf_base64": pdf_base64},
            headers=user_headers,
            timeout=30,
        )
    ).json()
    signature_path = write_json("detached-signature-envelope.json", detached_signature)
    record("Detached PDF signature", "pass", "Detached PDF signature envelope generated.", signature_path)

    detached_verification = checked(
        requests.post(
            f"{api_base}/pdf/verify/",
            json={"pdf_base64": pdf_base64, "signature_envelope": detached_signature},
            headers=user_headers,
            timeout=30,
        )
    ).json()
    if detached_verification["valid"] is not True:
        raise RuntimeError(f"Detached PDF verification failed: {detached_verification}")
    record("Detached PDF verification", "pass", "Detached signature and trust chain validated.", write_json("detached-verification-valid.json", detached_verification))

    pades_response = requests.post(
        f"{api_base}/pdf/sign-embedded/",
        json={"serial_number": issued["serial_number"], "pdf_base64": pdf_base64},
        headers=user_headers,
        timeout=60,
    )
    if pades_response.status_code == 501:
        record("PAdES embedded signature", "warn", pades_response.json().get("detail", "PAdES dependency unavailable."))
    else:
        checked(pades_response)
        pades_signature = pades_response.json()
        signed_pdf_bytes = base64.b64decode(pades_signature["signed_pdf_base64"])
        signed_pdf_path = write_bytes("signed-demo-pades.pdf", signed_pdf_bytes)
        pades_verification = checked(
            requests.post(
                f"{api_base}/pdf/verify-embedded/",
                json={"signed_pdf_base64": pades_signature["signed_pdf_base64"]},
                headers=user_headers,
                timeout=60,
            )
        ).json()
        if pades_verification["valid"] is not True:
            raise RuntimeError(f"PAdES verification failed: {pades_verification}")
        record("PAdES embedded signature", "pass", "Embedded PAdES PDF was signed and verified.", signed_pdf_path)
        artifacts.append({"name": "PAdES verification", "file": write_json("pades-verification-valid.json", pades_verification).name})

    ocsp_good = checked(
        requests.post(
            f"{api_base}/ocsp/status/",
            json={"serial_number": issued["serial_number"]},
            timeout=30,
        )
    ).json()
    if ocsp_good["status"] != "good":
        raise RuntimeError(f"OCSP JSON did not report good: {ocsp_good}")
    record("OCSP JSON good", "pass", "OCSP JSON endpoint reports good.", write_json("ocsp-json-good.json", ocsp_good))

    ocsp_request_der = _ocsp_request_der(issued["certificate_pem"], ca_json["intermediate_certificate_pem"])
    ocsp_request_path = write_bytes("ocsp-request.der", ocsp_request_der)
    standard_good_response = checked(
        requests.post(
            f"{api_base}/ocsp/",
            data=ocsp_request_der,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=30,
        )
    )
    standard_good_path = write_bytes("ocsp-response-good.der", standard_good_response.content)
    parsed_good = ocsp.load_der_ocsp_response(standard_good_response.content)
    if parsed_good.certificate_status != ocsp.OCSPCertStatus.GOOD:
        raise RuntimeError(f"Standard OCSP did not report GOOD: {parsed_good.certificate_status}")
    record("OCSP RFC 6960 good", "pass", "DER OCSP response reports GOOD.", standard_good_path)
    artifacts.append({"name": "OCSP request DER", "file": ocsp_request_path.name})

    renewed = checked(
        requests.post(
            f"{api_base}/certificates/{issued['id']}/renew/",
            json={"validity_days": 90},
            headers=admin_headers,
            timeout=30,
        )
    ).json()
    renewed_public = dict(renewed)
    renewed_public["private_key_pem"] = "<redacted>"
    renewed_path = write_json("renewed-certificate.json", renewed_public)
    record("Certificate renewal", "pass", f"Renewed certificate into serial {renewed['serial_number']}.", renewed_path)

    suspended = checked(
        requests.post(
            f"{api_base}/certificates/{issued['id']}/suspend/",
            json={},
            headers=admin_headers,
            timeout=30,
        )
    ).json()
    record("Certificate suspension", "pass", f"Original serial {suspended['serial_number']} moved to suspended.", write_json("suspended-certificate.json", suspended))

    revoked = checked(
        requests.post(
            f"{api_base}/certificates/{renewed['id']}/revoke/",
            json={"reason": "cessation_of_operation"},
            headers=admin_headers,
            timeout=30,
        )
    ).json()
    record("Certificate revocation", "pass", f"Renewed serial {revoked['serial_number']} moved to revoked.", write_json("revoked-certificate.json", revoked))

    trust_after_suspension = checked(
        requests.post(
            f"{api_base}/certificates/validate/",
            json={"serial_number": issued["serial_number"], "purpose": "document_signing"},
            headers=user_headers,
            timeout=30,
        )
    ).json()
    if trust_after_suspension["valid"] is not False:
        raise RuntimeError(f"Suspended certificate should not validate: {trust_after_suspension}")
    record("Trust after suspension", "pass", "Suspended certificate is rejected by trust validation.", write_json("trust-invalid-suspended.json", trust_after_suspension))

    detached_after_suspension = checked(
        requests.post(
            f"{api_base}/pdf/verify/",
            json={"pdf_base64": pdf_base64, "signature_envelope": detached_signature},
            headers=user_headers,
            timeout=30,
        )
    ).json()
    if detached_after_suspension["valid"] is not False:
        raise RuntimeError(f"Detached PDF should be untrusted after suspension: {detached_after_suspension}")
    record("PDF trust after suspension", "pass", "Detached signature cryptography remains intact but trust validation fails after suspension.", write_json("detached-verification-after-suspension.json", detached_after_suspension))

    ocsp_revoked = checked(
        requests.post(
            f"{api_base}/ocsp/status/",
            json={"serial_number": issued["serial_number"]},
            timeout=30,
        )
    ).json()
    if ocsp_revoked["status"] != "revoked":
        raise RuntimeError(f"OCSP JSON did not report revoked for suspended cert: {ocsp_revoked}")
    record("OCSP JSON revoked", "pass", "Suspended certificate is reported as revoked by OCSP JSON.", write_json("ocsp-json-revoked.json", ocsp_revoked))

    standard_revoked_response = checked(
        requests.post(
            f"{api_base}/ocsp/",
            data=ocsp_request_der,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=30,
        )
    )
    standard_revoked_path = write_bytes("ocsp-response-revoked.der", standard_revoked_response.content)
    parsed_revoked = ocsp.load_der_ocsp_response(standard_revoked_response.content)
    if parsed_revoked.certificate_status != ocsp.OCSPCertStatus.REVOKED:
        raise RuntimeError(f"Standard OCSP did not report REVOKED: {parsed_revoked.certificate_status}")
    record("OCSP RFC 6960 revoked", "pass", "DER OCSP response reports REVOKED after suspension.", standard_revoked_path)

    ocsp_unknown = checked(
        requests.post(
            f"{api_base}/ocsp/status/",
            json={"serial_number": "999999999999999999999999"},
            timeout=30,
        )
    ).json()
    if ocsp_unknown["status"] != "unknown":
        raise RuntimeError(f"OCSP JSON did not report unknown: {ocsp_unknown}")
    record("OCSP JSON unknown", "pass", "Unknown serial returns unknown.", write_json("ocsp-json-unknown.json", ocsp_unknown))

    crl_manifest = checked(requests.get(f"{api_base}/crl/manifest/", timeout=10)).json()
    crl_pem = checked(requests.get(f"{api_base}/crl.pem", timeout=10)).text
    crl_der = checked(requests.get(f"{api_base}/crl.der", timeout=10)).content
    manifest_path = write_json("crl-manifest.json", crl_manifest)
    crl_pem_path = write_text("latest.crl.pem", crl_pem)
    crl_der_path = write_bytes("latest.crl.der", crl_der)
    current_version = _current_crl_version(crl_manifest)
    revoked_count = current_version.get("revoked_count", 0)
    record("CRL publication", "pass", f"CRL number {crl_manifest['current_number']} published with {revoked_count} revoked/suspended certificates.", manifest_path)
    artifacts.append({"name": "Latest CRL PEM", "file": crl_pem_path.name})
    artifacts.append({"name": "Latest CRL DER", "file": crl_der_path.name})

    tls = verify_https_tls(args.https_connect_host, args.https_port, args.https_server_name, root_path)
    if tls["tls_version"] != "TLSv1.3" or " 200 " not in tls["status_line"]:
        raise RuntimeError(f"TLS verification failed: {tls}")
    record("TLS 1.3", "pass", f"{tls['server_name']} negotiated {tls['tls_version']} with {tls['cipher']}.", write_json("tls-verification.json", tls))

    audit = checked(requests.get(f"{api_base}/audit/", headers=admin_headers, timeout=10)).json()
    if audit["valid_chain"] is not True:
        raise RuntimeError(f"Audit chain is not valid: {audit['verification']}")
    audit_summary = {
        "valid_chain": audit["valid_chain"],
        "verification": audit["verification"],
        "last_entries": audit["entries"][-10:],
    }
    record("Immutable audit", "pass", f"Audit hash chain valid with {audit['verification']['entry_count']} entries.", write_json("audit-summary.json", audit_summary))

    summary = {
        "run_id": run_id,
        "api_base_url": api_base,
        "frontend_url": frontend,
        "https_server_name": args.https_server_name,
        "results": results,
        "artifacts": artifacts,
    }
    write_json("evidence-summary.json", summary)
    report_path = write_text("EVIDENCE_REPORT.md", _markdown_report(summary))
    print(f"Evidence bundle generated: {evidence_dir}")
    print(f"Report: {report_path}")


def _ocsp_request_der(certificate_pem: str, issuer_pem: str) -> bytes:
    leaf = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    issuer = x509.load_pem_x509_certificate(issuer_pem.encode("ascii"))
    return (
        ocsp.OCSPRequestBuilder()
        .add_certificate(leaf, issuer, hashes.SHA1())
        .build()
        .public_bytes(serialization.Encoding.DER)
    )


def _current_crl_version(manifest: dict[str, Any]) -> dict[str, Any]:
    current_number = manifest.get("current_number")
    versions = manifest.get("versions", [])
    for version in versions:
        if version.get("number") == current_number:
            return version
    return versions[-1] if versions else {}


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


def _markdown_report(summary: dict[str, Any]) -> str:
    result_rows = "\n".join(
        f"| {item['name']} | {item['status']} | {item['detail']} | {item.get('artifact', '')} |"
        for item in summary["results"]
    )
    artifact_rows = "\n".join(f"| {item['name']} | `{item['file']}` |" for item in summary["artifacts"])
    return f"""# EduPKIManager Evidence Report

Run ID: `{summary['run_id']}`

API: `{summary['api_base_url']}`

Frontend: `{summary['frontend_url']}`

HTTPS server name: `{summary['https_server_name']}`

## Resultados

| Check | Estado | Detalle | Evidencia |
| --- | --- | --- | --- |
{result_rows}

## Artefactos

| Artefacto | Archivo |
| --- | --- |
{artifact_rows}

## Cobertura

Este bundle demuestra emision X.509, validacion de confianza, firma PDF desprendida, firma PAdES embebida cuando esta disponible, OCSP JSON y RFC 6960, renovacion, suspension, revocacion, CRL versionada, TLS 1.3 y auditoria inmutable.
"""


if __name__ == "__main__":
    main()
