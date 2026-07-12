from __future__ import annotations

import tempfile
import unittest
import importlib.util
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from audit.service import append_audit_entry, verify_audit_log, verify_audit_log_report
from ca.service import CertificateRequest, ensure_intermediate_ca, ensure_root_ca, issue_certificate, parse_certificate, set_storage_dir
from crl.publication import latest_crl_bytes, load_manifest, publish_crl_if_needed, versioned_crl_bytes
from crl.service import crl_pem, generate_crl
from ocsp.service import OcspCertificateState, build_ocsp_response, build_standard_ocsp_response, inspect_ocsp_response
from pdf_sign.pades import sign_pdf_pades_bytes, verify_pdf_pades_bytes
from pdf_sign.service import sign_pdf_bytes, verify_pdf_signature
from validation.trust import validate_certificate_trust


class CryptoFlowTests(unittest.TestCase):
    def test_end_to_end_crypto_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            set_storage_dir(tmp)
            ca = ensure_root_ca()
            intermediate = ensure_intermediate_ca()
            self.assertTrue(ca.key_path.exists())
            self.assertTrue(ca.certificate_path.exists())
            self.assertEqual(intermediate.certificate.issuer, ca.certificate.subject)
            self.assertEqual(
                intermediate.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length,
                0,
            )

            issued = issue_certificate(
                CertificateRequest(
                    common_name="student.example.edu",
                    certificate_type="server",
                    sans=("student.example.edu", "127.0.0.1"),
                )
            )
            certificate = parse_certificate(issued.certificate_pem)
            self.assertEqual(certificate.serial_number, issued.serial_number)
            self.assertEqual(certificate.issuer, intermediate.certificate.subject)
            crl_points = certificate.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            self.assertTrue(crl_points[0].full_name[0].value.endswith("/crl.der"))
            aia = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            self.assertTrue(any(item.access_method == AuthorityInformationAccessOID.OCSP for item in aia))
            self.assertIsNotNone(certificate.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES))

            crl = generate_crl([{"serial_number": issued.serial_number, "reason": "key_compromise"}])
            self.assertEqual(crl.issuer, intermediate.certificate.subject)
            self.assertIn(issued.serial_number, [revoked.serial_number for revoked in crl])
            self.assertIn(b"BEGIN X509 CRL", crl_pem([{"serial_number": issued.serial_number}]))

            crl_dir = Path(tmp) / "published-crl"
            revoked_items = [{"serial_number": issued.serial_number, "reason": "key_compromise"}]
            manifest_v1 = publish_crl_if_needed(revoked_items, crl_dir)
            self.assertEqual(manifest_v1["current_number"], 1)
            self.assertTrue((crl_dir / "crl-1.pem").exists())
            self.assertTrue((crl_dir / "latest.crl.der").exists())
            self.assertEqual(load_manifest(crl_dir)["current_number"], 1)
            self.assertIn(b"BEGIN X509 CRL", latest_crl_bytes(revoked_items, "pem", crl_dir))
            self.assertGreater(len(versioned_crl_bytes(1, "der", crl_dir)), 0)

            manifest_same = publish_crl_if_needed(revoked_items, crl_dir)
            self.assertEqual(manifest_same["current_number"], 1)
            manifest_v2 = publish_crl_if_needed(
                [*revoked_items, {"serial_number": issued.serial_number + 1, "reason": "certificate_hold"}],
                crl_dir,
            )
            self.assertEqual(manifest_v2["current_number"], 2)
            self.assertTrue((crl_dir / "crl-2.pem").exists())

            ocsp_der = build_ocsp_response(issued.certificate_pem, "good")
            ocsp_info = inspect_ocsp_response(ocsp_der)
            self.assertEqual(ocsp_info["certificate_status"], "GOOD")

            ocsp_request = (
                ocsp.OCSPRequestBuilder()
                .add_certificate(certificate, intermediate.certificate, hashes.SHA1())
                .build()
                .public_bytes(serialization.Encoding.DER)
            )
            standard_good = ocsp.load_der_ocsp_response(
                build_standard_ocsp_response(
                    ocsp_request,
                    OcspCertificateState(certificate_pem=issued.certificate_pem, status="good"),
                )
            )
            self.assertEqual(standard_good.certificate_status, ocsp.OCSPCertStatus.GOOD)

            standard_revoked = ocsp.load_der_ocsp_response(
                build_standard_ocsp_response(
                    ocsp_request,
                    OcspCertificateState(certificate_pem=issued.certificate_pem, status="revoked", reason="key_compromise"),
                )
            )
            self.assertEqual(standard_revoked.certificate_status, ocsp.OCSPCertStatus.REVOKED)

            standard_unknown = ocsp.load_der_ocsp_response(build_standard_ocsp_response(ocsp_request, None))
            self.assertEqual(standard_unknown.certificate_status, ocsp.OCSPCertStatus.UNKNOWN)

            tls_trust = validate_certificate_trust(issued.certificate_pem, purpose="server_auth", revocation_records=[])
            self.assertTrue(tls_trust["valid"], tls_trust["errors"])
            document_trust_for_server = validate_certificate_trust(issued.certificate_pem, purpose="document_signing", revocation_records=[])
            self.assertFalse(document_trust_for_server["valid"])

            signer = issue_certificate(
                CertificateRequest(
                    common_name="signer.example.edu",
                    certificate_type="user",
                    sans=("signer.example.edu",),
                )
            )
            signer_trust = validate_certificate_trust(signer.certificate_pem, purpose="document_signing", revocation_records=[])
            self.assertTrue(signer_trust["valid"], signer_trust["errors"])
            revoked_trust = validate_certificate_trust(
                signer.certificate_pem,
                purpose="document_signing",
                revocation_records=[{"serial_number": signer.serial_number, "reason": "key_compromise"}],
            )
            self.assertFalse(revoked_trust["valid"])
            self.assertEqual(revoked_trust["revocation"]["status"], "revoked")
            self.assertTrue(revoked_trust["revocation"]["revoked_by_database"])
            self.assertTrue(revoked_trust["revocation"]["revoked_by_crl"])

            pdf = b"%PDF-1.4\n% EduPKIManager demo\n"
            envelope = sign_pdf_bytes(pdf, issued.certificate_pem, issued.private_key_pem, actor="alice")
            verification = verify_pdf_signature(pdf, envelope)
            self.assertTrue(verification["valid"])

            log_path = Path(tmp) / "audit.jsonl"
            append_audit_entry(log_path, "issue_certificate", "admin", "success", {"serial": issued.serial_number})
            append_audit_entry(log_path, "verify_signature", "alice", "success", {"serial": issued.serial_number})
            self.assertTrue(verify_audit_log(log_path))
            report = verify_audit_log_report(log_path)
            self.assertTrue(report.valid_chain)
            self.assertEqual(report.entry_count, 2)
            self.assertIsNotNone(report.last_hash)

            tampered = log_path.read_text(encoding="utf-8").replace("verify_signature", "verify_signature_tampered")
            log_path.write_text(tampered, encoding="utf-8")
            tampered_report = verify_audit_log_report(log_path)
            self.assertFalse(tampered_report.valid_chain)
            self.assertEqual(tampered_report.broken_at_index, 2)

    @unittest.skipIf(importlib.util.find_spec("pyhanko") is None, "pyHanko is not installed in this runtime")
    def test_pades_embedded_pdf_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            set_storage_dir(tmp)
            issued = issue_certificate(
                CertificateRequest(
                    common_name="signer.example.edu",
                    certificate_type="user",
                    sans=("signer.example.edu",),
                )
            )
            signed = sign_pdf_pades_bytes(_minimal_pdf(), issued.certificate_pem, issued.private_key_pem)
            verification = verify_pdf_pades_bytes(signed.signed_pdf_bytes)
            self.assertTrue(verification["valid"])
            self.assertEqual(verification["signature_count"], 1)

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
    unittest.main()
