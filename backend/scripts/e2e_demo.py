from __future__ import annotations

import tempfile
from pathlib import Path

from audit.service import append_audit_entry, verify_audit_log_report
from ca.service import CertificateRequest, issue_certificate, set_storage_dir
from crl.service import crl_pem
from ocsp.service import build_ocsp_response, inspect_ocsp_response
from pdf_sign.service import sign_pdf_bytes, verify_pdf_signature


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        set_storage_dir(tmp)
        issued = issue_certificate(CertificateRequest(common_name="portal.edu.local", certificate_type="server", sans=("portal.edu.local", "127.0.0.1")))
        pdf = b"%PDF-1.4\n% Demo PDF EduPKIManager\n"
        signature = sign_pdf_bytes(pdf, issued.certificate_pem, issued.private_key_pem, actor="demo-admin")
        verification = verify_pdf_signature(pdf, signature)
        revoked = [{"serial_number": issued.serial_number, "reason": "key_compromise"}]
        crl = crl_pem(revoked)
        ocsp = inspect_ocsp_response(build_ocsp_response(issued.certificate_pem, "revoked"))
        audit_path = Path(tmp) / "audit.jsonl"
        append_audit_entry(audit_path, "issue_certificate", "demo-admin", "success", {"serial": issued.serial_number})
        append_audit_entry(audit_path, "sign_pdf", "demo-admin", "success", {"serial": issued.serial_number})
        append_audit_entry(audit_path, "revoke_certificate", "demo-admin", "success", {"serial": issued.serial_number})

        print("1. Certificado emitido:", issued.serial_number)
        print("2. PDF firmado:", signature["signature_algorithm"])
        print("3. Verificacion:", verification["valid"])
        print("4. CRL actualizada:", len(crl), "bytes")
        print("5. OCSP:", ocsp["certificate_status"])
        audit_report = verify_audit_log_report(audit_path)
        print("6. Auditoria integra:", audit_report.valid_chain, "entradas:", audit_report.entry_count)


if __name__ == "__main__":
    main()
