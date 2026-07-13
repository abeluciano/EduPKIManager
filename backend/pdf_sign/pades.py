from __future__ import annotations

import base64
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from typing import Any

from ca.service import ca_certificate_pem, intermediate_ca_certificate_pem


class PadesDependencyError(RuntimeError):
    pass


class PadesPdfError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class EmbeddedPdfSignature:
    signed_pdf_bytes: bytes
    signed_pdf_sha256: str
    field_name: str
    subfilter: str


def sign_pdf_pades_bytes(
    pdf_bytes: bytes,
    certificate_pem: str,
    private_key_pem: str,
    field_name: str = "EduPKIManagerSignature",
) -> EmbeddedPdfSignature:
    modules = _load_pyhanko()
    signers = modules["signers"]
    IncrementalPdfFileWriter = modules["IncrementalPdfFileWriter"]
    PdfReadError = modules["PdfReadError"]
    SigSeedSubFilter = modules["SigSeedSubFilter"]
    SigningError = modules["SigningError"]

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        key_path = tmp_path / "signer.key.pem"
        cert_path = tmp_path / "signer.cert.pem"
        intermediate_path = tmp_path / "intermediate.cert.pem"
        root_path = tmp_path / "root.cert.pem"
        key_path.write_text(private_key_pem, encoding="ascii")
        cert_path.write_text(certificate_pem, encoding="ascii")
        intermediate_path.write_text(intermediate_ca_certificate_pem(), encoding="ascii")
        root_path.write_text(ca_certificate_pem(), encoding="ascii")

        signer = signers.SimpleSigner.load(
            key_file=str(key_path),
            cert_file=str(cert_path),
            ca_chain_files=(str(intermediate_path), str(root_path)),
            key_passphrase=None,
        )
        try:
            writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes))
            output = BytesIO()
            metadata = signers.PdfSignatureMetadata(
                field_name=field_name,
                md_algorithm="sha256",
                reason="EduPKIManager PAdES signature",
                location="EduPKIManager",
                subfilter=SigSeedSubFilter.PADES,
            )
            signers.sign_pdf(writer, metadata, signer=signer, output=output)
        except SigningError as exc:
            if "hybrid cross-reference" in str(exc).lower():
                raise PadesPdfError(
                    "pdf_hybrid_xref",
                    "Este PDF usa una estructura interna no compatible con la firma PAdES. Guardalo como un PDF nuevo y vuelve a intentarlo, o utiliza Firmar JSON.",
                ) from exc
            raise PadesPdfError(
                "pdf_signing_failed",
                "No se pudo insertar la firma PAdES en este PDF. Revisa el archivo o intenta con Firmar JSON.",
            ) from exc
        except PdfReadError as exc:
            raise PadesPdfError(
                "invalid_pdf",
                "El archivo no tiene una estructura PDF valida o esta danado.",
            ) from exc
        signed_pdf = output.getvalue()
        return EmbeddedPdfSignature(
            signed_pdf_bytes=signed_pdf,
            signed_pdf_sha256=sha256(signed_pdf).hexdigest(),
            field_name=field_name,
            subfilter="PADES",
        )


def verify_pdf_pades_bytes(signed_pdf_bytes: bytes) -> dict[str, Any]:
    modules = _load_pyhanko()
    PdfFileReader = modules["PdfFileReader"]
    PdfReadError = modules["PdfReadError"]
    ValidationContext = modules["ValidationContext"]
    load_cert_from_pemder = modules["load_cert_from_pemder"]
    validate_pdf_signature = modules["validate_pdf_signature"]

    with tempfile.TemporaryDirectory() as tmp:
        root_path = Path(tmp) / "root.cert.pem"
        root_path.write_text(ca_certificate_pem(), encoding="ascii")
        root_cert = load_cert_from_pemder(str(root_path))
        validation_context = ValidationContext(trust_roots=[root_cert], allow_fetching=False)

        try:
            reader = PdfFileReader(BytesIO(signed_pdf_bytes))
            embedded_signatures = list(reader.embedded_signatures)
        except PdfReadError as exc:
            raise PadesPdfError(
                "invalid_pdf",
                "El archivo no tiene una estructura PDF valida o esta danado.",
            ) from exc
        results = []
        for embedded_signature in embedded_signatures:
            status = validate_pdf_signature(
                embedded_signature,
                signer_validation_context=validation_context,
            )
            results.append(
                {
                    "field_name": getattr(embedded_signature, "field_name", ""),
                    "valid": bool(status.bottom_line),
                    "trusted": bool(getattr(status, "trusted", False)),
                    "intact": bool(getattr(status, "intact", False)),
                    "summary": _status_summary(status),
                }
            )

    return {
        "valid": bool(results) and all(item["valid"] for item in results),
        "signature_count": len(results),
        "signatures": results,
        "signed_pdf_sha256": sha256(signed_pdf_bytes).hexdigest(),
    }


def pades_signature_response(signature: EmbeddedPdfSignature) -> dict[str, str]:
    return {
        "format": "PAdES-B-B",
        "field_name": signature.field_name,
        "subfilter": signature.subfilter,
        "signed_pdf_sha256": signature.signed_pdf_sha256,
        "signed_pdf_base64": base64.b64encode(signature.signed_pdf_bytes).decode("ascii"),
    }


def _status_summary(status: Any) -> str:
    if hasattr(status, "summary"):
        return str(status.summary())
    if hasattr(status, "pretty_print_details"):
        return str(status.pretty_print_details())
    return str(status)


def _load_pyhanko() -> dict[str, Any]:
    try:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.pdf_utils.misc import PdfReadError
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign import signers, validation
        from pyhanko.sign.fields import SigSeedSubFilter
        from pyhanko.sign.general import SigningError, load_cert_from_pemder
        from pyhanko_certvalidator import ValidationContext
    except ImportError as exc:
        raise PadesDependencyError(
            "pyHanko is required for embedded PAdES PDF signatures. Install backend requirements or rebuild Docker."
        ) from exc

    return {
        "IncrementalPdfFileWriter": IncrementalPdfFileWriter,
        "PdfFileReader": PdfFileReader,
        "PdfReadError": PdfReadError,
        "SigSeedSubFilter": SigSeedSubFilter,
        "SigningError": SigningError,
        "ValidationContext": ValidationContext,
        "load_cert_from_pemder": load_cert_from_pemder,
        "signers": signers,
        "validate_pdf_signature": validation.validate_pdf_signature,
    }
