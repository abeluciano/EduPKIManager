from __future__ import annotations

import base64
import json
from pathlib import Path

from django.conf import settings
from django.db import connection
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.core import signing
from django.utils import timezone
from cryptography.x509 import ocsp as ocsp_module
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from audit.service import append_audit_entry, default_audit_log_path, read_audit_entries, verify_audit_log_report
from ca.service import CertificateRequest, ca_certificate_pem, ca_chain_pem, intermediate_ca_certificate_pem, issue_certificate
from crl.publication import latest_crl_bytes, load_manifest, publish_crl_if_needed, versioned_crl_bytes
from ocsp.service import OcspCertificateState, build_ocsp_response, build_standard_ocsp_response, build_unsuccessful_ocsp_response, inspect_ocsp_response
from pdf_sign.pades import PadesDependencyError, pades_signature_response, sign_pdf_pades_bytes, verify_pdf_pades_bytes
from pdf_sign.service import sign_pdf_bytes, verify_pdf_signature
from scripts.tls13_demo import run_tls13_handshake_demo
from validation.trust import validate_certificate_trust

from .models import CertificateRecord


AUDIT_LOG = default_audit_log_path()
AUTH_SALT = "edupki-auth-v1"


class HealthView(APIView):
    def get(self, request):
        return Response({"status": "ok", "service": "EduPKIManager"})


class ReadinessView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        checks: dict[str, object] = {}
        overall_ready = True

        try:
            connection.ensure_connection()
            checks["database"] = {"ready": True}
        except Exception as exc:
            checks["database"] = {"ready": False, "error": str(exc)}
            overall_ready = False

        try:
            root_pem = ca_certificate_pem()
            intermediate_pem = intermediate_ca_certificate_pem()
            checks["ca"] = {
                "ready": True,
                "root_pem_bytes": len(root_pem.encode("ascii")),
                "intermediate_pem_bytes": len(intermediate_pem.encode("ascii")),
            }
        except Exception as exc:
            checks["ca"] = {"ready": False, "error": str(exc)}
            overall_ready = False

        try:
            manifest = publish_crl_if_needed(_revoked_certificates())
            checks["crl"] = {
                "ready": True,
                "current_number": manifest["current_number"],
                "versions": len(manifest.get("versions", [])),
            }
        except Exception as exc:
            checks["crl"] = {"ready": False, "error": str(exc)}
            overall_ready = False

        try:
            audit_report = verify_audit_log_report(AUDIT_LOG)
            checks["audit"] = {
                "ready": audit_report.valid_chain,
                "entry_count": audit_report.entry_count,
                "last_hash": audit_report.last_hash,
                "errors": audit_report.errors,
            }
            overall_ready = overall_ready and audit_report.valid_chain
        except Exception as exc:
            checks["audit"] = {"ready": False, "error": str(exc)}
            overall_ready = False

        response_status = status.HTTP_200_OK if overall_ready else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response({"status": "ready" if overall_ready else "not_ready", "checks": checks}, status=response_status)


class AuthLoginView(APIView):
    def post(self, request):
        username = str(request.data.get("username", ""))
        password = str(request.data.get("password", ""))
        user = _demo_users().get(username)
        if user is None or user["password"] != password:
            raise AuthenticationFailed("Invalid credentials.")
        token = signing.dumps({"actor": username, "role": user["role"]}, salt=AUTH_SALT)
        append_audit_entry(AUDIT_LOG, "login", username, "success", {"role": user["role"]})
        return Response({"actor": username, "role": user["role"], "token": token})


class RootCaView(APIView):
    def get(self, request):
        root_pem = ca_certificate_pem()
        intermediate_pem = intermediate_ca_certificate_pem()
        append_audit_entry(AUDIT_LOG, "read_ca_chain", _actor(request), "success", {"format": "json"})
        return Response(
            {
                "certificate_pem": root_pem,
                "root_certificate_pem": root_pem,
                "intermediate_certificate_pem": intermediate_pem,
                "certificate_chain_pem": intermediate_pem + root_pem,
            }
        )


class RootCaPemView(APIView):
    def get(self, request):
        append_audit_entry(AUDIT_LOG, "download_root_ca", _actor(request), "success", {"format": "pem"})
        response = HttpResponse(ca_certificate_pem(), content_type="application/x-pem-file")
        response["Content-Disposition"] = 'attachment; filename="edupki-root-ca.pem"'
        return response


class CaChainPemView(APIView):
    def get(self, request):
        append_audit_entry(AUDIT_LOG, "download_ca_chain", _actor(request), "success", {"format": "pem"})
        response = HttpResponse(ca_chain_pem(), content_type="application/x-pem-file")
        response["Content-Disposition"] = 'attachment; filename="edupki-ca-chain.pem"'
        return response


class CertificateListCreateView(APIView):
    def get(self, request):
        context = _require_role(request, {"admin", "user"})
        records = CertificateRecord.objects.all() if context["role"] == "admin" else CertificateRecord.objects.filter(owner=context["actor"])
        return Response([_record_payload(record, include_private_key=False) for record in records])

    def post(self, request):
        context = _require_role(request, {"admin", "user"})
        payload = request.data
        certificate_type = payload.get("certificate_type", "user")
        if context["role"] != "admin" and certificate_type != "user":
            append_audit_entry(
                AUDIT_LOG,
                "issue_certificate",
                context["actor"],
                "failed",
                {"reason": "user_role_can_only_issue_user_certificates", "requested_type": certificate_type},
            )
            raise PermissionDenied("User role can only request user certificates.")
        owner = str(payload.get("owner") or context["actor"]) if context["role"] == "admin" else context["actor"]
        cert_request = CertificateRequest(
            common_name=payload["common_name"],
            certificate_type=certificate_type,
            organization=payload.get("organization", "EduPKIManager"),
            organizational_unit=payload.get("organizational_unit", "Education PKI"),
            country=payload.get("country", "PE"),
            sans=tuple(payload.get("sans", [])),
            validity_days=int(payload.get("validity_days", 365)),
            key_algorithm=payload.get("key_algorithm", "rsa-2048"),
        )
        issued = issue_certificate(cert_request)
        record = CertificateRecord.objects.create(
            serial_number=str(issued.serial_number),
            common_name=cert_request.common_name,
            certificate_type=cert_request.certificate_type,
            owner=owner,
            certificate_pem=issued.certificate_pem,
            private_key_pem=issued.private_key_pem,
            fingerprint_sha256=issued.fingerprint_sha256,
            not_before=issued.not_before,
            not_after=issued.not_after,
        )
        append_audit_entry(AUDIT_LOG, "issue_certificate", context["actor"], "success", {"serial": record.serial_number, "owner": owner, "type": cert_request.certificate_type})
        return Response(_record_payload(record, include_private_key=True), status=status.HTTP_201_CREATED)


class CertificateDetailView(APIView):
    def get(self, request, pk: int):
        _require_role(request, {"admin", "user"})
        record = get_object_or_404(CertificateRecord, pk=pk)
        _ensure_record_access(request, record)
        return Response(_record_payload(record, include_private_key=False))


class CertificateTrustView(APIView):
    def post(self, request):
        _require_role(request, {"admin", "user"})
        record = None
        if request.data.get("serial_number"):
            record = get_object_or_404(CertificateRecord, serial_number=str(request.data["serial_number"]))
            _ensure_record_access(request, record)
            certificate_pem = record.certificate_pem
        else:
            certificate_pem = request.data.get("certificate_pem")
        if not certificate_pem:
            return Response({"detail": "serial_number or certificate_pem is required."}, status=status.HTTP_400_BAD_REQUEST)

        ocsp_der = _ocsp_der_for_record(record) if record else None
        report = validate_certificate_trust(
            certificate_pem,
            purpose=request.data.get("purpose", "document_signing"),
            revocation_records=_revoked_certificates(),
            known_status=record.status if record else None,
            ocsp_der=ocsp_der,
        )
        append_audit_entry(
            AUDIT_LOG,
            "validate_certificate_trust",
            _actor(request),
            "success" if report["valid"] else "failed",
            {"serial": report["certificate"]["serial_number"], "purpose": report["purpose"]},
        )
        return Response(report)


class CertificateActionView(APIView):
    def post(self, request, pk: int, action: str):
        _require_role(request, {"admin"})
        record = get_object_or_404(CertificateRecord, pk=pk)
        if action == "revoke":
            record.status = "revoked"
            record.revoked_at = timezone.now()
            record.revocation_reason = request.data.get("reason", "key_compromise")
            record.save()
            append_audit_entry(AUDIT_LOG, "revoke_certificate", _actor(request), "success", {"serial": record.serial_number})
            return Response(_record_payload(record))
        if action == "suspend":
            record.status = "suspended"
            record.revoked_at = timezone.now()
            record.revocation_reason = "certificate_hold"
            record.save()
            append_audit_entry(AUDIT_LOG, "suspend_certificate", _actor(request), "success", {"serial": record.serial_number})
            return Response(_record_payload(record))
        if action == "renew":
            record.status = "renewed"
            record.save()
            renewed = issue_certificate(
                CertificateRequest(
                    common_name=record.common_name,
                    certificate_type=record.certificate_type,
                    sans=(record.common_name,),
                    validity_days=int(request.data.get("validity_days", 365)),
                )
            )
            new_record = CertificateRecord.objects.create(
                serial_number=str(renewed.serial_number),
                common_name=record.common_name,
                certificate_type=record.certificate_type,
                owner=record.owner,
                certificate_pem=renewed.certificate_pem,
                private_key_pem=renewed.private_key_pem,
                fingerprint_sha256=renewed.fingerprint_sha256,
                not_before=renewed.not_before,
                not_after=renewed.not_after,
            )
            append_audit_entry(AUDIT_LOG, "renew_certificate", _actor(request), "success", {"old_serial": record.serial_number, "new_serial": new_record.serial_number})
            return Response(_record_payload(new_record, include_private_key=True))
        return Response({"detail": "Unsupported action."}, status=status.HTTP_400_BAD_REQUEST)


class CrlView(APIView):
    encoding = "pem"

    def get(self, request):
        revoked = _revoked_certificates()
        manifest = publish_crl_if_needed(revoked)
        details = {"encoding": self.encoding, "crl_number": manifest["current_number"], "revoked_count": len(revoked)}
        if self.encoding == "der":
            append_audit_entry(AUDIT_LOG, "download_crl", _actor(request), "success", details)
            return HttpResponse(latest_crl_bytes(revoked, "der"), content_type="application/pkix-crl")
        append_audit_entry(AUDIT_LOG, "download_crl", _actor(request), "success", details)
        return HttpResponse(latest_crl_bytes(revoked, "pem"), content_type="application/x-pem-file")


class CrlManifestView(APIView):
    def get(self, request):
        manifest = publish_crl_if_needed(_revoked_certificates())
        append_audit_entry(
            AUDIT_LOG,
            "publish_crl_manifest",
            _actor(request),
            "success",
            {"crl_number": manifest["current_number"], "versions": len(manifest.get("versions", []))},
        )
        return Response(manifest)


class CrlVersionView(APIView):
    encoding = "pem"

    def get(self, request, number: int):
        publish_crl_if_needed(_revoked_certificates())
        try:
            content = versioned_crl_bytes(number, self.encoding)
        except FileNotFoundError:
            append_audit_entry(AUDIT_LOG, "download_crl_version", _actor(request), "failed", {"number": number, "encoding": self.encoding})
            return Response({"detail": "CRL version not found."}, status=status.HTTP_404_NOT_FOUND)
        content_type = "application/pkix-crl" if self.encoding == "der" else "application/x-pem-file"
        append_audit_entry(AUDIT_LOG, "download_crl_version", _actor(request), "success", {"number": number, "encoding": self.encoding})
        return HttpResponse(content, content_type=content_type)


class OcspStatusView(APIView):
    def post(self, request):
        serial = str(request.data["serial_number"])
        record = CertificateRecord.objects.filter(serial_number=serial).first()
        if record is None:
            append_audit_entry(AUDIT_LOG, "ocsp_status_query", _actor(request), "failed", {"serial": serial, "status": "unknown"})
            return Response({"status": "unknown"})
        ocsp_status = "revoked" if record.status in {"revoked", "suspended"} else "good"
        der = _ocsp_der_for_record(record)
        append_audit_entry(AUDIT_LOG, "ocsp_status_query", _actor(request), "success", {"serial": serial, "status": ocsp_status})
        return Response({"status": ocsp_status, "ocsp_der_base64": base64.b64encode(der).decode("ascii"), "details": inspect_ocsp_response(der)})


class StandardOcspView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        try:
            ocsp_request = ocsp_module.load_der_ocsp_request(request.body)
            record = CertificateRecord.objects.filter(serial_number=str(ocsp_request.serial_number)).first()
            state = None
            if record is not None:
                state = OcspCertificateState(
                    certificate_pem=record.certificate_pem,
                    status="revoked" if record.status in {"revoked", "suspended"} else "good",
                    revoked_at=record.revoked_at,
                    reason=record.revocation_reason or "key_compromise",
                )
            der = build_standard_ocsp_response(request.body, state)
            append_audit_entry(
                AUDIT_LOG,
                "ocsp_standard_response",
                _actor(request),
                "success",
                {"serial": str(ocsp_request.serial_number), "status": state.status if state else "unknown"},
            )
        except Exception:
            der = build_unsuccessful_ocsp_response(ocsp_module.OCSPResponseStatus.MALFORMED_REQUEST)
            append_audit_entry(AUDIT_LOG, "ocsp_standard_response", _actor(request), "failed", {"status": "malformed_request"})
        return HttpResponse(der, content_type="application/ocsp-response")


class PdfSignView(APIView):
    def post(self, request):
        _require_role(request, {"admin", "user"})
        record = get_object_or_404(CertificateRecord, serial_number=str(request.data["serial_number"]))
        _ensure_record_access(request, record)
        if record.status != "issued":
            append_audit_entry(AUDIT_LOG, "sign_pdf", _actor(request), "failed", {"serial": record.serial_number, "status": record.status})
            return Response({"detail": "Only issued certificates can sign documents."}, status=status.HTTP_400_BAD_REQUEST)
        pdf_bytes = base64.b64decode(request.data["pdf_base64"])
        envelope = sign_pdf_bytes(pdf_bytes, record.certificate_pem, record.private_key_pem, actor=_actor(request))
        append_audit_entry(AUDIT_LOG, "sign_pdf", _actor(request), "success", {"serial": record.serial_number})
        return Response(envelope)


class PdfVerifyView(APIView):
    def post(self, request):
        _require_role(request, {"admin", "user"})
        pdf_bytes = base64.b64decode(request.data["pdf_base64"])
        signature_envelope = request.data["signature_envelope"]
        signature_payload = json.loads(signature_envelope) if isinstance(signature_envelope, str) else signature_envelope
        result = verify_pdf_signature(pdf_bytes, signature_payload)
        record = CertificateRecord.objects.filter(serial_number=result["certificate_serial_number"]).first()
        trust_report = validate_certificate_trust(
            signature_payload["certificate_pem"],
            purpose="document_signing",
            revocation_records=_revoked_certificates(),
            known_status=record.status if record else None,
            ocsp_der=_ocsp_der_for_record(record) if record else None,
        )
        result["detached_signature_valid"] = result["valid"]
        result["valid_trust"] = trust_report["valid"]
        result["trust_report"] = trust_report
        result["valid"] = result["detached_signature_valid"] and trust_report["valid"]
        append_audit_entry(AUDIT_LOG, "verify_pdf_signature", _actor(request), "success" if result["valid"] else "failed", result)
        return Response(result)


class PdfEmbeddedSignView(APIView):
    def post(self, request):
        _require_role(request, {"admin", "user"})
        record = get_object_or_404(CertificateRecord, serial_number=str(request.data["serial_number"]))
        _ensure_record_access(request, record)
        if record.status != "issued":
            append_audit_entry(AUDIT_LOG, "sign_pdf_pades", _actor(request), "failed", {"serial": record.serial_number, "status": record.status})
            return Response({"detail": "Only issued certificates can sign documents."}, status=status.HTTP_400_BAD_REQUEST)
        pdf_bytes = base64.b64decode(request.data["pdf_base64"])
        try:
            signature = sign_pdf_pades_bytes(pdf_bytes, record.certificate_pem, record.private_key_pem)
        except PadesDependencyError as exc:
            append_audit_entry(AUDIT_LOG, "sign_pdf_pades", _actor(request), "failed", {"serial": record.serial_number, "error": str(exc)})
            return Response({"detail": str(exc)}, status=status.HTTP_501_NOT_IMPLEMENTED)
        append_audit_entry(AUDIT_LOG, "sign_pdf_pades", _actor(request), "success", {"serial": record.serial_number})
        return Response(pades_signature_response(signature))


class PdfEmbeddedVerifyView(APIView):
    def post(self, request):
        _require_role(request, {"admin", "user"})
        signed_pdf_bytes = base64.b64decode(request.data["signed_pdf_base64"])
        try:
            result = verify_pdf_pades_bytes(signed_pdf_bytes)
        except PadesDependencyError as exc:
            append_audit_entry(AUDIT_LOG, "verify_pdf_pades", _actor(request), "failed", {"error": str(exc)})
            return Response({"detail": str(exc)}, status=status.HTTP_501_NOT_IMPLEMENTED)
        append_audit_entry(AUDIT_LOG, "verify_pdf_pades", _actor(request), "success" if result["valid"] else "failed", result)
        return Response(result)


class AuditLogView(APIView):
    def get(self, request):
        _require_role(request, {"admin"})
        report = verify_audit_log_report(AUDIT_LOG)
        entries = read_audit_entries(AUDIT_LOG)
        return Response(
            {
                "valid_chain": report.valid_chain,
                "verification": {
                    "entry_count": report.entry_count,
                    "first_hash": report.first_hash,
                    "last_hash": report.last_hash,
                    "broken_at_index": report.broken_at_index,
                    "errors": report.errors,
                },
                "entries": entries[-100:],
            }
        )


class TlsDemoView(APIView):
    def get(self, request):
        _require_role(request, {"admin"})
        result = run_tls13_handshake_demo()
        append_audit_entry(AUDIT_LOG, "tls13_handshake_demo", _actor(request), "success", result)
        return Response(result)


def _record_payload(record: CertificateRecord, include_private_key: bool = False) -> dict[str, object]:
    payload = {
        "id": record.id,
        "serial_number": record.serial_number,
        "common_name": record.common_name,
        "certificate_type": record.certificate_type,
        "owner": record.owner,
        "status": record.status,
        "certificate_pem": record.certificate_pem,
        "fingerprint_sha256": record.fingerprint_sha256,
        "not_before": record.not_before,
        "not_after": record.not_after,
        "revoked_at": record.revoked_at,
        "revocation_reason": record.revocation_reason,
    }
    if include_private_key:
        payload["private_key_pem"] = record.private_key_pem
    return payload


def _revoked_certificates() -> list[dict[str, object]]:
    return [
        {
            "serial_number": item.serial_number,
            "status": item.status,
            "revoked_at": item.revoked_at,
            "reason": item.revocation_reason or "unspecified",
        }
        for item in CertificateRecord.objects.filter(status__in=["revoked", "suspended"]).order_by("serial_number")
    ]


def _ocsp_der_for_record(record: CertificateRecord) -> bytes:
    ocsp_status = "revoked" if record.status in {"revoked", "suspended"} else "good"
    return build_ocsp_response(record.certificate_pem, ocsp_status, record.revoked_at, record.revocation_reason or "key_compromise")


def _ensure_record_access(request, record: CertificateRecord) -> dict[str, str]:
    context = _require_role(request, {"admin", "user"})
    if context["role"] == "admin" or record.owner == context["actor"]:
        return context
    append_audit_entry(
        AUDIT_LOG,
        "certificate_access_denied",
        context["actor"],
        "failed",
        {"serial": record.serial_number, "owner": record.owner},
    )
    raise PermissionDenied("Certificate belongs to another actor.")


def _actor(request) -> str:
    context = _auth_context(request, required=False)
    if context:
        return context["actor"]
    if getattr(request, "user", None) and request.user.is_authenticated:
        return request.user.username
    return request.headers.get("X-Actor", "anonymous")


def _require_role(request, allowed_roles: set[str]) -> dict[str, str]:
    context = _auth_context(request, required=True)
    if context["role"] not in allowed_roles:
        raise PermissionDenied("Insufficient role for this operation.")
    return context


def _auth_context(request, required: bool) -> dict[str, str] | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        token = header.removeprefix("Bearer ").strip()
        try:
            payload = signing.loads(token, salt=AUTH_SALT, max_age=60 * 60 * 12)
        except signing.BadSignature as exc:
            raise AuthenticationFailed("Invalid or expired token.") from exc
        return {"actor": str(payload["actor"]), "role": str(payload["role"])}

    role = request.headers.get("X-Actor-Role")
    actor = request.headers.get("X-Actor")
    if actor and role:
        return {"actor": actor, "role": role}
    if required:
        raise AuthenticationFailed("Authentication token is required.")
    return None


def _demo_users() -> dict[str, dict[str, str]]:
    return {
        "admin": {"password": getattr(settings, "EDUPKI_ADMIN_PASSWORD", "admin123"), "role": "admin"},
        "user": {"password": getattr(settings, "EDUPKI_USER_PASSWORD", "user123"), "role": "user"},
    }
