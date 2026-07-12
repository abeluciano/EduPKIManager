from __future__ import annotations

import os
import time
from pathlib import Path

import django


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "edupki.settings")
django.setup()

from api.models import CertificateRecord  # noqa: E402
from audit.service import append_audit_entry, default_audit_log_path  # noqa: E402
from crl.publication import publish_crl_if_needed  # noqa: E402


def refresh_once() -> dict[str, int | str]:
    revoked = [
        {
            "serial_number": item.serial_number,
            "revoked_at": item.revoked_at,
            "reason": item.revocation_reason or "unspecified",
        }
        for item in CertificateRecord.objects.filter(status__in=["revoked", "suspended"])
    ]
    output_dir = Path(os.getenv("EDUPKI_CRL_DIR", "data/crl"))
    manifest = publish_crl_if_needed(revoked, output_dir)
    result = {"revoked_count": len(revoked), "current_number": int(manifest["current_number"]), "output_dir": str(output_dir)}
    append_audit_entry(default_audit_log_path(), "scheduled_crl_refresh", "crl_scheduler", "success", result)
    return result


def main() -> None:
    interval_seconds = int(os.getenv("CRL_REFRESH_SECONDS", "300"))
    while True:
        try:
            result = refresh_once()
            print(f"CRL refreshed: {result}", flush=True)
        except Exception as exc:
            append_audit_entry(default_audit_log_path(), "scheduled_crl_refresh", "crl_scheduler", "failed", {"error": str(exc)})
            print(f"CRL refresh pending: {exc}", flush=True)
        time.sleep(interval_seconds)


if __name__ == "__main__":
    main()
