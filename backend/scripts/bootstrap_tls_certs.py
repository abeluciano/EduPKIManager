from __future__ import annotations

import os
from pathlib import Path

from audit.service import append_audit_entry, default_audit_log_path
from tls.service import DEFAULT_TLS_HOSTNAME, DEFAULT_TLS_SANS, ensure_tls_server_bundle


def main() -> None:
    hostname = os.getenv("EDUPKI_TLS_HOSTNAME", DEFAULT_TLS_HOSTNAME)
    sans = tuple(
        item.strip()
        for item in os.getenv("EDUPKI_TLS_SANS", ",".join(DEFAULT_TLS_SANS)).split(",")
        if item.strip()
    )
    output_dir = Path(os.getenv("EDUPKI_TLS_CERT_DIR", "/app/tls"))
    bundle = ensure_tls_server_bundle(hostname, output_dir, sans)
    append_audit_entry(
        default_audit_log_path(),
        "bootstrap_tls_certificate",
        "tls_init",
        "success",
        {"hostname": hostname, "sans": list(sans), "certificate": str(bundle["certificate"])},
    )
    print("TLS certificate bundle ready:")
    print(f"  hostname: {hostname}")
    print(f"  certificate: {bundle['certificate']}")
    print(f"  private_key: {bundle['private_key']}")
    print(f"  ca_certificate: {bundle['ca_certificate']}")


if __name__ == "__main__":
    main()
