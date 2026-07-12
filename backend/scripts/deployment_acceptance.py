from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

import requests

from verify_https_tls import verify_https_tls


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deployment acceptance checks for EduPKIManager.")
    parser.add_argument("--api-base-url", default="http://127.0.0.1:8000/api")
    parser.add_argument("--frontend-url", default="http://localhost:3000")
    parser.add_argument("--https-connect-host", default="127.0.0.1")
    parser.add_argument("--https-port", type=int, default=443)
    parser.add_argument("--https-server-name", default="edupkimanager.com")
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-password", default=os.getenv("EDUPKI_ADMIN_PASSWORD", "admin123"))
    args = parser.parse_args()

    api_base = args.api_base_url.rstrip("/")
    frontend = args.frontend_url.rstrip("/")

    readiness = requests.get(f"{api_base}/readiness/", timeout=10)
    readiness.raise_for_status()
    readiness_data = readiness.json()
    assert readiness_data["status"] == "ready", readiness_data

    frontend_health = requests.get(f"{frontend}/healthz", timeout=10)
    frontend_health.raise_for_status()
    assert frontend_health.text.strip() == "ok"

    session = requests.post(
        f"{api_base}/auth/login/",
        json={"username": args.admin_user, "password": args.admin_password},
        timeout=10,
    )
    session.raise_for_status()
    token = session.json()["token"]

    audit = requests.get(
        f"{api_base}/audit/",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    audit.raise_for_status()
    audit_data = audit.json()
    assert audit_data["valid_chain"] is True, audit_data["verification"]

    with tempfile.TemporaryDirectory() as tmp:
        root_ca = requests.get(f"{api_base}/ca/root.pem", timeout=10)
        root_ca.raise_for_status()
        ca_file = Path(tmp) / "edupki-root-ca.pem"
        ca_file.write_text(root_ca.text, encoding="ascii")
        tls = verify_https_tls(args.https_connect_host, args.https_port, args.https_server_name, ca_file)
        assert tls["tls_version"] == "TLSv1.3", tls
        assert " 200 " in tls["status_line"], tls

    print("Deployment acceptance completed.")
    print(f"Readiness: {readiness_data['status']}")
    print(f"Audit entries: {audit_data['verification']['entry_count']}")
    print(f"TLS: {tls['tls_version']} / {tls['cipher']} / {tls['status_line']}")


if __name__ == "__main__":
    main()
