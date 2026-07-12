from __future__ import annotations

import argparse
import socket
import ssl
from pathlib import Path


def verify_https_tls(
    connect_host: str,
    port: int,
    server_name: str,
    ca_file: Path,
) -> dict[str, str]:
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection((connect_host, port), timeout=8) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=server_name) as tls_socket:
            request = f"GET /api/health/ HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n"
            tls_socket.sendall(request.encode("ascii"))
            response = tls_socket.recv(4096).decode("iso-8859-1", errors="replace")
            status_line = response.splitlines()[0] if response else ""
            return {
                "server_name": server_name,
                "connect_host": connect_host,
                "port": str(port),
                "tls_version": tls_socket.version() or "unknown",
                "cipher": tls_socket.cipher()[0],
                "status_line": status_line,
            }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify EduPKIManager HTTPS TLS 1.3 endpoint.")
    parser.add_argument("--connect-host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--server-name", default="edupkimanager.com")
    parser.add_argument("--ca-file", type=Path, default=Path("backend/data/tls/root_ca_cert.pem"))
    args = parser.parse_args()

    result = verify_https_tls(args.connect_host, args.port, args.server_name, args.ca_file)
    print("TLS version:", result["tls_version"])
    print("Cipher:", result["cipher"])
    print("HTTP:", result["status_line"])
    if result["tls_version"] != "TLSv1.3" or " 200 " not in result["status_line"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
