from __future__ import annotations

import socket
import ssl
import tempfile
import threading
from pathlib import Path

from ca.service import set_storage_dir, storage_dir
from tls.service import DEFAULT_TLS_HOSTNAME, DEFAULT_TLS_SANS, issue_tls_server_bundle, tls13_context


def run_tls13_handshake_demo(hostname: str = DEFAULT_TLS_HOSTNAME) -> dict[str, str]:
    original_storage_dir = storage_dir()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            workspace = Path(tmp)
            set_storage_dir(workspace / "ca")
            bundle = issue_tls_server_bundle(hostname, workspace / "tls", DEFAULT_TLS_SANS)
            server_context = tls13_context(bundle["certificate"], bundle["private_key"])
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(("127.0.0.1", 0))
            server_socket.listen(1)
            port = server_socket.getsockname()[1]
            result: dict[str, str] = {}

            def serve_once() -> None:
                connection, _ = server_socket.accept()
                with server_context.wrap_socket(connection, server_side=True) as tls_connection:
                    result["server_tls_version"] = tls_connection.version() or "unknown"
                    tls_connection.recv(1)
                    tls_connection.sendall(b"ok")
                server_socket.close()

            thread = threading.Thread(target=serve_once, daemon=True)
            thread.start()

            client_context = ssl.create_default_context(cafile=bundle["ca_certificate"])
            client_context.minimum_version = ssl.TLSVersion.TLSv1_3
            client_context.maximum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client_socket:
                with client_context.wrap_socket(client_socket, server_hostname=hostname) as tls_client:
                    result["hostname"] = hostname
                    result["client_tls_version"] = tls_client.version() or "unknown"
                    tls_client.sendall(b"x")
                    result["server_reply"] = tls_client.recv(2).decode("ascii")

            thread.join(timeout=5)
            return result
        finally:
            set_storage_dir(original_storage_dir)


def main() -> None:
    result = run_tls13_handshake_demo()
    print("TLS client:", result["client_tls_version"])
    print("TLS server:", result["server_tls_version"])
    print("Reply:", result["server_reply"])


if __name__ == "__main__":
    main()
