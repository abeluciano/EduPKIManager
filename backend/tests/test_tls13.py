from __future__ import annotations

import tempfile
import unittest

from ca.service import set_storage_dir, storage_dir
from scripts.tls13_demo import run_tls13_handshake_demo


class Tls13DemoTests(unittest.TestCase):
    def test_tls13_handshake(self) -> None:
        previous_storage_dir = storage_dir()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                set_storage_dir(tmp)
                original_storage_dir = storage_dir()
                result = run_tls13_handshake_demo()
                self.assertEqual(result["hostname"], "edupkimanager.com")
                self.assertEqual(result["client_tls_version"], "TLSv1.3")
                self.assertEqual(result["server_tls_version"], "TLSv1.3")
                self.assertEqual(result["server_reply"], "ok")
                self.assertEqual(storage_dir(), original_storage_dir)
            finally:
                set_storage_dir(previous_storage_dir)


if __name__ == "__main__":
    unittest.main()
