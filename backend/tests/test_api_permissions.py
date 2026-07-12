from __future__ import annotations

import os
import tempfile
import unittest
import importlib.util

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "edupki.settings")

if importlib.util.find_spec("django") is None:
    class ApiPermissionTests(unittest.TestCase):
        @unittest.skip("Django is not installed in this runtime")
        def test_django_runtime_unavailable(self) -> None:
            pass
else:
    import django

    django.setup()

    from django.test import TestCase
    from rest_framework.test import APIClient

    from ca.service import set_storage_dir  # noqa: E402


    class ApiPermissionTests(TestCase):
        def setUp(self) -> None:
            self.tmp = tempfile.TemporaryDirectory()
            set_storage_dir(self.tmp.name)
            self.client = APIClient()
            self.admin_token = self._login("admin", "admin123")
            self.user_token = self._login("user", "user123")

        def tearDown(self) -> None:
            self.tmp.cleanup()

        def test_user_can_only_see_and_use_owned_certificates(self) -> None:
            admin_cert = self.client.post(
                "/api/certificates/",
                {
                    "common_name": "portal.edu.local",
                    "certificate_type": "server",
                    "owner": "admin",
                    "sans": ["portal.edu.local"],
                    "validity_days": 365,
                },
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {self.admin_token}",
            )
            self.assertEqual(admin_cert.status_code, 201)

            forbidden_issue = self.client.post(
                "/api/certificates/",
                {
                    "common_name": "server-by-user.edu.local",
                    "certificate_type": "server",
                    "sans": ["server-by-user.edu.local"],
                    "validity_days": 365,
                },
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {self.user_token}",
            )
            self.assertEqual(forbidden_issue.status_code, 403)

            user_cert = self.client.post(
                "/api/certificates/",
                {
                    "common_name": "student.edu.local",
                    "certificate_type": "user",
                    "sans": ["student.edu.local"],
                    "validity_days": 365,
                },
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {self.user_token}",
            )
            self.assertEqual(user_cert.status_code, 201)
            self.assertEqual(user_cert.json()["owner"], "user")

            user_list = self.client.get("/api/certificates/", HTTP_AUTHORIZATION=f"Bearer {self.user_token}")
            self.assertEqual(user_list.status_code, 200)
            self.assertEqual([item["owner"] for item in user_list.json()], ["user"])

            foreign_detail = self.client.get(
                f"/api/certificates/{admin_cert.json()['id']}/",
                HTTP_AUTHORIZATION=f"Bearer {self.user_token}",
            )
            self.assertEqual(foreign_detail.status_code, 403)

            foreign_sign = self.client.post(
                "/api/pdf/sign/",
                {"serial_number": admin_cert.json()["serial_number"], "pdf_base64": "JVBERi0xLjQK"},
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {self.user_token}",
            )
            self.assertEqual(foreign_sign.status_code, 403)

        def _login(self, username: str, password: str) -> str:
            response = self.client.post(
                "/api/auth/login/",
                {"username": username, "password": password},
                format="json",
            )
            self.assertEqual(response.status_code, 200)
            return str(response.json()["token"])
