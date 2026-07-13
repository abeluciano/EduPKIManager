from __future__ import annotations

import base64
import os
import tempfile
import unittest
import importlib.util
from unittest.mock import patch

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
    from pdf_sign.pades import PadesPdfError  # noqa: E402


    class ApiPermissionTests(TestCase):
        def setUp(self) -> None:
            self.tmp = tempfile.TemporaryDirectory()
            set_storage_dir(self.tmp.name)
            self.client = APIClient()
            self.admin_token = self._login("admin", "admin123")
            self.user_owner = "Abel Aragon"
            self.user_token = self._login("abel.aragon", "abel123")

        def tearDown(self) -> None:
            self.tmp.cleanup()

        def test_user_can_only_see_and_use_owned_certificates(self) -> None:
            admin_cert = self.client.post(
                "/api/certificates/",
                {
                    "common_name": "portal.edu.local",
                    "certificate_type": "server",
                    "owner": "Universidad la Salle",
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
                    "common_name": "student-by-user.edu.local",
                    "certificate_type": "user",
                    "sans": ["student-by-user.edu.local"],
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
                    "owner": self.user_owner,
                    "sans": ["student.edu.local"],
                    "validity_days": 365,
                },
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {self.admin_token}",
            )
            self.assertEqual(user_cert.status_code, 201)
            self.assertEqual(user_cert.json()["owner"], self.user_owner)

            user_list = self.client.get("/api/certificates/", HTTP_AUTHORIZATION=f"Bearer {self.user_token}")
            self.assertEqual(user_list.status_code, 200)
            user_items = user_list.json()
            self.assertTrue(user_items)
            self.assertTrue(all(item["owner"] == self.user_owner for item in user_items))
            self.assertIn(user_cert.json()["serial_number"], [item["serial_number"] for item in user_items])

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

        def test_pdf_payload_errors_are_short_and_structured(self) -> None:
            certificate = self._issue_user_certificate()
            headers = {"HTTP_AUTHORIZATION": f"Bearer {self.user_token}"}

            invalid = self.client.post(
                "/api/pdf/sign/",
                {"serial_number": certificate["serial_number"], "pdf_base64": base64.b64encode(b"not a pdf").decode("ascii")},
                format="json",
                **headers,
            )
            self.assertEqual(invalid.status_code, 400)
            self.assertEqual(invalid.json()["code"], "invalid_pdf")

            with patch("api.views.MAX_PDF_BYTES", 8):
                too_large = self.client.post(
                    "/api/pdf/sign/",
                    {"serial_number": certificate["serial_number"], "pdf_base64": base64.b64encode(b"%PDF-1234").decode("ascii")},
                    format="json",
                    **headers,
                )
            self.assertEqual(too_large.status_code, 413)
            self.assertEqual(too_large.json()["code"], "pdf_too_large")
            self.assertLess(len(too_large.json()["detail"]), 100)

        def test_hybrid_pdf_error_is_safe_for_the_frontend(self) -> None:
            certificate = self._issue_user_certificate()
            error = PadesPdfError(
                "pdf_hybrid_xref",
                "Este PDF usa una estructura interna no compatible con la firma PAdES.",
            )
            with patch("api.views.sign_pdf_pades_bytes", side_effect=error):
                response = self.client.post(
                    "/api/pdf/sign-embedded/",
                    {
                        "serial_number": certificate["serial_number"],
                        "pdf_base64": base64.b64encode(b"%PDF-1.7\n").decode("ascii"),
                    },
                    format="json",
                    HTTP_AUTHORIZATION=f"Bearer {self.user_token}",
                )
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json()["code"], "pdf_hybrid_xref")
            self.assertNotIn("SigningError", response.content.decode("utf-8"))

        def _issue_user_certificate(self) -> dict[str, object]:
            response = self.client.post(
                "/api/certificates/",
                {
                    "common_name": "signer.edu.local",
                    "certificate_type": "user",
                    "owner": self.user_owner,
                    "sans": ["signer.edu.local"],
                    "validity_days": 365,
                },
                format="json",
                HTTP_AUTHORIZATION=f"Bearer {self.admin_token}",
            )
            self.assertEqual(response.status_code, 201)
            return response.json()

        def _login(self, username: str, password: str) -> str:
            response = self.client.post(
                "/api/auth/login/",
                {"username": username, "password": password},
                format="json",
            )
            self.assertEqual(response.status_code, 200)
            return str(response.json()["token"])
