from django.urls import path

from . import views


urlpatterns = [
    path("health/", views.HealthView.as_view(), name="health"),
    path("readiness/", views.ReadinessView.as_view(), name="readiness"),
    path("auth/login/", views.AuthLoginView.as_view(), name="auth-login"),
    path("ca/root/", views.RootCaView.as_view(), name="root-ca"),
    path("ca/root.pem", views.RootCaPemView.as_view(), name="root-ca-pem"),
    path("ca/chain.pem", views.CaChainPemView.as_view(), name="ca-chain-pem"),
    path("certificates/", views.CertificateListCreateView.as_view(), name="certificates"),
    path("certificates/validate/", views.CertificateTrustView.as_view(), name="certificate-trust"),
    path("certificates/<int:pk>/", views.CertificateDetailView.as_view(), name="certificate-detail"),
    path("certificates/<int:pk>/<str:action>/", views.CertificateActionView.as_view(), name="certificate-action"),
    path("crl.pem", views.CrlView.as_view(encoding="pem"), name="crl-pem"),
    path("crl.der", views.CrlView.as_view(encoding="der"), name="crl-der"),
    path("crl/manifest/", views.CrlManifestView.as_view(), name="crl-manifest"),
    path("crl/<int:number>.pem", views.CrlVersionView.as_view(encoding="pem"), name="crl-version-pem"),
    path("crl/<int:number>.der", views.CrlVersionView.as_view(encoding="der"), name="crl-version-der"),
    path("ocsp/", views.StandardOcspView.as_view(), name="standard-ocsp"),
    path("ocsp/status/", views.OcspStatusView.as_view(), name="ocsp-status"),
    path("pdf/sign/", views.PdfSignView.as_view(), name="pdf-sign"),
    path("pdf/verify/", views.PdfVerifyView.as_view(), name="pdf-verify"),
    path("pdf/sign-embedded/", views.PdfEmbeddedSignView.as_view(), name="pdf-sign-embedded"),
    path("pdf/verify-embedded/", views.PdfEmbeddedVerifyView.as_view(), name="pdf-verify-embedded"),
    path("tls/demo/", views.TlsDemoView.as_view(), name="tls-demo"),
    path("audit/", views.AuditLogView.as_view(), name="audit-log"),
]
