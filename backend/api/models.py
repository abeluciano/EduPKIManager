from django.db import models


class CertificateRecord(models.Model):
    TYPE_CHOICES = [("user", "User"), ("server", "Server"), ("device", "Device")]
    STATUS_CHOICES = [
        ("issued", "Issued"),
        ("suspended", "Suspended"),
        ("revoked", "Revoked"),
        ("renewed", "Renewed"),
    ]

    serial_number = models.CharField(max_length=80, unique=True)
    common_name = models.CharField(max_length=255)
    certificate_type = models.CharField(max_length=16, choices=TYPE_CHOICES)
    owner = models.CharField(max_length=150, default="admin", db_index=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="issued")
    certificate_pem = models.TextField()
    private_key_pem = models.TextField(blank=True)
    fingerprint_sha256 = models.CharField(max_length=64)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.common_name} ({self.serial_number})"
