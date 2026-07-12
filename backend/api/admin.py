from django.contrib import admin

from .models import CertificateRecord


@admin.register(CertificateRecord)
class CertificateRecordAdmin(admin.ModelAdmin):
    list_display = ("common_name", "certificate_type", "status", "serial_number", "not_after")
    search_fields = ("common_name", "serial_number", "fingerprint_sha256")
    list_filter = ("certificate_type", "status")

