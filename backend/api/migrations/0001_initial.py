from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="CertificateRecord",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("serial_number", models.CharField(max_length=80, unique=True)),
                ("common_name", models.CharField(max_length=255)),
                ("certificate_type", models.CharField(choices=[("user", "User"), ("server", "Server"), ("device", "Device")], max_length=16)),
                ("status", models.CharField(choices=[("issued", "Issued"), ("suspended", "Suspended"), ("revoked", "Revoked"), ("renewed", "Renewed")], default="issued", max_length=16)),
                ("certificate_pem", models.TextField()),
                ("private_key_pem", models.TextField(blank=True)),
                ("fingerprint_sha256", models.CharField(max_length=64)),
                ("not_before", models.DateTimeField()),
                ("not_after", models.DateTimeField()),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revocation_reason", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]

