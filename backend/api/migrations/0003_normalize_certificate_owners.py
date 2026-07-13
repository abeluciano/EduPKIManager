from django.db import migrations, models


OWNER_RENAMES = {
    "admin": "Universidad la Salle",
    "user": "Abel Aragon",
}


def normalize_owners(apps, schema_editor):
    certificate_record = apps.get_model("api", "CertificateRecord")
    for old_owner, new_owner in OWNER_RENAMES.items():
        certificate_record.objects.filter(owner=old_owner).update(owner=new_owner)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0002_certificaterecord_owner"),
    ]

    operations = [
        migrations.AlterField(
            model_name="certificaterecord",
            name="owner",
            field=models.CharField(db_index=True, default="Universidad la Salle", max_length=150),
        ),
        migrations.RunPython(normalize_owners, migrations.RunPython.noop),
    ]
