from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificaterecord",
            name="owner",
            field=models.CharField(db_index=True, default="admin", max_length=150),
        ),
    ]
