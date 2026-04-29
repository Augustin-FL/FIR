from django.db import migrations, connection


def copy_threatintel_to_yeti(apps, schema_editor):
    with connection.cursor() as cursor:
        existing_tables = connection.introspection.table_names()

        if "fir_threatintel_yetiprofile" in existing_tables:
            cursor.execute(
                "INSERT INTO fir_yeti_yetiprofile SELECT * FROM fir_threatintel_yetiprofile;"
            )
            cursor.execute("DROP TABLE fir_threatintel_yetiprofile;")


class Migration(migrations.Migration):

    dependencies = [
        ("fir_yeti", "0002_auto_20161128_1014"),
    ]

    operations = [
        migrations.RunPython(copy_threatintel_to_yeti),
    ]
