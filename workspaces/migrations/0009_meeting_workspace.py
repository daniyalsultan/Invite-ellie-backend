from django.db import migrations, models
import django.db.models.deletion


def populate_workspace_from_folder(apps, schema_editor):
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE workspaces_meeting m
            SET workspace_id = f.workspace_id
            FROM workspaces_folder f
            WHERE m.folder_id = f.id
              AND m.workspace_id IS NULL
        """)


class Migration(migrations.Migration):

    dependencies = [
        ('workspaces', '0008_alter_meeting_folder'),
    ]

    operations = [
        migrations.AddField(
            model_name='meeting',
            name='workspace',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='meetings',
                to='workspaces.workspace',
            ),
        ),
        migrations.RunPython(
            populate_workspace_from_folder,
            migrations.RunPython.noop,
        ),
    ]
