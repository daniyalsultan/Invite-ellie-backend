"""How long a meeting's recording is kept, per customer.

The published privacy policy already promises business customers a
configurable retention period defaulting to 30 days. Nothing implemented it,
so the promise had no mechanism behind it. This is the column that setting
lives in.

The database default is not optional. A Supabase trigger writes this table
and names a fixed column list, so a NOT NULL column it does not name fails
every signup — which is exactly what happened with auto_join_meetings, for a
month, silently (see 0018 and ProfileTriggerInsertTests).
"""

from django.db import migrations, models


def add_default(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE public.profiles '
                       'ALTER COLUMN recording_retention_days SET DEFAULT 30')


def drop_default(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE public.profiles '
                       'ALTER COLUMN recording_retention_days DROP DEFAULT')


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0018_profiles_defaults_for_trigger'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='recording_retention_days',
            field=models.PositiveIntegerField(default=30),
        ),
        migrations.RunPython(add_default, drop_default),
    ]
