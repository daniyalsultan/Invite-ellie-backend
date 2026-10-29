"""Recordings are kept for the life of the workspace again.

0019 gave this column a 30-day default. That was decided mid-build and
contradicts the signed scope of work, which specifies retention for the
life of the workspace, so this is a compliance revert rather than a
product change.

Three things happen here, and each matters on its own:

* The column becomes nullable, with NULL meaning "no expiry".
* The *database* default is dropped. The Supabase trigger that writes this
  table names a fixed column list and never names this one, so without
  dropping the default every new signup would silently come back with 30
  days (see 0018, 0019 and ProfileTriggerInsertTests).
* Existing rows still holding exactly 30 are set to NULL. Measured on
  2026-10-29, all 114 profiles held 30 and not one differed, so no row
  carries a value a person chose. Any row that does differ is left alone:
  an explicit choice is not something a revert gets to overwrite.

The per-workspace override is untouched. No workspace had set one (0 of
89 on the same date), and any that had would still win over the profile.
"""

from django.db import migrations, models

OLD_DEFAULT = 30


def clear_unchosen_defaults(apps, schema_editor):
    Profile = apps.get_model('accounts', 'Profile')
    Profile.objects.filter(recording_retention_days=OLD_DEFAULT).update(
        recording_retention_days=None)


def restore_defaults(apps, schema_editor):
    Profile = apps.get_model('accounts', 'Profile')
    Profile.objects.filter(recording_retention_days__isnull=True).update(
        recording_retention_days=OLD_DEFAULT)


def drop_db_default(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE public.profiles '
                       'ALTER COLUMN recording_retention_days DROP DEFAULT')


def add_db_default(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('ALTER TABLE public.profiles '
                       'ALTER COLUMN recording_retention_days SET DEFAULT 30')


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0019_profile_recording_retention_days'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='recording_retention_days',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        # Order matters: the default is dropped before the rows are
        # cleared. The other way round leaves a window in which a signup
        # landing between the UPDATE and the DROP still gets 30 and is
        # never cleared.
        migrations.RunPython(drop_db_default, add_db_default),
        migrations.RunPython(clear_unchosen_defaults, restore_defaults),
    ]
