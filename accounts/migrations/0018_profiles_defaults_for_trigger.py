"""Give profile columns database defaults, because a trigger writes this table.

Supabase creates the auth user, then `sync_user_to_profile` (a trigger on
auth.users) copies it into profiles. That trigger names a fixed list of
columns, so any column added later has to work without being named — the
insert fails otherwise, Supabase rolls the whole signup back, and the person
sees "Database error saving new user".

That is what happened with auto_join_meetings, added 2026-08-25: Django
applies a field default when Django writes the row and drops the database
default afterwards, so the trigger's insert hit a NOT NULL violation. Every
signup failed, by email and by SSO, for a month, and nothing alerted — the
last profile created was 2026-08-16.

Any future NOT NULL column on this table needs a database default too. See
accounts/tests.py::ProfileTriggerInsertTests, which fails if one doesn't.
"""

from django.db import migrations

COLUMNS = {
    'auto_join_meetings': 'true',
}


def add_defaults(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        for column, default in COLUMNS.items():
            cursor.execute(f'ALTER TABLE public.profiles ALTER COLUMN {column} SET DEFAULT {default}')


def drop_defaults(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        for column in COLUMNS:
            cursor.execute(f'ALTER TABLE public.profiles ALTER COLUMN {column} DROP DEFAULT')


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0017_add_auto_join_meetings'),
    ]

    operations = [
        migrations.RunPython(add_defaults, drop_defaults),
    ]
