"""Avatar URL on /api/accounts/me/: never held hostage by storage latency.

Storage is mocked; nothing leaves the machine. Run against a throwaway
Postgres with an in-memory cache.
"""

from unittest import mock

from django.core.cache import cache
from django.test import TestCase

from accounts import serializers as account_serializers
from accounts.models import Profile

STORAGE = 'accounts.serializers.default_storage'


class AvatarUrlTests(TestCase):
    def setUp(self):
        cache.clear()
        self.profile = Profile.objects.create(email='a@example.com', avatar_url='https://sso.example/pic.png')
        self.profile.avatar.name = 'avatars/a.webp'

    def url(self):
        return account_serializers.ProfileSerializer().get_avatar_url(self.profile)

    def test_uploaded_avatar_is_signed_when_it_exists(self):
        with mock.patch(STORAGE) as storage:
            storage.exists.return_value = True
            storage.signed_url.return_value = 'https://signed/avatar'
            self.assertEqual(self.url(), 'https://signed/avatar')

    def test_existence_is_remembered_so_storage_is_not_asked_every_time(self):
        with mock.patch(STORAGE) as storage:
            storage.exists.return_value = True
            storage.signed_url.return_value = 'https://signed/avatar'
            self.url(); self.url(); self.url()
            self.assertEqual(storage.exists.call_count, 1)

    def test_missing_file_falls_back_to_the_sso_picture(self):
        with mock.patch(STORAGE) as storage:
            storage.exists.return_value = False
            self.assertEqual(self.url(), 'https://sso.example/pic.png')

    def test_storage_failure_falls_back_instead_of_failing_the_request(self):
        with mock.patch(STORAGE) as storage:
            storage.exists.side_effect = TimeoutError('storage slow')
            self.assertEqual(self.url(), 'https://sso.example/pic.png')
            self.url()
            self.assertEqual(storage.exists.call_count, 1)  # failure remembered briefly

    def test_no_uploaded_avatar_never_touches_storage(self):
        self.profile.avatar.name = ''
        with mock.patch(STORAGE) as storage:
            self.assertEqual(self.url(), 'https://sso.example/pic.png')
            storage.exists.assert_not_called()


class ProfileTriggerInsertTests(TestCase):
    """A database trigger writes this table, and it names a fixed column list.

    Supabase's `sync_user_to_profile` copies a new auth user into profiles. It
    was written once and lists its columns explicitly, so a column added later
    has to work without being named: NOT NULL with no database default makes
    every signup fail, and Supabase reports only "Database error saving new
    user".

    That happened for a month (auto_join_meetings, 2026-08-25 to 2026-09-24).
    This test fails instead, by inserting the way the trigger does.
    """

    # What sync_user_to_profile actually sets, as of 2026-09-24.
    TRIGGER_COLUMNS = {
        'id', 'email', 'first_name', 'last_name', 'avatar_url', 'company', 'company_notes',
        'position', 'audience', 'purpose', 'sso_provider', 'is_active', 'confirmed_at',
        'created_at', 'updated_at', 'first_login', 'show_tour', 'deletion_requested_at',
        'deletion_requested_by_ip', 'deletion_type', 'data_exported', 'data_export_completed_at',
        'deleted_at', 'deletion_completed_at', 'deletion_verified_at', 'legal_hold',
        'legal_hold_reason', 'legal_hold_reason_user_facing', 'legal_hold_case_number',
        'legal_hold_placed_at', 'legal_hold_placed_by_id', 'legal_hold_approved_by_id',
        'retention_basis', 'legal_hold_review_date', 'deletion_verification_token',
        'deletion_verification_sent_at', 'deletion_verification_confirmed_at',
        'excluded_from_backups', 'backup_exclusion_verified_at', 'user_country',
        'is_eu_resident', 'privacy_regulation', 'subscription_auto_renew',
        'subscription_status', 'subscription_plan',
    }

    def columns(self):
        from django.db import connection
        table = Profile._meta.db_table
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_name = %s AND table_schema = current_schema()
            """, [table])
            return cursor.fetchall()

    def test_a_signup_insert_naming_only_the_triggers_columns_succeeds(self):
        import uuid
        from datetime import datetime, timezone as dt_timezone
        from django.db import connection, transaction

        def value(name, data_type, nullable):
            if name == 'id':
                return str(uuid.uuid4())
            if name == 'email':
                return 'trigger-probe@example.invalid'
            if nullable == 'YES':
                return None  # the trigger passes NULL for most of these
            if 'timestamp' in data_type:
                return datetime.now(dt_timezone.utc)
            if data_type == 'boolean':
                return False
            return ''

        present = [(n, t, nullable) for n, t, nullable, _ in self.columns() if n in self.TRIGGER_COLUMNS]
        names = ', '.join(n for n, _, _ in present)
        placeholders = ', '.join(['%s'] * len(present))
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(
                    f'INSERT INTO {Profile._meta.db_table} ({names}) VALUES ({placeholders})',
                    [value(n, t, nullable) for n, t, nullable in present],
                )
            transaction.set_rollback(True)

    def test_every_column_the_trigger_does_not_set_can_look_after_itself(self):
        unnamed = [
            (name, is_nullable, default) for name, _, is_nullable, default in self.columns()
            if name not in self.TRIGGER_COLUMNS
        ]
        stranded = [name for name, is_nullable, default in unnamed if is_nullable == 'NO' and default is None]
        self.assertEqual(stranded, [], msg=(
            'These columns are NOT NULL with no database default and are not set by '
            "Supabase's sync_user_to_profile trigger, so every signup will fail: "
            f'{stranded}. Give each a database default (see migration 0018).'
        ))
