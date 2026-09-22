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
