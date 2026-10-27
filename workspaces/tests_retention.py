"""Who may set a workspace's retention period, and whose period applies.

Two failures this guards against, both silent: any member being able to
shorten retention and start deleting other people's recordings, and the
internal endpoint reporting the profile's period when the workspace has set
its own, which would quietly keep recordings past what a customer was told.
"""

from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings

from accounts.models import Profile
from workspaces.models import Workspace, WorkspaceMembership
from workspaces.serializers import WorkspaceSerializer


def _profile(email):
    return Profile.objects.create(email=email, first_name='T', last_name='U')


class RetentionPermissionTests(TestCase):
    def setUp(self):
        self.owner = _profile('owner@example.com')
        self.member = _profile('member@example.com')
        self.ws = Workspace.objects.create(owner=self.owner, name='Acme')
        for profile, role in ((self.owner, WorkspaceMembership.ROLE_OWNER),
                              (self.member, WorkspaceMembership.ROLE_MEMBER)):
            WorkspaceMembership.objects.create(
                workspace=self.ws, profile=profile, role=role,
                status=WorkspaceMembership.STATUS_ACTIVE)

    def _serializer(self, profile, value):
        request = RequestFactory().patch('/')
        request.profile = profile
        return WorkspaceSerializer(self.ws, data={'recording_retention_days': value},
                                   partial=True, context={'request': request})

    def test_an_owner_may_set_it(self):
        s = self._serializer(self.owner, 7)
        self.assertTrue(s.is_valid(), s.errors)
        s.save()
        self.ws.refresh_from_db()
        self.assertEqual(self.ws.recording_retention_days, 7)

    def test_a_member_may_not(self):
        s = self._serializer(self.member, 7)
        self.assertFalse(s.is_valid())
        self.assertIn('recording_retention_days', s.errors)

    def test_an_owner_may_unset_it_to_fall_back_to_the_profile(self):
        self.ws.recording_retention_days = 7
        self.ws.save()
        s = self._serializer(self.owner, None)
        self.assertTrue(s.is_valid(), s.errors)
        s.save()
        self.ws.refresh_from_db()
        self.assertIsNone(self.ws.recording_retention_days)

    def test_nonsense_periods_are_refused(self):
        for bad in (0, 4000):
            self.assertFalse(self._serializer(self.owner, bad).is_valid(), f'{bad} was accepted')

    def test_a_default_workspace_overrides_nothing(self):
        self.assertIsNone(Workspace.objects.create(owner=self.owner, name='B')
                          .recording_retention_days)


@override_settings(INTERNAL_API_KEY='test-internal-key')
class InternalUserInfoRetentionTests(TestCase):
    """The endpoint recall-server reads to decide what to delete."""

    def setUp(self):
        # DRF throttle counters live in the cache and outlive a test, so the
        # second request in a run gets a 429 and the assertion reads as a
        # broken endpoint rather than a dirty fixture.
        cache.clear()
        self.profile = _profile('u@example.com')
        self.profile.recording_retention_days = 30
        self.profile.save()
        self.ws = Workspace.objects.create(owner=self.profile, name='Acme')
        WorkspaceMembership.objects.create(
            workspace=self.ws, profile=self.profile,
            role=WorkspaceMembership.ROLE_OWNER,
            status=WorkspaceMembership.STATUS_ACTIVE)

    def _get(self, params=''):
        # override_settings rather than patching settings directly: the key is
        # read at request time, and a patch that leaks between tests made this
        # pass alone and fail in the suite.
        response = self.client.get(
            f'/api/accounts/internal/user-info/{self.profile.id}/{params}',
            HTTP_X_INTERNAL_API_KEY='test-internal-key')
        self.assertEqual(response.status_code, 200, response.content[:200])
        return response

    def test_without_a_workspace_the_profile_period_is_reported(self):
        body = self._get().json()
        self.assertEqual(body['recording_retention_days'], 30)
        self.assertEqual(body['retention_source'], 'profile')

    def test_a_workspace_that_sets_a_period_wins(self):
        self.ws.recording_retention_days = 7
        self.ws.save()
        body = self._get(f'?workspace_id={self.ws.id}').json()
        self.assertEqual(body['recording_retention_days'], 7)
        self.assertEqual(body['retention_source'], 'workspace')

    def test_a_workspace_that_sets_nothing_defers_to_the_profile(self):
        body = self._get(f'?workspace_id={self.ws.id}').json()
        self.assertEqual(body['recording_retention_days'], 30)
        self.assertEqual(body['retention_source'], 'profile')

    def test_an_unknown_workspace_does_not_change_the_answer(self):
        body = self._get('?workspace_id=11111111-1111-1111-1111-111111111111').json()
        self.assertEqual(body['recording_retention_days'], 30)
