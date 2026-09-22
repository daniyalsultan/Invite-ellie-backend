"""Workspace membership: model, backfill, write-through and reconciliation.

Run against a throwaway Postgres, never Supabase:
    python manage.py test workspaces --settings=<local test settings>
recall-server is never called: every write-through is mocked.
"""

import importlib
from types import SimpleNamespace
from unittest import mock

from django.apps import apps
from django.db import IntegrityError, transaction
from django.test import TestCase

from accounts.models import Profile
from workspaces.membership_sync import MembershipSyncError, discrepancy_total, find_discrepancies
from workspaces.models import Workspace, WorkspaceMembership
from workspaces.serializers import WorkspaceSerializer
from workspaces.views import MembershipUnavailable, WorkspaceViewSet

backfill_migration = importlib.import_module('workspaces.migrations.0013_backfill_owner_memberships')
PUSH = 'workspaces.views.push_workspace_members'


def make_profile(email):
    return Profile.objects.create(email=email)


def view_for(profile):
    view = WorkspaceViewSet()
    view.request = SimpleNamespace(profile=profile)
    return view


def serializer_for(profile, data, instance=None):
    return WorkspaceSerializer(instance=instance, data=data, context={'request': SimpleNamespace(profile=profile)})


class BackfillTests(TestCase):
    def test_every_workspace_gets_its_owner_exactly_once(self):
        alice, bob = make_profile('alice@example.com'), make_profile('bob@example.com')
        a1 = Workspace.objects.create(owner=alice, name='Personal')
        a2 = Workspace.objects.create(owner=alice, name='Client A')
        b1 = Workspace.objects.create(owner=bob, name='Personal')

        backfill_migration.backfill(apps, None)
        backfill_migration.backfill(apps, None)  # re-running adds nothing

        rows = set(WorkspaceMembership.objects.values_list('workspace_id', 'profile_id', 'role', 'status'))
        self.assertEqual(rows, {
            (a1.id, alice.id, 'owner', 'active'),
            (a2.id, alice.id, 'owner', 'active'),
            (b1.id, bob.id, 'owner', 'active'),
        })
        self.assertTrue(all(m.joined_at == m.workspace.created_at for m in WorkspaceMembership.objects.all()))


class WorkspaceWriteThroughTests(TestCase):
    def setUp(self):
        self.alice = make_profile('alice@example.com')

    def test_create_makes_the_creator_an_owner_and_updates_the_mirror(self):
        serializer = serializer_for(self.alice, {'name': 'Client A'})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        with mock.patch(PUSH) as push:
            view_for(self.alice).perform_create(serializer)
        workspace = Workspace.objects.get(name='Client A')
        membership = WorkspaceMembership.objects.get(workspace=workspace)
        self.assertEqual((membership.profile, membership.role, membership.status), (self.alice, 'owner', 'active'))
        push.assert_called_once_with(workspace.id)

    def test_create_is_rolled_back_when_the_mirror_cannot_be_updated(self):
        serializer = serializer_for(self.alice, {'name': 'Client A'})
        self.assertTrue(serializer.is_valid())
        with mock.patch(PUSH, side_effect=MembershipSyncError('recall-server down')):
            with self.assertRaises(MembershipUnavailable):
                view_for(self.alice).perform_create(serializer)
        self.assertFalse(Workspace.objects.filter(name='Client A').exists())
        self.assertEqual(WorkspaceMembership.objects.count(), 0)

    def test_delete_clears_the_mirror_then_deletes(self):
        workspace = Workspace.objects.create(owner=self.alice, name='Client A')
        WorkspaceMembership.objects.create(workspace=workspace, profile=self.alice, role='owner')
        workspace_id = workspace.id  # Django clears the pk on delete
        with mock.patch(PUSH) as push:
            view_for(self.alice).perform_destroy(workspace)
        push.assert_called_once_with(workspace_id, members=[])
        self.assertFalse(Workspace.objects.filter(pk=workspace_id).exists())
        self.assertEqual(WorkspaceMembership.objects.count(), 0)

    def test_delete_is_rolled_back_when_the_mirror_cannot_be_updated(self):
        workspace = Workspace.objects.create(owner=self.alice, name='Client A')
        WorkspaceMembership.objects.create(workspace=workspace, profile=self.alice, role='owner')
        with mock.patch(PUSH, side_effect=MembershipSyncError('recall-server down')):
            with self.assertRaises(MembershipUnavailable):
                view_for(self.alice).perform_destroy(workspace)
        self.assertTrue(Workspace.objects.filter(pk=workspace.pk).exists())
        self.assertEqual(WorkspaceMembership.objects.count(), 1)


class WorkspaceNameTests(TestCase):
    """Replaces the old (owner, name) unique constraint."""

    def setUp(self):
        self.alice, self.bob = make_profile('alice@example.com'), make_profile('bob@example.com')
        self.personal = Workspace.objects.create(owner=self.alice, name='Personal')
        WorkspaceMembership.objects.create(workspace=self.personal, profile=self.alice, role='owner')
        self.client_a = Workspace.objects.create(owner=self.alice, name='Client A')
        WorkspaceMembership.objects.create(workspace=self.client_a, profile=self.alice, role='owner')

    def test_an_owner_cannot_create_a_second_workspace_with_the_same_name(self):
        self.assertFalse(serializer_for(self.alice, {'name': 'Personal'}).is_valid())

    def test_different_people_can_use_the_same_name(self):
        self.assertTrue(serializer_for(self.bob, {'name': 'Personal'}).is_valid())

    def test_renaming_onto_another_owned_name_is_rejected(self):
        self.assertFalse(serializer_for(self.alice, {'name': 'Personal'}, instance=self.client_a).is_valid())

    def test_saving_a_workspace_under_its_own_name_is_fine(self):
        self.assertTrue(serializer_for(self.alice, {'name': 'Client A'}, instance=self.client_a).is_valid())

    def test_a_workspace_someone_was_removed_from_does_not_block_the_name(self):
        shared = Workspace.objects.create(owner=self.bob, name='Shared')
        WorkspaceMembership.objects.create(workspace=shared, profile=self.alice, role='owner', status='removed')
        self.assertTrue(serializer_for(self.alice, {'name': 'Shared'}).is_valid())


class MembershipConstraintTests(TestCase):
    def setUp(self):
        self.alice = make_profile('alice@example.com')
        self.workspace = Workspace.objects.create(owner=self.alice, name='Personal')

    def test_one_live_membership_per_person_per_workspace(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.alice, role='owner')
        with self.assertRaises(IntegrityError), transaction.atomic():
            WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.alice, role='member', status='invited')

    def test_removed_history_may_repeat(self):
        for _ in range(2):
            WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.alice, status='removed')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.alice, role='owner')
        self.assertEqual(WorkspaceMembership.objects.count(), 3)


class ReconciliationTests(TestCase):
    def setUp(self):
        self.alice, self.bob = make_profile('alice@example.com'), make_profile('bob@example.com')
        self.workspace = Workspace.objects.create(owner=self.alice, name='Personal')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.alice, role='owner')
        self.key = (str(self.workspace.id), str(self.alice.id))

    def found(self, mirror):
        with mock.patch('workspaces.membership_sync.fetch_mirror', return_value=mirror):
            return find_discrepancies()

    def test_an_exact_mirror_has_no_discrepancies(self):
        self.assertEqual(discrepancy_total(self.found({self.key: 'owner'})), 0)

    def test_reports_missing_extra_and_role_mismatch(self):
        stranger = (str(self.workspace.id), str(self.bob.id))
        self.assertEqual(self.found({})['missing'], [self.key])
        self.assertEqual(self.found({self.key: 'owner', stranger: 'member'})['extra'], [stranger])
        self.assertEqual(self.found({self.key: 'member'})['role_mismatch'], [(self.key, 'member', 'owner')])

    def test_invited_and_removed_rows_are_not_expected_in_the_mirror(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.bob, status='invited')
        WorkspaceMembership.objects.create(workspace=self.workspace, invited_email='new@example.com', status='invited')
        self.assertEqual(discrepancy_total(self.found({self.key: 'owner'})), 0)

    def test_reports_a_workspace_with_no_active_owner(self):
        orphan = Workspace.objects.create(owner=self.bob, name='Orphan')
        self.assertEqual(self.found({self.key: 'owner'})['ownerless_workspaces'], [str(orphan.id)])


class WorkspaceAuthorizationTests(TestCase):
    """Workspace endpoints for an owner, a member, a removed member and an outsider."""

    def setUp(self):
        from rest_framework.test import APIRequestFactory
        self.factory = APIRequestFactory()
        self.owner, self.member = make_profile('owner@example.com'), make_profile('member@example.com')
        self.removed, self.outsider = make_profile('removed@example.com'), make_profile('outsider@example.com')
        self.workspace = Workspace.objects.create(owner=self.owner, name='Client A')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.owner, role='owner')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.member, role='member')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.removed, role='member', status='removed')
        own = Workspace.objects.create(owner=self.outsider, name='Elsewhere')
        WorkspaceMembership.objects.create(workspace=own, profile=self.outsider, role='owner')

    def call(self, profile, method, action, pk=None, data=None):
        request = getattr(self.factory, method)('/api/workspaces/', data or {}, format='json')
        request.profile = profile
        view = WorkspaceViewSet.as_view({method: action})
        with mock.patch(PUSH):
            return view(request, pk=pk) if pk else view(request)

    def listed(self, profile):
        response = self.call(profile, 'get', 'list')
        rows = response.data['results'] if isinstance(response.data, dict) else response.data
        return {row['id'] for row in rows}

    def test_list_shows_workspaces_the_person_is_an_active_member_of(self):
        ws = str(self.workspace.id)
        self.assertIn(ws, self.listed(self.owner))
        self.assertIn(ws, self.listed(self.member))
        self.assertNotIn(ws, self.listed(self.removed))
        self.assertNotIn(ws, self.listed(self.outsider))

    def test_retrieve_for_members_only(self):
        for profile, status in ((self.owner, 200), (self.member, 200), (self.removed, 404), (self.outsider, 404)):
            with self.subTest(profile=profile.email):
                self.assertEqual(self.call(profile, 'get', 'retrieve', pk=self.workspace.pk).status_code, status)

    def test_rename_is_for_owners_only(self):
        for profile, status in ((self.member, 403), (self.removed, 404), (self.outsider, 404), (self.owner, 200)):
            with self.subTest(profile=profile.email):
                response = self.call(profile, 'patch', 'partial_update', pk=self.workspace.pk, data={'name': 'Renamed'})
                self.assertEqual(response.status_code, status)

    def test_delete_is_for_owners_only(self):
        for profile, status in ((self.member, 403), (self.removed, 404), (self.outsider, 404)):
            with self.subTest(profile=profile.email):
                self.assertEqual(self.call(profile, 'delete', 'destroy', pk=self.workspace.pk).status_code, status)
        self.assertTrue(Workspace.objects.filter(pk=self.workspace.pk).exists())
        self.assertEqual(self.call(self.owner, 'delete', 'destroy', pk=self.workspace.pk).status_code, 204)

    def test_a_workspace_can_have_more_than_one_owner(self):
        WorkspaceMembership.objects.filter(profile=self.member).update(role='owner')
        response = self.call(self.member, 'patch', 'partial_update', pk=self.workspace.pk, data={'name': 'Co-owned'})
        self.assertEqual(response.status_code, 200)

    def test_global_search_answers_empty_instead_of_failing(self):
        from workspaces.views import GlobalSearchView
        request = self.factory.get('/api/workspaces/search/', {'q': 'anything'})
        request.profile = self.owner
        with mock.patch('workspaces.views.GlobalSearchView.permission_classes', []):
            response = GlobalSearchView.as_view()(request)
        self.assertEqual((response.status_code, response.data['count']), (200, 0))


class InternalUserInfoTests(TestCase):
    def test_lists_active_memberships_with_roles(self):
        from django.test import override_settings
        from accounts.views import InternalUserInfoView
        from rest_framework.test import APIRequestFactory
        owner, member = make_profile('owner@example.com'), make_profile('member@example.com')
        shared = Workspace.objects.create(owner=owner, name='Shared')
        WorkspaceMembership.objects.create(workspace=shared, profile=owner, role='owner')
        WorkspaceMembership.objects.create(workspace=shared, profile=member, role='member')
        gone = Workspace.objects.create(owner=owner, name='Gone')
        WorkspaceMembership.objects.create(workspace=gone, profile=member, role='member', status='removed')
        request = APIRequestFactory().get('/', HTTP_X_INTERNAL_API_KEY='k')
        with override_settings(INTERNAL_API_KEY='k'):
            response = InternalUserInfoView.as_view()(request, user_id=member.id)
        self.assertEqual(response.data['workspaces'], [{'id': str(shared.id), 'name': 'Shared', 'role': 'member'}])


class LeaveWorkspaceTests(TestCase):
    def setUp(self):
        from rest_framework.test import APIRequestFactory
        self.factory = APIRequestFactory()
        self.owner, self.member, self.outsider = (make_profile(f'{n}@example.com') for n in ('owner', 'member', 'out'))
        self.workspace = Workspace.objects.create(owner=self.owner, name='Client A')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.owner, role='owner')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.member, role='member')

    def leave(self, profile, push_error=None):
        request = self.factory.post(f'/api/workspaces/{self.workspace.id}/leave/')
        request.profile = profile
        with mock.patch('workspaces.membership.push_workspace_members',
                        side_effect=push_error) as push:
            response = WorkspaceViewSet.as_view({'post': 'leave'})(request, pk=self.workspace.pk)
        return response, push

    def status_of(self, profile):
        return WorkspaceMembership.objects.filter(workspace=self.workspace, profile=profile).values_list('status', flat=True).first()

    def test_a_member_leaving_leaves_the_workspace_intact(self):
        response, push = self.leave(self.member)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(self.status_of(self.member), 'removed')
        self.assertTrue(Workspace.objects.filter(pk=self.workspace.pk).exists())
        push.assert_called_once_with(self.workspace.id)

    def test_the_last_owner_cannot_leave_while_others_remain(self):
        response, push = self.leave(self.owner)
        self.assertEqual(response.status_code, 409)
        self.assertIn('only owner', response.data['error'])
        self.assertEqual(self.status_of(self.owner), 'active')
        push.assert_not_called()

    def test_a_co_owner_can_leave(self):
        WorkspaceMembership.objects.filter(profile=self.member).update(role='owner')
        response, _ = self.leave(self.owner)
        self.assertEqual(response.status_code, 204)

    def test_the_only_member_is_told_to_delete_instead(self):
        WorkspaceMembership.objects.filter(profile=self.member).update(status='removed')
        response, _ = self.leave(self.owner)
        self.assertEqual(response.status_code, 409)
        self.assertIn('Delete it', response.data['error'])

    def test_a_non_member_gets_404(self):
        response, _ = self.leave(self.outsider)
        self.assertEqual(response.status_code, 404)

    def test_leaving_is_rolled_back_if_the_mirror_cannot_be_updated(self):
        response, _ = self.leave(self.member, push_error=MembershipSyncError('down'))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.status_of(self.member), 'active')


class AccountDeletionTests(TestCase):
    """What happens to workspaces when someone's account is deleted."""

    def setUp(self):
        self.leaver = make_profile('leaver@example.com')
        self.early, self.late = make_profile('early@example.com'), make_profile('late@example.com')

    def workspace(self, name, *members):
        from datetime import timedelta
        from django.utils import timezone
        ws = Workspace.objects.create(owner=members[0][0], name=name)
        for i, (profile, role) in enumerate(members):
            WorkspaceMembership.objects.create(workspace=ws, profile=profile, role=role,
                                               joined_at=timezone.now() - timedelta(days=30 - i))
        return ws

    def delete_account(self, purge_error=None):
        from accounts.tasks import perform_deletion
        with mock.patch('workspaces.membership.push_workspace_members') as push, \
                mock.patch('workspaces.membership_sync.purge_recall_data',
                           side_effect=purge_error, return_value={'deleted': {}, 'kept_in_shared_workspaces': 0}) as purge, \
                mock.patch('accounts.tasks.delete_supabase_user', return_value=True), \
                mock.patch('accounts.tasks.send_mail'):
            result = perform_deletion(self.leaver.id)
        self.assertEqual(result, 'Deletion completed successfully')
        self.purge = purge
        return push

    def test_recall_server_data_is_purged_after_the_workspaces_are_released(self):
        shared = self.workspace('Shared', (self.leaver, 'owner'), (self.early, 'member'))
        self.delete_account()
        self.purge.assert_called_once_with(self.leaver.id)
        self.assertTrue(Workspace.objects.filter(pk=shared.pk).exists())

    def test_a_failed_purge_is_alerted_but_does_not_stop_the_deletion(self):
        self.workspace('Solo', (self.leaver, 'owner'))
        with self.assertLogs('accounts.tasks', level='CRITICAL') as logs:
            self.delete_account(purge_error=MembershipSyncError('recall-server down'))
        self.assertIn('NOT purged', ' '.join(logs.output))
        self.leaver.refresh_from_db()
        self.assertFalse(self.leaver.is_active)

    def role(self, ws, profile):
        return WorkspaceMembership.objects.filter(workspace=ws, profile=profile, status='active').values_list('role', flat=True).first()

    def test_a_workspace_nobody_else_is_in_is_deleted(self):
        solo = self.workspace('Solo', (self.leaver, 'owner'))
        push = self.delete_account()
        self.assertFalse(Workspace.objects.filter(pk=solo.pk).exists())
        push.assert_any_call(solo.id, members=[])

    def test_a_shared_workspace_passes_to_the_longest_standing_member(self):
        shared = self.workspace('Shared', (self.leaver, 'owner'), (self.early, 'member'), (self.late, 'member'))
        self.delete_account()
        shared.refresh_from_db()
        self.assertEqual(self.role(shared, self.early), 'owner')
        self.assertEqual(self.role(shared, self.late), 'member')
        self.assertIsNone(self.role(shared, self.leaver))
        self.assertEqual(shared.owner_id, self.early.id)

    def test_no_promotion_when_another_owner_remains(self):
        shared = self.workspace('Co-owned', (self.leaver, 'owner'), (self.late, 'member'), (self.early, 'owner'))
        self.delete_account()
        self.assertEqual(self.role(shared, self.late), 'member')
        self.assertEqual(self.role(shared, self.early), 'owner')

    def test_a_workspace_they_created_but_already_left_is_untouched(self):
        handed_on = self.workspace('Handed on', (self.leaver, 'owner'), (self.early, 'owner'))
        WorkspaceMembership.objects.filter(workspace=handed_on, profile=self.leaver).update(status='removed')
        self.delete_account()
        self.assertTrue(Workspace.objects.filter(pk=handed_on.pk).exists())
        self.assertEqual(self.role(handed_on, self.early), 'owner')

    def test_pending_invites_to_them_are_withdrawn(self):
        other = self.workspace('Other', (self.early, 'owner'))
        WorkspaceMembership.objects.create(workspace=other, profile=self.leaver, status='invited')
        self.delete_account()
        self.assertFalse(WorkspaceMembership.objects.filter(profile=self.leaver, status='invited').exists())


class ExportTests(TestCase):
    def test_export_lists_active_memberships_and_their_own_recall_data(self):
        from accounts.services import DataExportService
        member, owner = make_profile('member@example.com'), make_profile('owner@example.com')
        shared = Workspace.objects.create(owner=owner, name='Shared')
        WorkspaceMembership.objects.create(workspace=shared, profile=owner, role='owner')
        WorkspaceMembership.objects.create(workspace=shared, profile=member, role='member')
        left = Workspace.objects.create(owner=owner, name='Left')
        WorkspaceMembership.objects.create(workspace=left, profile=member, role='member', status='removed')

        recall = mock.Mock(status_code=200)
        recall.json.return_value = {'meetings': [{'id': 'm1'}], 'assistant_questions': [{'question': 'q?'}]}
        s3 = mock.Mock()
        s3.generate_presigned_url.return_value = 'https://signed/export'
        with mock.patch('accounts.services.requests.get', return_value=recall) as get, \
                mock.patch.object(DataExportService, '_get_s3_client', return_value=s3), \
                self.settings(RECALL_SERVER_URL='https://recall.test', INTERNAL_API_KEY='k'):
            ok, url, error = DataExportService.generate_export(member)
        self.assertTrue(ok, error)
        exported = __import__('json').loads(s3.put_object.call_args.kwargs['Body'])
        self.assertEqual([(w['name'], w['role']) for w in exported['workspaces']], [('Shared', 'member')])
        self.assertEqual(exported['meetings'], [{'id': 'm1'}])
        self.assertEqual(exported['assistant_questions'], [{'question': 'q?'}])
        self.assertIn(f'/api/internal/user-meetings/{member.id}', get.call_args.args[0])
