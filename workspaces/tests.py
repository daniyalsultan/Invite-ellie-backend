"""Workspace membership: model, backfill, write-through and reconciliation.

Run against a throwaway Postgres, never Supabase:
    python manage.py test workspaces --settings=<local test settings>
recall-server is never called: every write-through is mocked.
"""

import importlib
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.apps import apps
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

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


class InviteTests(TestCase):
    """Inviting someone, and what happens when they follow the link."""

    def setUp(self):
        from rest_framework.test import APIRequestFactory
        from django.core import mail
        self.factory = APIRequestFactory()
        self.mail = mail
        mail.outbox = []
        self.owner, self.member = make_profile('owner@example.com'), make_profile('member@example.com')
        self.invitee, self.stranger = make_profile('invitee@example.com'), make_profile('stranger@example.com')
        self.workspace = Workspace.objects.create(owner=self.owner, name='Client A')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.owner, role='owner')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.member, role='member')

    def call(self, profile, method, action, data=None, **kwargs):
        request = getattr(self.factory, method)('/', data or {}, format='json')
        request.profile = profile
        with mock.patch(PUSH), mock.patch('workspaces.membership.push_workspace_members'):
            return WorkspaceViewSet.as_view({method: action})(request, pk=self.workspace.pk, **kwargs)

    def invite(self, email, by=None, role='member'):
        return self.call(by or self.owner, 'post', 'invite', {'email': email, 'role': role})

    def accept(self, token, profile, push_error=None):
        from workspaces.views import InviteAcceptView
        request = self.factory.post('/')
        request.profile = profile
        with mock.patch('workspaces.invites.push_workspace_members', side_effect=push_error):
            return InviteAcceptView.as_view()(request, token=token)

    def preview(self, token):
        from workspaces.views import InviteDetailView
        return InviteDetailView.as_view()(self.factory.get('/'), token=token)

    def pending(self, email='new@example.com'):
        self.invite(email)
        return WorkspaceMembership.objects.get(invited_email=email, status='invited')

    def test_an_owner_invites_by_email_and_an_email_goes_out(self):
        response = self.invite('new@example.com')
        self.assertEqual(response.status_code, 201)
        invite = WorkspaceMembership.objects.get(invited_email='new@example.com')
        self.assertEqual((invite.status, invite.role), ('invited', 'member'))
        self.assertIsNotNone(invite.invite_token)
        self.assertGreater(invite.invite_expires_at, timezone.now() + timedelta(days=6))
        self.assertEqual(len(self.mail.outbox), 1)
        self.assertIn(invite.invite_token, self.mail.outbox[0].body)
        self.assertEqual(self.mail.outbox[0].to, ['new@example.com'])

    def test_an_existing_account_is_linked_to_the_invite_but_must_still_accept(self):
        self.invite('invitee@example.com')
        invite = WorkspaceMembership.objects.get(invited_email='invitee@example.com')
        self.assertEqual(invite.profile, self.invitee)
        self.assertEqual(invite.status, 'invited')

    def test_members_and_outsiders_cannot_invite(self):
        self.assertEqual(self.invite('new@example.com', by=self.member).status_code, 403)
        self.assertEqual(self.invite('new@example.com', by=self.stranger).status_code, 404)
        self.assertEqual(len(self.mail.outbox), 0)

    def test_inviting_someone_twice_or_an_existing_member_is_refused(self):
        self.invite('new@example.com')
        self.assertEqual(self.invite('new@example.com').status_code, 409)
        self.assertEqual(self.invite('member@example.com').status_code, 409)
        self.assertEqual(self.invite('').status_code, 400)

    def test_accepting_joins_the_workspace_and_updates_the_mirror(self):
        invite = self.pending('invitee@example.com')
        with mock.patch('workspaces.invites.push_workspace_members') as push:
            request = self.factory.post('/')
            request.profile = self.invitee
            from workspaces.views import InviteAcceptView
            response = InviteAcceptView.as_view()(request, token=invite.invite_token)
        self.assertEqual(response.status_code, 200)
        invite.refresh_from_db()
        self.assertEqual((invite.status, invite.profile), ('active', self.invitee))
        self.assertIsNone(invite.invite_token)
        self.assertIsNotNone(invite.joined_at)
        push.assert_called_once_with(self.workspace.id)

    def test_only_the_invited_address_can_accept(self):
        invite = self.pending('invitee@example.com')
        response = self.accept(invite.invite_token, self.stranger)
        self.assertEqual(response.status_code, 403)
        self.assertIn('invitee@example.com', response.data['error'])
        invite.refresh_from_db()
        self.assertEqual(invite.status, 'invited')

    def test_an_expired_link_says_so(self):
        invite = self.pending('invitee@example.com')
        WorkspaceMembership.objects.filter(pk=invite.pk).update(invite_expires_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.accept(invite.invite_token, self.invitee).status_code, 410)
        self.assertEqual(self.preview(invite.invite_token).data['state'], 'expired')

    def test_a_revoked_link_says_it_was_withdrawn(self):
        invite = self.pending('invitee@example.com')
        token = invite.invite_token
        self.assertEqual(self.call(self.owner, 'delete', 'revoke', membership_id=str(invite.id)).status_code, 204)
        self.assertEqual(self.accept(token, self.invitee).status_code, 404)
        self.assertEqual(self.preview(token).data['state'], 'revoked')

    def test_an_unknown_link_is_not_an_error_page(self):
        response = self.preview('nope')
        self.assertEqual((response.status_code, response.data['state']), (404, 'not_found'))

    def test_the_preview_says_who_invited_whom_to_what(self):
        invite = self.pending('invitee@example.com')
        data = self.preview(invite.invite_token).data
        self.assertEqual((data['state'], data['workspace_name'], data['email']),
                         ('pending', 'Client A', 'invitee@example.com'))
        self.assertEqual(data['invited_by'], 'owner@example.com')

    def test_resending_extends_the_expiry_and_keeps_the_link(self):
        invite = self.pending('invitee@example.com')
        WorkspaceMembership.objects.filter(pk=invite.pk).update(invite_expires_at=timezone.now() + timedelta(days=1))
        self.mail.outbox = []
        response = self.call(self.owner, 'post', 'resend', membership_id=str(invite.id))
        self.assertEqual(response.status_code, 200)
        invite.refresh_from_db()
        self.assertGreater(invite.invite_expires_at, timezone.now() + timedelta(days=6))
        self.assertEqual(len(self.mail.outbox), 1)

    def test_accepting_is_rolled_back_if_the_mirror_cannot_be_updated(self):
        invite = self.pending('invitee@example.com')
        response = self.accept(invite.invite_token, self.invitee, push_error=MembershipSyncError('down'))
        self.assertEqual(response.status_code, 503)
        invite.refresh_from_db()
        self.assertEqual(invite.status, 'invited')

    def test_a_failed_invite_email_does_not_lose_the_invitation(self):
        with mock.patch('workspaces.invites.send_mail', side_effect=Exception('smtp down')):
            response = self.invite('new@example.com')
        self.assertEqual(response.status_code, 201)
        self.assertTrue(WorkspaceMembership.objects.filter(invited_email='new@example.com', status='invited').exists())


class MemberManagementTests(TestCase):
    def setUp(self):
        from rest_framework.test import APIRequestFactory
        self.factory = APIRequestFactory()
        self.owner, self.member = make_profile('owner@example.com'), make_profile('member@example.com')
        self.workspace = Workspace.objects.create(owner=self.owner, name='Client A')
        self.owner_row = WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.owner, role='owner')
        self.member_row = WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.member, role='member')

    def call(self, profile, method, action, data=None, **kwargs):
        request = getattr(self.factory, method)('/', data or {}, format='json')
        request.profile = profile
        with mock.patch('workspaces.membership.push_workspace_members'):
            return WorkspaceViewSet.as_view({method: action})(request, pk=self.workspace.pk, **kwargs)

    def test_members_list_shows_everyone_and_pending_invites(self):
        WorkspaceMembership.objects.create(workspace=self.workspace, invited_email='new@example.com', status='invited')
        rows = self.call(self.member, 'get', 'members').data
        self.assertEqual({(r['email'], r['status']) for r in rows}, {
            ('owner@example.com', 'active'), ('member@example.com', 'active'), ('new@example.com', 'invited')})

    def test_an_owner_removes_a_member(self):
        response = self.call(self.owner, 'delete', 'remove_member', membership_id=str(self.member_row.id))
        self.assertEqual(response.status_code, 204)
        self.member_row.refresh_from_db()
        self.assertEqual(self.member_row.status, 'removed')

    def test_a_member_cannot_remove_anyone(self):
        response = self.call(self.member, 'delete', 'remove_member', membership_id=str(self.owner_row.id))
        self.assertEqual(response.status_code, 403)

    def test_the_last_owner_cannot_be_removed_or_demoted(self):
        removed = self.call(self.owner, 'delete', 'remove_member', membership_id=str(self.owner_row.id))
        demoted = self.call(self.owner, 'patch', 'change_role', {'role': 'member'}, membership_id=str(self.owner_row.id))
        self.assertEqual((removed.status_code, demoted.status_code), (409, 409))
        self.owner_row.refresh_from_db()
        self.assertEqual((self.owner_row.status, self.owner_row.role), ('active', 'owner'))

    def test_promoting_someone_then_stepping_back_works(self):
        self.assertEqual(self.call(self.owner, 'patch', 'change_role', {'role': 'owner'},
                                   membership_id=str(self.member_row.id)).status_code, 200)
        self.member_row.refresh_from_db()
        self.assertEqual(self.member_row.role, 'owner')
        self.assertEqual(self.call(self.member, 'patch', 'change_role', {'role': 'member'},
                                   membership_id=str(self.owner_row.id)).status_code, 200)

    def test_an_unknown_membership_id_is_a_404(self):
        import uuid as uuid_lib
        response = self.call(self.owner, 'delete', 'remove_member', membership_id=str(uuid_lib.uuid4()))
        self.assertEqual(response.status_code, 404)


class WorkspaceOwnershipDisplayTests(TestCase):
    """Names are unique per owner, so a shared workspace has to say whose it is."""

    def setUp(self):
        from rest_framework.test import APIRequestFactory
        self.factory = APIRequestFactory()
        self.owner = make_profile('owner@example.com')
        self.owner.first_name, self.owner.last_name = 'Ada', 'Lovelace'
        self.owner.save()
        self.member = make_profile('member@example.com')
        self.shared = Workspace.objects.create(owner=self.owner, name='Personal')
        WorkspaceMembership.objects.create(workspace=self.shared, profile=self.owner, role='owner')
        WorkspaceMembership.objects.create(workspace=self.shared, profile=self.member, role='member')
        self.own = Workspace.objects.create(owner=self.member, name='Personal')
        WorkspaceMembership.objects.create(workspace=self.own, profile=self.member, role='owner')

    def listed(self, profile):
        request = self.factory.get('/api/workspaces/')
        request.profile = profile
        response = WorkspaceViewSet.as_view({'get': 'list'})(request)
        rows = response.data['results'] if isinstance(response.data, dict) else response.data
        return {row['id']: row for row in rows}

    def test_each_workspace_says_who_owns_it_and_what_you_are(self):
        rows = self.listed(self.member)
        shared, own = rows[str(self.shared.id)], rows[str(self.own.id)]
        self.assertEqual((shared['owner_name'], shared['my_role'], shared['member_count']),
                         ('Ada Lovelace', 'member', 2))
        self.assertEqual((own['owner_name'], own['my_role'], own['member_count']),
                         ('member@example.com', 'owner', 1))

    def test_an_owner_without_a_name_falls_back_to_their_email(self):
        rows = self.listed(self.owner)
        self.assertEqual(rows[str(self.shared.id)]['owner_email'], 'owner@example.com')

    def test_listing_workspaces_does_not_cost_a_query_per_workspace(self):
        from django.test.utils import CaptureQueriesContext
        from django.db import connection

        def queries_for_listing():
            with CaptureQueriesContext(connection) as captured:
                self.listed(self.member)
            return len(captured)

        baseline = queries_for_listing()
        for i in range(5):
            extra = Workspace.objects.create(owner=self.member, name=f'Client {i}')
            WorkspaceMembership.objects.create(workspace=extra, profile=self.member, role='owner')
        self.assertEqual(queries_for_listing(), baseline)


class SignedOutAccessTests(TestCase):
    """A signed-out caller is told to sign in, not shown an empty workspace list."""

    def setUp(self):
        from rest_framework.test import APIRequestFactory
        self.factory = APIRequestFactory()
        self.profile = make_profile('owner@example.com')
        self.workspace = Workspace.objects.create(owner=self.profile, name='Client A')
        WorkspaceMembership.objects.create(workspace=self.workspace, profile=self.profile, role='owner')

    def anonymous(self, method, action, pk=None):
        request = getattr(self.factory, method)('/', {}, format='json')
        request.profile = None
        view = WorkspaceViewSet.as_view({method: action})
        return view(request, pk=pk) if pk else view(request)

    def test_every_workspace_route_refuses_a_signed_out_caller(self):
        for method, action, pk in (('get', 'list', None), ('post', 'create', None),
                                   ('get', 'retrieve', self.workspace.pk),
                                   ('get', 'members', self.workspace.pk),
                                   ('post', 'leave', self.workspace.pk),
                                   ('delete', 'destroy', self.workspace.pk)):
            with self.subTest(action=action):
                self.assertEqual(self.anonymous(method, action, pk).status_code, 403)

    def test_a_signed_in_member_still_gets_their_workspaces(self):
        request = self.factory.get('/')
        request.profile = self.profile
        response = WorkspaceViewSet.as_view({'get': 'list'})(request)
        rows = response.data['results'] if isinstance(response.data, dict) else response.data
        self.assertEqual((response.status_code, len(rows)), (200, 1))
