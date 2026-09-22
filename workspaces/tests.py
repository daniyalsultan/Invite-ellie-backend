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
