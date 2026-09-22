"""Changing who belongs to a workspace.

Every change here is written through to recall-server's membership mirror
(workspaces/membership_sync.py), which is what decides meeting access. A
change made on request (leaving) happens inside a transaction and is rolled
back if the mirror can't be updated. Account deletion can't wait on another
service, so a failed write-through there is emailed and left for
reconcile_memberships.
"""

import logging

from django.db import transaction
from django.utils import timezone

from .membership_sync import MembershipSyncError, push_workspace_members
from .models import Workspace, WorkspaceMembership

logger = logging.getLogger(__name__)

ACTIVE = WorkspaceMembership.STATUS_ACTIVE
OWNER = WorkspaceMembership.ROLE_OWNER


class MembershipChangeRefused(Exception):
    """A change the rules don't allow. `status` is the HTTP status to answer with."""

    def __init__(self, message, status=409):
        super().__init__(message)
        self.message = message
        self.status = status


def _active(workspace):
    return WorkspaceMembership.objects.filter(workspace=workspace, status=ACTIVE, profile__isnull=False)


def leave_workspace(profile, workspace):
    """Remove this person's own membership; the workspace and its meetings stay.

    The last owner can't leave while anyone else remains (they must promote
    someone or delete the workspace), and the only member can't leave at all
    (that would strand the workspace with nobody in it; delete it instead).
    Raises MembershipChangeRefused or MembershipSyncError; nothing changes on
    either side if it does.
    """
    with transaction.atomic():
        memberships = list(_active(workspace).select_for_update())
        mine = next((m for m in memberships if m.profile_id == profile.id), None)
        if mine is None:
            raise MembershipChangeRefused('You are not a member of this workspace.', status=404)

        others = [m for m in memberships if m.profile_id != profile.id]
        if not others:
            raise MembershipChangeRefused(
                "You're the only member of this workspace. Delete it instead of leaving.")
        if mine.role == OWNER and not any(m.role == OWNER for m in others):
            raise MembershipChangeRefused(
                "You're the only owner. Make someone else an owner, or delete the workspace, before leaving.")

        mine.status = WorkspaceMembership.STATUS_REMOVED
        mine.save(update_fields=['status', 'updated_at'])
        push_workspace_members(workspace.id)


def remove_member(workspace, membership):
    """An owner takes someone out. The workspace keeps its meetings.

    The last owner can't be removed — a workspace with no owner could never be
    renamed, shared or deleted again.
    """
    with transaction.atomic():
        memberships = list(_active(workspace).select_for_update())
        mine = next((m for m in memberships if m.id == membership.id), None)
        if mine is None:
            raise MembershipChangeRefused('They are not a member of this workspace.', status=404)
        others = [m for m in memberships if m.id != mine.id]
        if mine.role == OWNER and not any(m.role == OWNER for m in others):
            raise MembershipChangeRefused(
                "That's the workspace's only owner. Make someone else an owner first.")
        mine.status = WorkspaceMembership.STATUS_REMOVED
        mine.save(update_fields=['status', 'updated_at'])
        push_workspace_members(workspace.id)


def change_member_role(workspace, membership, role):
    """Promote someone to owner, or step an owner back to member."""
    if role not in dict(WorkspaceMembership.ROLES):
        raise MembershipChangeRefused('Role must be owner or member.', status=400)
    with transaction.atomic():
        memberships = list(_active(workspace).select_for_update())
        mine = next((m for m in memberships if m.id == membership.id), None)
        if mine is None:
            raise MembershipChangeRefused('They are not a member of this workspace.', status=404)
        if mine.role == role:
            return mine
        others = [m for m in memberships if m.id != mine.id]
        if mine.role == OWNER and not any(m.role == OWNER for m in others):
            raise MembershipChangeRefused(
                "That's the workspace's only owner. Make someone else an owner first.")
        mine.role = role
        mine.save(update_fields=['role', 'updated_at'])
        push_workspace_members(workspace.id)
        membership.role = role
    return mine


def _longest_standing(memberships):
    return min(memberships, key=lambda m: (m.joined_at or m.created_at, m.created_at))


def release_memberships_for_deleted_account(profile):
    """Account deletion: hand shared workspaces on, delete ones nobody else is in.

    For each workspace the person is an active member of:
    * nobody else is in it: the workspace is deleted, as before sharing;
    * others remain: if the person was its only owner, the longest-standing
      active member becomes owner. Their own membership is then removed and the
      workspace, with every meeting in it, stays with the team.
    Workspaces they created but no longer belong to are left alone unless they
    have no members at all. Pending invites to them are withdrawn.

    Returns {'deleted': [...], 'transferred': {workspace_id: new_owner_id}, 'left': [...]}.
    """
    summary = {'deleted': [], 'transferred': {}, 'left': []}

    workspace_ids = set(
        WorkspaceMembership.objects.filter(profile=profile, status=ACTIVE).values_list('workspace_id', flat=True)
    )
    # Created by them, but empty: nothing to hand on.
    workspace_ids |= {
        w.id for w in Workspace.objects.filter(owner=profile) if not _active(w).exists()
    }

    for workspace in Workspace.objects.filter(id__in=workspace_ids):
        with transaction.atomic():
            memberships = list(_active(workspace).select_for_update())
            others = [m for m in memberships if m.profile_id != profile.id]
            if not others:
                _push_or_alert(workspace.id, members=[])
                workspace.delete()
                summary['deleted'].append(str(workspace.id))
                continue

            if not any(m.role == OWNER for m in others):
                heir = _longest_standing(others)
                heir.role = OWNER
                heir.save(update_fields=['role', 'updated_at'])
                workspace.owner_id = heir.profile_id
                workspace.save(update_fields=['owner', 'updated_at'])
                summary['transferred'][str(workspace.id)] = str(heir.profile_id)

            WorkspaceMembership.objects.filter(workspace=workspace, profile=profile, status=ACTIVE).update(
                status=WorkspaceMembership.STATUS_REMOVED, updated_at=timezone.now())
            summary['left'].append(str(workspace.id))
            _push_or_alert(workspace.id)

    WorkspaceMembership.objects.filter(profile=profile, status=WorkspaceMembership.STATUS_INVITED).update(
        status=WorkspaceMembership.STATUS_REMOVED, updated_at=timezone.now())
    return summary


def _push_or_alert(workspace_id, members=None):
    try:
        push_workspace_members(workspace_id, members=members)
    except MembershipSyncError as error:
        logger.critical(f'Membership mirror not updated for workspace {workspace_id} during account deletion: {error}')
