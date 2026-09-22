"""Write workspace membership through to recall-server's mirror.

recall-server authorises meeting access from its own copy of each
workspace's active members (it cannot read this database). After any change
here, the workspace's complete active member set is sent there; the endpoint
replaces the mirror's set atomically, so repeats and retries are harmless.

A change must never land on one side only. Callers make the change inside a
transaction and push *before* it commits: if the push fails, raising
MembershipSyncError rolls the change back. The rare opposite case (the push
succeeded, then the commit failed) leaves the mirror ahead of the source of
truth, which `reconcile_memberships` reports and repairs.
"""

import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class MembershipSyncError(Exception):
    """recall-server's mirror could not be updated."""


def active_member_set(workspace_id):
    from workspaces.models import WorkspaceMembership

    rows = WorkspaceMembership.objects.filter(
        workspace_id=workspace_id,
        status=WorkspaceMembership.STATUS_ACTIVE,
        profile__isnull=False,
    ).values_list('profile_id', 'role')
    return [{'backend_user_id': str(profile_id), 'role': role} for profile_id, role in rows]


def _recall_request(method, path, **kwargs):
    base_url = (getattr(settings, 'RECALL_SERVER_URL', '') or '').rstrip('/')
    api_key = getattr(settings, 'INTERNAL_API_KEY', '')
    if not base_url or not api_key:
        raise MembershipSyncError('RECALL_SERVER_URL or INTERNAL_API_KEY is not configured')
    try:
        response = requests.request(
            method, f'{base_url}{path}',
            headers={'X-Internal-Api-Key': api_key}, timeout=15, **kwargs,
        )
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as error:
        raise MembershipSyncError(f'{method} {path} failed: {error}') from error


def push_workspace_members(workspace_id, members=None):
    """Make the mirror's member set for this workspace match ours.

    `members=[]` clears it (workspace being deleted). Raises MembershipSyncError.
    """
    payload = {
        'workspace_id': str(workspace_id),
        'members': active_member_set(workspace_id) if members is None else members,
    }
    result = _recall_request('POST', '/api/internal/workspace-members/set', json=payload)
    logger.info(f'Membership mirror updated for workspace {workspace_id}: {result}')
    return result


def fetch_mirror():
    """Every mirrored (workspace, user) -> role, from recall-server."""
    rows = _recall_request('GET', '/api/internal/workspace-members')['members']
    return {(row['workspace_id'], row['backend_user_id']): row['role'] for row in rows}


def find_discrepancies():
    """Compare our active memberships with recall-server's mirror.

    Returns a dict of lists. `extra` is the dangerous kind: a mirror row with
    no active membership behind it grants meeting access nobody gave.
    """
    from workspaces.models import Workspace, WorkspaceMembership

    ours = {
        (str(w), str(p)): role
        for w, p, role in WorkspaceMembership.objects.filter(
            status=WorkspaceMembership.STATUS_ACTIVE, profile__isnull=False,
        ).values_list('workspace_id', 'profile_id', 'role')
    }
    mirror = fetch_mirror()

    ownerless = [
        str(w) for w in Workspace.objects.exclude(
            memberships__role=WorkspaceMembership.ROLE_OWNER,
            memberships__status=WorkspaceMembership.STATUS_ACTIVE,
        ).values_list('id', flat=True)
    ]
    return {
        'missing': sorted(k for k in ours if k not in mirror),
        'extra': sorted(k for k in mirror if k not in ours),
        'role_mismatch': sorted((k, mirror[k], ours[k]) for k in ours if k in mirror and mirror[k] != ours[k]),
        'ownerless_workspaces': sorted(ownerless),
        'counts': {'backend_active': len(ours), 'mirror': len(mirror)},
    }


def discrepancy_total(found):
    return sum(len(found[key]) for key in ('missing', 'extra', 'role_mismatch', 'ownerless_workspaces'))
