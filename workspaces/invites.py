"""Inviting someone to a workspace.

An invite is a WorkspaceMembership with status 'invited', a token and a
7-day expiry. It is always accepted explicitly, even when the email already
has an account: being added to a workspace means colleagues can see your
meetings there, so nobody is put in one without agreeing.

The email goes through the backend's own SMTP (smtp2go), not Supabase, which
only sends auth mail. Accepting writes through to recall-server's membership
mirror before the person lands in the workspace, so their first page load
already shows the right meetings.
"""

import logging
import secrets

from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from accounts.models import Profile
from .membership import MembershipChangeRefused
from .membership_sync import push_workspace_members
from .models import WorkspaceMembership

logger = logging.getLogger(__name__)

INVITE_VALID_DAYS = 7

ACTIVE = WorkspaceMembership.STATUS_ACTIVE
INVITED = WorkspaceMembership.STATUS_INVITED
REMOVED = WorkspaceMembership.STATUS_REMOVED


def invite_url(token):
    base = (settings.FRONTEND_CONFIG.get('FRONTEND_URL') or '').rstrip('/')
    return f'{base}/invite/{token}'


def _expiry():
    return timezone.now() + timezone.timedelta(days=INVITE_VALID_DAYS)


def create_invite(workspace, invited_by, email, role=WorkspaceMembership.ROLE_MEMBER):
    """Invite an email address to a workspace. Returns the membership row."""
    email = (email or '').strip().lower()
    if not email:
        raise MembershipChangeRefused('An email address is required.', status=400)
    if role not in dict(WorkspaceMembership.ROLES):
        raise MembershipChangeRefused('Role must be owner or member.', status=400)

    profile = Profile.objects.filter(email__iexact=email, is_active=True).first()

    with transaction.atomic():
        live = WorkspaceMembership.objects.select_for_update().filter(
            workspace=workspace, status__in=[ACTIVE, INVITED],
        )
        if profile and live.filter(profile=profile).exists():
            existing = live.get(profile=profile)
            raise MembershipChangeRefused(
                'They are already a member of this workspace.' if existing.status == ACTIVE
                else 'They have already been invited.', status=409)
        if live.filter(invited_email__iexact=email, profile__isnull=True).exists():
            raise MembershipChangeRefused('They have already been invited.', status=409)

        invite = WorkspaceMembership.objects.create(
            workspace=workspace, profile=profile, role=role, status=INVITED,
            invited_by=invited_by, invited_email=email,
            invite_token=secrets.token_urlsafe(32), invite_expires_at=_expiry(),
        )

    send_invite_email(invite)
    return invite


def send_invite_email(invite):
    """Tell them they've been invited. A failed send must not lose the invite."""
    inviter = invite.invited_by
    inviter_name = ' '.join(filter(None, [getattr(inviter, 'first_name', ''), getattr(inviter, 'last_name', '')])).strip()
    inviter_label = inviter_name or (getattr(inviter, 'email', '') or 'Someone')
    workspace_name = invite.workspace.name
    link = invite_url(invite.invite_token)
    try:
        send_mail(
            f'{inviter_label} invited you to {workspace_name} on Invite Ellie',
            f'{inviter_label} has invited you to join the workspace "{workspace_name}" on Invite Ellie.\n\n'
            f'Joining lets you see the meetings in this workspace, and record your own into it.\n\n'
            f'Accept the invitation:\n{link}\n\n'
            f'This link expires in {INVITE_VALID_DAYS} days. If you were not expecting this, ignore this email.\n',
            settings.DEFAULT_FROM_EMAIL,
            [invite.invited_email],
        )
        return True
    except Exception as error:
        logger.error(f'Invite email to {invite.invited_email} for workspace {invite.workspace_id} failed: {error}')
        return False


def resend_invite(invite):
    """Send it again with a fresh expiry; the link stays the same."""
    if invite.status != INVITED:
        raise MembershipChangeRefused('That invitation is no longer pending.', status=409)
    invite.invite_expires_at = _expiry()
    invite.save(update_fields=['invite_expires_at', 'updated_at'])
    return send_invite_email(invite)


def revoke_invite(invite):
    if invite.status != INVITED:
        raise MembershipChangeRefused('That invitation is no longer pending.', status=409)
    # The token stays so the link can say the invitation was withdrawn rather
    # than that it never existed. accept_invite refuses anything not 'invited'.
    invite.status = REMOVED
    invite.save(update_fields=['status', 'updated_at'])


def find_invite(token):
    """The invite this token refers to, whatever state it is in, or None."""
    if not token:
        return None
    return WorkspaceMembership.objects.select_related('workspace', 'invited_by').filter(invite_token=token).first()


def describe_invite(token):
    """What to show on the invite screen: who, which workspace, and whether it still stands."""
    invite = find_invite(token)
    if invite is None or invite.status != INVITED:
        return {'state': 'not_found' if invite is None else 'revoked'}
    if invite.invite_expires_at and invite.invite_expires_at <= timezone.now():
        return {'state': 'expired', 'workspace_name': invite.workspace.name, 'email': invite.invited_email}
    inviter = invite.invited_by
    return {
        'state': 'pending',
        'workspace_id': str(invite.workspace_id),
        'workspace_name': invite.workspace.name,
        'email': invite.invited_email,
        'role': invite.role,
        'invited_by': (' '.join(filter(None, [getattr(inviter, 'first_name', ''), getattr(inviter, 'last_name', '')])).strip()
                       or getattr(inviter, 'email', '') or ''),
        'expires_at': invite.invite_expires_at,
    }


def accept_invite(token, profile):
    """Join the workspace. The signed-in account must be the invited address.

    recall-server's mirror is updated inside the transaction, so a failure
    leaves nobody half-joined, and a successful join is already visible to the
    meeting endpoints by the time the person is redirected.
    """
    with transaction.atomic():
        invite = WorkspaceMembership.objects.select_for_update().select_related('workspace').filter(
            invite_token=token).first()
        if invite is None or invite.status != INVITED:
            raise MembershipChangeRefused('This invitation is no longer valid. Ask for a new one.', status=404)
        if invite.invite_expires_at and invite.invite_expires_at <= timezone.now():
            raise MembershipChangeRefused('This invitation has expired. Ask for a new one.', status=410)
        if (profile.email or '').strip().lower() != (invite.invited_email or '').strip().lower():
            raise MembershipChangeRefused(
                f'This invitation was sent to {invite.invited_email}. Sign in with that address to accept it.',
                status=403)

        already = WorkspaceMembership.objects.filter(
            workspace=invite.workspace, profile=profile, status=ACTIVE).exists()
        if already:
            revoke_invite(invite)
            return invite.workspace

        invite.profile = profile
        invite.status = ACTIVE
        invite.joined_at = timezone.now()
        invite.invite_token = None
        invite.save(update_fields=['profile', 'status', 'joined_at', 'invite_token', 'updated_at'])
        push_workspace_members(invite.workspace_id)
    return invite.workspace
