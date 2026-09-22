import uuid
from django.db.models import (
    Model, UUIDField, ForeignKey, CharField, DateTimeField, DurationField,
    CASCADE, SET_NULL, URLField, TextField, Index, IntegerField, BooleanField, UniqueConstraint,
    EmailField, Q
)
from django.contrib.postgres.fields import ArrayField
from accounts.models import Profile
from workspaces.choices import WorkspaceCategoryChoices

class Workspace(Model):
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Who created the workspace. Membership (WorkspaceMembership) decides who
    # can see and manage it; this column is kept so nothing breaks mid-deploy
    # and is no longer the source of truth.
    owner = ForeignKey(Profile, on_delete=CASCADE, related_name='workspaces')
    name = CharField(max_length=255)
    category = CharField(choices=WorkspaceCategoryChoices.choices, max_length=255, blank=True, null=True)
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)

    # Names used to be unique per owner at the database level. With shared
    # workspaces and ownership transfer that collides (nearly everyone has a
    # "Personal"), so uniqueness is checked per owner-member on create and
    # rename instead (WorkspaceSerializer.validate_name).
    class Meta:
        managed = True

    def __str__(self):
        return self.name



class WorkspaceMembership(Model):
    """Who belongs to a workspace, and as what. The source of truth.

    recall-server keeps a mirror of each workspace's active members (it cannot
    read this database); every change here is written through to it — see
    workspaces/membership_sync.py.
    """

    ROLE_OWNER = 'owner'
    ROLE_MEMBER = 'member'
    ROLES = [(ROLE_OWNER, 'Owner'), (ROLE_MEMBER, 'Member')]

    STATUS_ACTIVE = 'active'
    STATUS_INVITED = 'invited'
    STATUS_REMOVED = 'removed'
    STATUSES = [(STATUS_ACTIVE, 'Active'), (STATUS_INVITED, 'Invited'), (STATUS_REMOVED, 'Removed')]

    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workspace = ForeignKey(Workspace, on_delete=CASCADE, related_name='memberships')
    # Null only for an invite sent to an email with no account yet.
    profile = ForeignKey(Profile, on_delete=CASCADE, related_name='workspace_memberships', null=True, blank=True)
    role = CharField(max_length=16, choices=ROLES, default=ROLE_MEMBER)
    status = CharField(max_length=16, choices=STATUSES, default=STATUS_ACTIVE)
    invited_by = ForeignKey(Profile, on_delete=SET_NULL, related_name='+', null=True, blank=True)
    invited_email = EmailField(blank=True, default='')
    invite_token = CharField(max_length=64, null=True, blank=True, unique=True)
    invite_expires_at = DateTimeField(null=True, blank=True)
    joined_at = DateTimeField(null=True, blank=True)
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            # One live membership per person per workspace. Removed rows are
            # history and may repeat (someone removed, re-invited, removed).
            UniqueConstraint(
                fields=['workspace', 'profile'],
                condition=Q(status__in=['active', 'invited']),
                name='unique_live_membership_per_profile',
            ),
        ]
        indexes = [
            Index(fields=['profile', 'status']),
            Index(fields=['workspace', 'status']),
        ]

    def __str__(self):
        who = self.profile.email if self.profile_id else self.invited_email
        return f'{who} {self.role} ({self.status}) of {self.workspace_id}'
