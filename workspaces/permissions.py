from rest_framework import permissions

from .models import WorkspaceMembership


def membership_role(profile, workspace):
    """'owner', 'member', or None for this person in this workspace."""
    if profile is None or workspace is None:
        return None
    return WorkspaceMembership.objects.filter(
        workspace=workspace, profile=profile, status=WorkspaceMembership.STATUS_ACTIVE,
    ).values_list('role', flat=True).first()


class IsWorkspaceMember(permissions.BasePermission):
    """Any active member may read a workspace; changing or deleting it is for owners.

    Replaces IsOwner (owner-column equality) now that a workspace can have
    several members and more than one owner.
    """

    def has_object_permission(self, request, view, obj):
        role = membership_role(getattr(request, 'profile', None), obj)
        if role is None:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        return role == WorkspaceMembership.ROLE_OWNER
