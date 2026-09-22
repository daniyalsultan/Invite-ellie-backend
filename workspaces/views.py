# workspaces/views.py
from datetime import timezone
import json
from rest_framework import viewsets, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, OpenApiParameter

from accounts.models import ActivityLog
from accounts.permissions import IsSupabaseAuthenticated
from .models import Workspace, WorkspaceMembership
from rest_framework.exceptions import NotFound
from .membership import (MembershipChangeRefused, change_member_role, leave_workspace, remove_member)
from .invites import accept_invite, create_invite, describe_invite, resend_invite, revoke_invite
from .membership_sync import MembershipSyncError, push_workspace_members
from .serializers import WorkspaceSerializer, WorkspaceMembershipSerializer
from .permissions import IsWorkspaceMember
from .filters import WorkspaceFilter
from django.db import connection, transaction
from django.utils import timezone as django_timezone
from rest_framework.exceptions import APIException
from rest_framework.views import APIView
import logging

logger = logging.getLogger(__name__)

class MembershipUnavailable(APIException):
    status_code = 503
    default_detail = "Couldn't update the workspace right now. Nothing was changed; please try again."
    default_code = 'membership_unavailable'


@extend_schema(tags=['workspaces'])
class WorkspaceViewSet(viewsets.ModelViewSet):
    queryset = Workspace.objects.all()
    serializer_class = WorkspaceSerializer
    permission_classes = [IsWorkspaceMember]
    filterset_class = WorkspaceFilter
    search_fields = ['name']
    ordering_fields = ['created_at', 'name']

    def get_queryset(self):
        # Workspaces this person is an active member of, whoever created them.
        # A workspace they can't see is a 404, not a 403: its id isn't theirs
        # to confirm.
        return self.queryset.filter(
            memberships__profile=self.request.profile,
            memberships__status=WorkspaceMembership.STATUS_ACTIVE,
        ).prefetch_related('memberships__profile').distinct()

    def perform_create(self, serializer):
        # The creator is the workspace's first owner member. The workspace,
        # the membership and recall-server's mirror change together or not at
        # all: a failed write-through raises inside the transaction.
        try:
            with transaction.atomic():
                workspace = serializer.save(owner=self.request.profile)
                WorkspaceMembership.objects.create(
                    workspace=workspace,
                    profile=self.request.profile,
                    role=WorkspaceMembership.ROLE_OWNER,
                    status=WorkspaceMembership.STATUS_ACTIVE,
                    joined_at=django_timezone.now(),
                )
                push_workspace_members(workspace.id)
        except MembershipSyncError as error:
            logger.error(f'Workspace create rolled back, membership write-through failed: {error}')
            raise MembershipUnavailable()

    def _membership_or_404(self, workspace, membership_id, status=None):
        rows = WorkspaceMembership.objects.filter(workspace=workspace, id=membership_id)
        if status:
            rows = rows.filter(status=status)
        membership = rows.select_related('profile', 'workspace', 'invited_by').first()
        if membership is None:
            raise NotFound('No such member or invitation in this workspace.')
        return membership

    @action(detail=True, methods=['get'])
    def members(self, request, pk=None):
        """Everyone in the workspace, plus pending invitations. Any member may look."""
        workspace = self.get_object()
        rows = WorkspaceMembership.objects.filter(
            workspace=workspace, status__in=[WorkspaceMembership.STATUS_ACTIVE, WorkspaceMembership.STATUS_INVITED],
        ).select_related('profile', 'invited_by').order_by('status', 'joined_at', 'created_at')
        return Response(WorkspaceMembershipSerializer(rows, many=True).data)

    @action(detail=True, methods=['post'], url_path='invites')
    def invite(self, request, pk=None):
        """Invite an email address. Owners only (the default for writes)."""
        workspace = self.get_object()
        try:
            invite = create_invite(workspace, request.profile, request.data.get('email'),
                                   request.data.get('role') or WorkspaceMembership.ROLE_MEMBER)
        except MembershipChangeRefused as refused:
            return Response({'error': refused.message}, status=refused.status)
        return Response(WorkspaceMembershipSerializer(invite).data, status=201)

    @action(detail=True, methods=['post'], url_path=r'invites/(?P<membership_id>[^/.]+)/resend')
    def resend(self, request, pk=None, membership_id=None):
        workspace = self.get_object()
        invite = self._membership_or_404(workspace, membership_id)
        try:
            sent = resend_invite(invite)
        except MembershipChangeRefused as refused:
            return Response({'error': refused.message}, status=refused.status)
        return Response({'sent': sent, 'expires_at': invite.invite_expires_at})

    @action(detail=True, methods=['delete'], url_path=r'invites/(?P<membership_id>[^/.]+)')
    def revoke(self, request, pk=None, membership_id=None):
        workspace = self.get_object()
        invite = self._membership_or_404(workspace, membership_id)
        try:
            revoke_invite(invite)
        except MembershipChangeRefused as refused:
            return Response({'error': refused.message}, status=refused.status)
        return Response(status=204)

    @action(detail=True, methods=['delete'], url_path=r'members/(?P<membership_id>[^/.]+)')
    def remove_member(self, request, pk=None, membership_id=None):
        """Take someone out of the workspace. Owners only; the last owner stays."""
        workspace = self.get_object()
        membership = self._membership_or_404(workspace, membership_id, status=WorkspaceMembership.STATUS_ACTIVE)
        try:
            remove_member(workspace, membership)
        except MembershipChangeRefused as refused:
            return Response({'error': refused.message}, status=refused.status)
        except MembershipSyncError as error:
            logger.error(f'Removing a member rolled back, membership write-through failed: {error}')
            raise MembershipUnavailable()
        return Response(status=204)

    @action(detail=True, methods=['patch'], url_path=r'members/(?P<membership_id>[^/.]+)/role')
    def change_role(self, request, pk=None, membership_id=None):
        """Make someone an owner, or step them back to member. Owners only."""
        workspace = self.get_object()
        membership = self._membership_or_404(workspace, membership_id, status=WorkspaceMembership.STATUS_ACTIVE)
        try:
            change_member_role(workspace, membership, request.data.get('role'))
        except MembershipChangeRefused as refused:
            return Response({'error': refused.message}, status=refused.status)
        except MembershipSyncError as error:
            logger.error(f'Role change rolled back, membership write-through failed: {error}')
            raise MembershipUnavailable()
        return Response(WorkspaceMembershipSerializer(membership).data)

    def get_permissions(self):
        # Any member may leave, so the owner-only rule for writes doesn't
        # apply to it. Decided here rather than on the @action, which only
        # takes effect when the route comes from the router.
        if self.action in ('leave', 'members'):
            return [IsWorkspaceMember()] if self.action == 'members' else []
        return super().get_permissions()

    @action(detail=True, methods=['post'])
    def leave(self, request, pk=None):
        # get_object() still 404s for someone who isn't a member, and
        # leave_workspace re-checks membership under a row lock.
        workspace = self.get_object()
        try:
            leave_workspace(request.profile, workspace)
        except MembershipChangeRefused as refused:
            return Response({'error': refused.message}, status=refused.status)
        except MembershipSyncError as error:
            logger.error(f'Leave rolled back, membership write-through failed: {error}')
            raise MembershipUnavailable()
        return Response(status=204)

    def perform_destroy(self, instance):
        try:
            with transaction.atomic():
                push_workspace_members(instance.id, members=[])
                instance.delete()
        except MembershipSyncError as error:
            logger.error(f'Workspace delete rolled back, membership write-through failed: {error}')
            raise MembershipUnavailable()


class GlobalSearchView(APIView):
    permission_classes = [IsSupabaseAuthenticated]
    pagination_class = PageNumberPagination
    serializer_class = None

    @extend_schema(
        tags=['workspaces'],
        parameters=[
            OpenApiParameter(name='q', type=str, description='Search query', required=True),
            OpenApiParameter(name='page', type=int, description='Page number', required=False),
            OpenApiParameter(name='limit', type=int, description='Results per page (max 100)', required=False),
        ],
    )
    def get(self, request):
        query = request.query_params.get('q', '').strip()
        if not query:
            return Response({
                "count": 0,
                "next": None,
                "previous": None,
                "results": []
            })

        # Search read `workspaces_meeting`, a table dropped on 27 Aug (meetings
        # live in recall-server), so it could only fail, and nothing in the
        # frontend calls it. Until search is rebuilt against recall-server it
        # answers honestly with no results rather than a 500.
        return Response({
            "count": 0,
            "next": None,
            "previous": None,
            "results": []
        })

    def _get_next_link(self, page, page_size, total_count):
        if page * page_size < total_count:
            return f"?page={page + 1}&limit={page_size}"
        return None

    def _get_previous_link(self, page):
        if page > 1:
            return f"?page={page - 1}"
        return None


@extend_schema(tags=['workspaces'])
class InviteDetailView(APIView):
    """What an invitation link points at. Open: the recipient may not be signed in yet."""

    permission_classes = []
    serializer_class = None

    def get(self, request, token):
        described = describe_invite(token)
        if described['state'] == 'not_found':
            return Response({'error': 'We could not find that invitation.', 'state': 'not_found'}, status=404)
        return Response(described)


@extend_schema(tags=['workspaces'])
class InviteAcceptView(APIView):
    """Join the workspace. Signing in is required, with the invited address."""

    permission_classes = [IsSupabaseAuthenticated]
    serializer_class = None

    def post(self, request, token):
        try:
            workspace = accept_invite(token, request.profile)
        except MembershipChangeRefused as refused:
            return Response({'error': refused.message}, status=refused.status)
        except MembershipSyncError as error:
            logger.error(f'Accepting an invitation rolled back, membership write-through failed: {error}')
            raise MembershipUnavailable()
        return Response({'workspace_id': str(workspace.id), 'workspace_name': workspace.name})
