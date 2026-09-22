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
from .membership import MembershipChangeRefused, leave_workspace
from .membership_sync import MembershipSyncError, push_workspace_members
from .serializers import WorkspaceSerializer
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
        ).distinct()

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

    def get_permissions(self):
        # Any member may leave, so the owner-only rule for writes doesn't
        # apply to it. Decided here rather than on the @action, which only
        # takes effect when the route comes from the router.
        if self.action == 'leave':
            return []
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
