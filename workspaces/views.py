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
from .membership_sync import MembershipSyncError, push_workspace_members
from .serializers import WorkspaceSerializer
from .permissions import IsOwner
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
    permission_classes = [IsOwner]
    filterset_class = WorkspaceFilter
    search_fields = ['name']
    ordering_fields = ['created_at', 'name']

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.profile)

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

        paginator = self.pagination_class()
        page_size = min(paginator.get_page_size(request), 100)
        page = int(request.query_params.get('page', 1))
        offset = (page - 1) * page_size

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*) FROM workspaces_meeting,
                     plainto_tsquery('english', %s) query
                WHERE search_vector @@ query
                  AND workspace_id IN (
                    SELECT id FROM workspaces_workspace WHERE owner_id = %s
                  )
            """, [query, request.profile.id])

            count_result = cursor.fetchone()
            total_count = count_result[0] if count_result else 0

            if total_count == 0:
                return Response({
                    "count": 0,
                    "next": None,
                    "previous": None,
                    "results": []
                })

            cursor.execute("""
                SELECT
                    'meeting' as type,
                    id::text,
                    title as name,
                    ts_rank_cd(search_vector, query) as rank,
                    'workspace_id' as parent_field,
                    workspace_id::text as parent_id
                FROM workspaces_meeting,
                     plainto_tsquery('english', %s) query
                WHERE search_vector @@ query
                  AND workspace_id IN (
                    SELECT id FROM workspaces_workspace WHERE owner_id = %s
                  )
                ORDER BY rank DESC
                OFFSET %s LIMIT %s;
            """, [query, request.profile.id, offset, page_size])

            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        return Response({
            "count": total_count,
            "next": self._get_next_link(page, page_size, total_count),
            "previous": self._get_previous_link(page),
            "results": results
        })

    def _get_next_link(self, page, page_size, total_count):
        if page * page_size < total_count:
            return f"?page={page + 1}&limit={page_size}"
        return None

    def _get_previous_link(self, page):
        if page > 1:
            return f"?page={page - 1}"
        return None
