# workspaces/views.py
from rest_framework import viewsets, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, OpenApiParameter

from accounts.permissions import IsSupabaseAuthenticated
from .models import Workspace, Folder, Meeting
from .serializers import WorkspaceSerializer, FolderSerializer, MeetingSerializer
from .permissions import IsOwner, IsWorkspaceOwner
from .filters import WorkspaceFilter, FolderFilter, MeetingFilter
from django.db import connection
from rest_framework.views import APIView
import logging

logger = logging.getLogger(__name__)

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
        serializer.save(owner=self.request.profile)


@extend_schema(tags=['folders'])
class FolderViewSet(viewsets.ModelViewSet):
    queryset = Folder.objects.all()
    serializer_class = FolderSerializer
    permission_classes = [IsWorkspaceOwner]
    filterset_class = FolderFilter
    search_fields = ['name']
    ordering_fields = ['created_at', 'name']

    def get_queryset(self):
        return Folder.objects.filter(
            workspace__owner=self.request.profile
        ).order_by('-is_pinned', '-created_at')


@extend_schema(tags=['meetings'])
class MeetingViewSet(viewsets.ModelViewSet):
    queryset = Meeting.objects.all()
    serializer_class = MeetingSerializer
    permission_classes = [IsOwner]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_class = MeetingFilter
    search_fields = ['title', 'transcript', 'summary']
    ordering_fields = ['created_at', 'title']

    def get_queryset(self):
        return self.queryset.filter(folder__workspace__owner=self.request.profile)

    @extend_schema(
        parameters=[
            OpenApiParameter(name='created_at__gte', type=str, description='ISO date (YYYY-MM-DD)'),
            OpenApiParameter(name='search', type=str, description='Search title, transcript, summary'),
        ]
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

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
        page_size = min(paginator.get_page_size(request), 100)  # Enforce max 100
        page = int(request.query_params.get('page', 1))
        offset = (page - 1) * page_size

        with connection.cursor() as cursor:
            cursor.execute("""
                WITH search_results AS (
                    SELECT 1 FROM workspaces_meeting,
                         plainto_tsquery('english', %s) query
                    WHERE search_vector @@ query
                      AND folder_id IN (
                        SELECT id FROM workspaces_folder
                        WHERE workspace_id IN (
                          SELECT id FROM workspaces_workspace WHERE owner_id = %s
                        )
                      )
                    UNION ALL
                    SELECT 1 FROM workspaces_folder
                    WHERE name ILIKE %s
                      AND workspace_id IN (
                        SELECT id FROM workspaces_workspace WHERE owner_id = %s
                      )
                )
                SELECT COUNT(*) FROM search_results;
            """, [query, request.profile.id, f'%{query}%', request.profile.id])

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
                WITH search_results AS (
                    SELECT
                        'meeting' as type,
                        id::text,
                        title as name,
                        ts_rank_cd(search_vector, query) as rank,
                        'folder_id' as parent_field,
                        folder_id::text as parent_id
                    FROM workspaces_meeting,
                         plainto_tsquery('english', %s) query
                    WHERE search_vector @@ query
                      AND folder_id IN (
                        SELECT id FROM workspaces_folder
                        WHERE workspace_id IN (
                          SELECT id FROM workspaces_workspace WHERE owner_id = %s
                        )
                      )

                    UNION ALL

                    SELECT
                        'folder' as type,
                        id::text,
                        name,
                        similarity(name, %s) as rank,
                        'workspace_id' as parent_field,
                        workspace_id::text as parent_id
                    FROM workspaces_folder
                    WHERE name ILIKE %s
                      AND workspace_id IN (
                        SELECT id FROM workspaces_workspace WHERE owner_id = %s
                      )
                )
                SELECT type, id, name, rank, parent_field, parent_id
                FROM search_results
                ORDER BY rank DESC
                OFFSET %s LIMIT %s;
            """, [query, request.profile.id, query, f'%{query}%', request.profile.id, offset, page_size])

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