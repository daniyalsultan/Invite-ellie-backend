# workspaces/views.py
from rest_framework import viewsets, filters
from rest_framework.decorators import action
from rest_framework.response import Response
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

    @extend_schema(
        tags=['workspaces'],
        parameters=[
            OpenApiParameter(name='q', type=str, description='Search query', required=True),
            OpenApiParameter(name='limit', type=int, description='Max results (default 20)', required=False),
        ],
        responses={200: None}
    )
    def get(self, request):
        query = request.query_params.get('q', '').strip()
        limit = int(request.query_params.get('limit', 20))

        if not query:
            return Response({"results": []})

        # Raw SQL = fastest + full control
        with connection.cursor() as cursor:
            cursor.execute("""
                WITH search_results AS (
                    -- Meetings
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

                    -- Folders
                    SELECT
                        'folder' as type,
                        id::text,
                        name,
                        similarity(name, %s) as rank,
                        'workspace_id' as parent_field,
                        workspace_id::text as parent_id
                    FROM workspaces_folder
                    WHERE name % %s
                      AND workspace_id IN (
                        SELECT id FROM workspaces_workspace WHERE owner_id = %s
                      )

                    ORDER BY rank DESC
                    LIMIT %s
                )
                SELECT type, id, name, rank, parent_field, parent_id
                FROM search_results
                ORDER BY rank DESC;
            """, [query, request.user.id, query, query, request.user.id, limit])

            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        return Response({"query": query, "results": results})