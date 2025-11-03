# workspaces/views.py
from rest_framework import viewsets, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, OpenApiParameter
from .models import Workspace, Folder, Meeting
from .serializers import WorkspaceSerializer, FolderSerializer, MeetingSerializer
from .permissions import IsOwner
from .filters import WorkspaceFilter, FolderFilter, MeetingFilter
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
    permission_classes = [IsOwner]
    filterset_class = FolderFilter
    search_fields = ['name']
    ordering_fields = ['created_at', 'name']

    def get_queryset(self):
        return self.queryset.filter(workspace__owner=self.request.profile)


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