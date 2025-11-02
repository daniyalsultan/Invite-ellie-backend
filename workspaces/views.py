from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from .models import Workspace, Folder, Meeting
from .serializers import WorkspaceSerializer, FolderSerializer, MeetingSerializer
from .permissions import IsOwner
import logging

logger = logging.getLogger(__name__)

@extend_schema(tags=['workspaces'])
class WorkspaceViewSet(viewsets.ModelViewSet):
    queryset = Workspace.objects.all()
    serializer_class = WorkspaceSerializer
    permission_classes = [IsOwner]

    def perform_create(self, serializer):
        serializer.save(owner=self.request.profile)

    @extend_schema(tags=['workspaces'])
    @action(detail=True, methods=['get'])
    def stats(self, request, pk=None):
        workspace = self.get_object()
        folder_count = workspace.folders.count()
        meeting_count = Meeting.objects.filter(folder__workspace=workspace).count()
        return Response({
            'folders': folder_count,
            'meetings': meeting_count,
        })


@extend_schema(tags=['folders'])
class FolderViewSet(viewsets.ModelViewSet):
    queryset = Folder.objects.all()
    serializer_class = FolderSerializer
    permission_classes = [IsOwner]

    def get_queryset(self):
        return self.queryset.filter(workspace__owner=self.request.profile)

    def perform_create(self, serializer):
        workspace = Workspace.objects.get(id=self.request.data['workspace'], owner=self.request.profile)
        serializer.save(workspace=workspace)


@extend_schema(tags=['meetings'])
class MeetingViewSet(viewsets.ModelViewSet):
    queryset = Meeting.objects.all()
    serializer_class = MeetingSerializer
    permission_classes = [IsOwner]

    def get_queryset(self):
        return self.queryset.filter(folder__workspace__owner=self.request.profile)

    def perform_create(self, serializer):
        folder = Folder.objects.get(id=self.request.data['folder'], workspace__owner=self.request.profile)
        serializer.save(folder=folder)