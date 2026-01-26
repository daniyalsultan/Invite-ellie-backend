# workspaces/serializers.py
from rest_framework import serializers
from .models import Workspace, Folder, Meeting

class MeetingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Meeting
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'status']

class MeetingExportSerializer(serializers.ModelSerializer):
    folder_name = serializers.CharField(source='folder.name', read_only=True)
    workspace_name = serializers.CharField(source='folder.workspace.name', read_only=True)
    duration_formatted = serializers.SerializerMethodField()
    created_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S')
    updated_at = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S')

    class Meta:
        model = Meeting
        fields = [
            'id',
            'title',
            'transcript',
            'summary',
            'highlights',
            'action_items',
            'participants',
            'status',
            'duration',
            'duration_formatted',
            'held_at',
            'created_at',
            'updated_at',
            'folder_name',
            'workspace_name',
            # Add audio_url / video_url if you store signed links
        ]

    def get_duration_formatted(self, obj):
        if obj.duration:
            minutes = int(obj.duration.total_seconds() // 60)
            seconds = int(obj.duration.total_seconds() % 60)
            return f"{minutes}m {seconds}s"
        return "N/A"

class FolderSerializer(serializers.ModelSerializer):
    meetings = MeetingSerializer(many=True, read_only=True)

    class Meta:
        model = Folder
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']

class WorkspaceSerializer(serializers.ModelSerializer):
    folders = FolderSerializer(many=True, read_only=True)

    class Meta:
        model = Workspace
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'owner']