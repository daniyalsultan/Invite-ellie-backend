# workspaces/serializers.py
from rest_framework import serializers
from .models import Workspace, Folder, Meeting

class MeetingSerializer(serializers.ModelSerializer):
    workspace_name = serializers.CharField(source='workspace.name', read_only=True)

    class Meta:
        model = Meeting
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'status']

class MeetingExportSerializer(serializers.ModelSerializer):
    workspace_name = serializers.CharField(source='workspace.name', read_only=True, default=None)
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
            'paticipants',
            'status',
            'duration',
            'duration_formatted',
            'held_at',
            'created_at',
            'updated_at',
            'workspace_name',
        ]

    def get_duration_formatted(self, obj):
        if obj.duration:
            minutes = int(obj.duration.total_seconds() // 60)
            seconds = int(obj.duration.total_seconds() % 60)
            return f"{minutes}m {seconds}s"
        return "N/A"

class WorkspaceSerializer(serializers.ModelSerializer):
    # Meetings are deliberately NOT embedded: doing so serialized every
    # meeting's full transcript per workspace (N+1 queries + huge payloads)
    # and no consumer read them — the app loads meetings from recall-server.

    class Meta:
        model = Workspace
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'owner']
