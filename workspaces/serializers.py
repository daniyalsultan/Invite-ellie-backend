# workspaces/serializers.py
from rest_framework import serializers
from .models import Workspace, Folder, Meeting

class MeetingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Meeting
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'status']

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