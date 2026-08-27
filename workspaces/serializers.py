# workspaces/serializers.py
from rest_framework import serializers
from .models import Workspace

class WorkspaceSerializer(serializers.ModelSerializer):
    # Meetings are deliberately NOT embedded: doing so serialized every
    # meeting's full transcript per workspace (N+1 queries + huge payloads)
    # and no consumer read them — the app loads meetings from recall-server.

    class Meta:
        model = Workspace
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'owner']
