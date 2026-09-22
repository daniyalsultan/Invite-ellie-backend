# workspaces/serializers.py
from rest_framework import serializers
from .models import Workspace, WorkspaceMembership

class WorkspaceSerializer(serializers.ModelSerializer):
    # Meetings are deliberately NOT embedded: doing so serialized every
    # meeting's full transcript per workspace (N+1 queries + huge payloads)
    # and no consumer read them — the app loads meetings from recall-server.

    class Meta:
        model = Workspace
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'owner']

    def validate_name(self, value):
        # Replaces the old (owner, name) database constraint: a person can't
        # own two workspaces with the same name. Checked against the
        # workspaces they are an active owner of, so it survives sharing and
        # ownership transfer, which a single-owner constraint could not.
        request = self.context.get('request')
        profile = getattr(request, 'profile', None)
        if profile is None:
            return value
        clashes = Workspace.objects.filter(
            name=value,
            memberships__profile=profile,
            memberships__role=WorkspaceMembership.ROLE_OWNER,
            memberships__status=WorkspaceMembership.STATUS_ACTIVE,
        )
        if self.instance is not None:
            clashes = clashes.exclude(pk=self.instance.pk)
        if clashes.exists():
            raise serializers.ValidationError('You already have a workspace with this name.')
        return value

