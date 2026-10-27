# workspaces/serializers.py
from rest_framework import serializers
from .models import Workspace, WorkspaceMembership

def _display_name(profile):
    if profile is None:
        return ''
    full = ' '.join(filter(None, [profile.first_name, profile.last_name])).strip()
    return full or (profile.email or '')


class WorkspaceSerializer(serializers.ModelSerializer):
    # Meetings are deliberately NOT embedded: doing so serialized every
    # meeting's full transcript per workspace (N+1 queries + huge payloads)
    # and no consumer read them — the app loads meetings from recall-server.

    # Who owns it, how many people are in it, and what this viewer is. Names
    # are only unique per owner now, so someone in two workspaces both called
    # "Personal" needs to be told whose is whose.
    owner_name = serializers.SerializerMethodField()
    owner_email = serializers.SerializerMethodField()
    member_count = serializers.SerializerMethodField()
    my_role = serializers.SerializerMethodField()

    class Meta:
        model = Workspace
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'owner',
                            'owner_name', 'owner_email', 'member_count', 'my_role']

    def _active(self, obj):
        # Uses the prefetched memberships (WorkspaceViewSet.get_queryset), so
        # a list of workspaces stays two queries rather than two per row.
        return [m for m in obj.memberships.all()
                if m.status == WorkspaceMembership.STATUS_ACTIVE and m.profile_id]

    def _first_owner(self, obj):
        owners = [m for m in self._active(obj) if m.role == WorkspaceMembership.ROLE_OWNER]
        owners.sort(key=lambda m: (m.joined_at or m.created_at, m.created_at))
        return owners[0].profile if owners else None

    def get_owner_name(self, obj):
        return _display_name(self._first_owner(obj))

    def get_owner_email(self, obj):
        owner = self._first_owner(obj)
        return (owner.email if owner else '') or ''

    def get_member_count(self, obj):
        return len(self._active(obj))

    def get_my_role(self, obj):
        profile = getattr(self.context.get('request'), 'profile', None)
        if profile is None:
            return None
        for membership in self._active(obj):
            if membership.profile_id == profile.id:
                return membership.role
        return None

    def validate_recording_retention_days(self, value):
        """Only an owner sets how long this workspace keeps recordings.

        `fields = '__all__'` makes every column writable by default, so
        without this any member could shorten a workspace's retention and
        start deleting other people's recordings. Role comes from the same
        active-membership list `my_role` reads, so the answer here and the
        answer the UI shows cannot disagree.

        None is allowed and means "unset": the workspace stops overriding and
        each recording falls back to its own recorder's profile.
        """
        if value is None:
            pass
        elif value < 1:
            raise serializers.ValidationError('Retention must be at least one day.')
        elif value > 3650:
            raise serializers.ValidationError('Retention cannot exceed 3650 days (10 years).')

        if self.instance is None:
            # On create there are no members yet; the creator becomes owner.
            return value

        profile = getattr(self.context.get('request'), 'profile', None)
        role = None
        if profile is not None:
            for membership in self._active(self.instance):
                if membership.profile_id == profile.id:
                    role = membership.role
                    break
        if role != WorkspaceMembership.ROLE_OWNER:
            raise serializers.ValidationError(
                'Only a workspace owner can change how long recordings are kept.')
        return value

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



class WorkspaceMembershipSerializer(serializers.ModelSerializer):
    """A member or a pending invite, as the members screen shows them."""

    name = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()
    profile_id = serializers.UUIDField(read_only=True, allow_null=True)

    class Meta:
        model = WorkspaceMembership
        fields = ['id', 'profile_id', 'name', 'email', 'role', 'status', 'joined_at', 'created_at',
                  'invite_expires_at']
        read_only_fields = fields

    def get_name(self, obj):
        if obj.profile_id:
            full = ' '.join(filter(None, [obj.profile.first_name, obj.profile.last_name])).strip()
            return full or (obj.profile.email or '')
        return ''

    def get_email(self, obj):
        return (obj.profile.email if obj.profile_id else obj.invited_email) or ''
