# workspaces/admin.py
from django.contrib import admin
from .models import Workspace, Meeting

@admin.register(Workspace)
class WorkspaceAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('name', 'owner', 'meeting_count', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'owner__email')
    readonly_fields = ('id', 'created_at', 'updated_at')

    def meeting_count(self, obj):
        return obj.meetings.count()
    meeting_count.short_description = "Meetings"

@admin.register(Meeting)
class MeetingAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('title', 'workspace', 'status', 'duration', 'updated_at')
    list_filter = ('status', 'updated_at')
    search_fields = ('title', 'workspace__name', 'workspace__owner__email')
    readonly_fields = ('id', 'audio_url', 'updated_at')
    raw_id_fields = ('workspace',)
