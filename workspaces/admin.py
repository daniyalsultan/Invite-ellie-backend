# workspaces/admin.py
from django.contrib import admin
from .models import Workspace, Folder, Meeting

@admin.register(Workspace)
class WorkspaceAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('name', 'owner', 'folder_count', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'owner__email')
    readonly_fields = ('id', 'created_at', 'updated_at')
    inlines = []

    def folder_count(self, obj):
        return obj.folders.count()
    folder_count.short_description = "Folders"

@admin.register(Folder)
class FolderAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('name', 'workspace', 'is_pinned', 'meeting_count', 'created_at', 'workspace__owner__email')
    list_filter = ('is_pinned', 'created_at')
    search_fields = ('name', 'workspace__name', 'workspace__owner__email')
    readonly_fields = ('id', 'created_at', 'updated_at')

    def meeting_count(self, obj):
        return obj.meetings.count()
    meeting_count.short_description = "Meetings"

@admin.register(Meeting)
class MeetingAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('title', 'folder', 'status', 'duration', 'updated_at', 'folder__workspace__owner__email')
    list_filter = ('status', 'updated_at')
    search_fields = ('title', 'folder__name', 'folder__workspace__owner__email')
    readonly_fields = ('id', 'audio_url', 'updated_at')
    raw_id_fields = ('folder',)
