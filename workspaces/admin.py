# workspaces/admin.py
from django.contrib import admin
from .models import Workspace, WorkspaceMembership

@admin.register(Workspace)
class WorkspaceAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('name', 'owner', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'owner__email')
    readonly_fields = ('id', 'created_at', 'updated_at')



@admin.register(WorkspaceMembership)
class WorkspaceMembershipAdmin(admin.ModelAdmin):
    # Read-only: a change made here would skip the write-through to
    # recall-server's mirror. Change membership through the app.
    list_per_page = 50
    list_display = ('workspace', 'profile', 'invited_email', 'role', 'status', 'joined_at', 'created_at')
    list_filter = ('role', 'status')
    search_fields = ('workspace__name', 'profile__email', 'invited_email')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
