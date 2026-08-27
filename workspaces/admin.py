# workspaces/admin.py
from django.contrib import admin
from .models import Workspace

@admin.register(Workspace)
class WorkspaceAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('name', 'owner', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'owner__email')
    readonly_fields = ('id', 'created_at', 'updated_at')

