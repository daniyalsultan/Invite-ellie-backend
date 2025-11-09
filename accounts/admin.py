# accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import ActivityLog, Notification, Profile
from django.contrib.admin.models import LogEntry

@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ('action_time', 'user', 'content_type', 'object_repr', 'action_flag')
    list_filter = ('action_time', 'action_flag')
    search_fields = ('user__email', 'object_repr')
    readonly_fields = ('action_time', 'user', 'content_type', 'object_id', 'object_repr', 'action_flag', 'change_message')


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('email', 'full_name', 'company', 'is_active', 'avatar_thumb', 'created_at')
    list_filter = ('is_active', 'created_at', 'audience', 'purpose')
    search_fields = ('email', 'first_name', 'last_name', 'company')
    readonly_fields = ('id', 'created_at', 'updated_at', 'avatar_url')
    fieldsets = (
        ('User Info', {'fields': ('email', 'first_name', 'last_name', 'avatar', 'avatar_url')}),
        ('Company', {'fields': ('company', 'position', 'audience', 'purpose')}),
        ('Metadata', {'fields': ('is_active', 'confirmed_at', 'created_at', 'updated_at')}),
    )
    ordering = ('-created_at',)

    def full_name(self, obj):
        return f"{obj.first_name or ''} {obj.last_name or ''}".strip() or "—"
    full_name.short_description = "Name"

    def avatar_thumb(self, obj):
        if obj.avatar_url:
            return format_html('<img src="{}" width="40" height="40" style="border-radius:50%;">', obj.avatar_url)
        return "—"
    avatar_thumb.short_description = "Avatar"

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('message', 'owner', 'notify_type', 'seen', 'created_at')
    list_filter = ('notify_type', 'seen', 'created_at')
    search_fields = ('message', 'owner__email')

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('profile', 'get_activity_type_display', 'timestamp')
    list_filter = ('activity_type', 'timestamp')
    search_fields = ('profile__email', 'description')