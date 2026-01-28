# accounts/admin.py
from django_celery_beat.models import PeriodicTask, IntervalSchedule, CrontabSchedule, ClockedSchedule
from django_celery_beat.admin import PeriodicTaskAdmin
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import ActivityLog, Notification, Profile, ProfileStorage
from django.contrib.admin.models import LogEntry
from django import forms
from django.contrib import admin
from django.utils import timezone
from django.contrib.auth.models import User
from .models import Profile, DeletionAuditLog


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('action_time', 'user', 'content_type', 'object_repr', 'action_flag')
    list_filter = ('action_time', 'action_flag')
    search_fields = ('user__email', 'object_repr')
    readonly_fields = ('action_time', 'user', 'content_type', 'object_id', 'object_repr', 'action_flag', 'change_message')


class LegalHoldAdminForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = '__all__'
        widgets = {
            'legal_hold_reason': forms.Textarea(attrs={'rows': 3}),
            'legal_hold_reason_user_facing': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = kwargs.get('request')
        user = request.user if request else None

        # Only approvers/superusers can modify approval fields
        if user and not (user.is_superuser or user.groups.filter(name='Legal Hold Approvers').exists()):
            self.fields['legal_hold_approved_by'].disabled = True
            self.fields['legal_hold_approved_by'].help_text = "Only Legal Hold Approvers can set this field"



@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    form = LegalHoldAdminForm
    list_display = [
        'email',
        'legal_hold',
        'legal_hold_placed_at',
        'legal_hold_placed_by',
        'legal_hold_approved_by',
        'deletion_status_display',
        'subscription_status',
    ]
    list_filter = [
        'legal_hold',
        'subscription_status',
        'is_active',
        'deletion_type',
    ]
    search_fields = ['email', 'first_name', 'last_name']
    readonly_fields = [
        'id', 'email', 'created_at', 'updated_at',
        'deletion_requested_at', 'deletion_completed_at',
        'stripe_customer_id', 'stripe_subscription_id',
        'legal_hold_placed_at', 'legal_hold_placed_by',  # auto-filled
    ]

    # Custom method for deletion status (this fixes error 2)
    @admin.display(description="Deletion Status")
    def deletion_status_display(self, obj):
        if obj.deletion_completed_at:
            return format_html('<span style="color: red;">Deleted</span>')
        if obj.deletion_requested_at:
            days_elapsed = (timezone.now() - obj.deletion_requested_at).days
            if obj.deletion_type == 'GRACE_PERIOD':
                days_left = max(0, 7 - days_elapsed)
                return format_html(
                    '<span style="color: orange;">Pending ({} days left)</span>',
                    days_left
                )
            return format_html('<span style="color: red;">Immediate pending</span>')
        return format_html('<span style="color: green;">Active</span>')

    fieldsets = (
        ('Basic Info', {
            'fields': ('id', 'email', 'first_name', 'last_name', 'is_active')
        }),
        ('Legal Hold Controls', {
            'fields': (
                'legal_hold',
                'legal_hold_reason',
                'legal_hold_reason_user_facing',
                'legal_hold_case_number',
                'legal_hold_placed_at',
                'legal_hold_placed_by',
                'legal_hold_approved_by',
                'retention_basis',
                'legal_hold_review_date',
            ),
            'classes': ('collapse',),
        }),
        ('Deletion & Subscription', {
            'fields': (
                'deletion_requested_at', 'deletion_type', 'deletion_completed_at',
                'subscription_status', 'subscription_end_date', 'subscription_auto_renew'
            ),
        }),
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

    def save_model(self, request, obj, form, change):
        """
        Auto-populate placed_by / placed_at when legal_hold is turned ON
        Only allow approvers to set approved_by / approved_at
        """
        # If legal hold is newly enabled
        if obj.legal_hold and not obj.legal_hold_placed_at:
            obj.legal_hold_placed_at = timezone.now()
            obj.legal_hold_placed_by = request.user

        # Auto-approve if current user is allowed
        if obj.legal_hold:
            if request.user.is_superuser or request.user.groups.filter(name='Legal Hold Approvers').exists():
                obj.legal_hold_approved_by = request.user

        # Audit log every change to legal hold fields
        if change and any(f in form.changed_data for f in [
            'legal_hold', 'legal_hold_reason', 'legal_hold_case_number',
            'legal_hold_approved_by', 'legal_hold_placed_by'
        ]):
            from .models import DeletionAuditLog

            # Convert datetime to ISO string for JSON serialization
            placed_at_str = obj.legal_hold_placed_at.isoformat() if obj.legal_hold_placed_at else None

            DeletionAuditLog.objects.create(
                profile=obj,
                action='LEGAL_HOLD_UPDATED',
                metadata={
                    'legal_hold': obj.legal_hold,
                    'changed_by': request.user.username,
                    'placed_by': obj.legal_hold_placed_by.username if obj.legal_hold_placed_by else None,
                    'approved_by': obj.legal_hold_approved_by.username if obj.legal_hold_approved_by else None,
                    'placed_at': placed_at_str,      # now a string
                }
            )

        super().save_model(request, obj, form, change)

    def get_readonly_fields(self, request, obj=None):
        readonly = super().get_readonly_fields(request, obj)
        if not (request.user.is_superuser or request.user.groups.filter(name='Legal Hold Approvers').exists()):
            readonly += ('legal_hold_approved_by')
        return readonly

    def has_approve_permission(self, request, obj=None):
        return request.user.is_superuser or request.user.groups.filter(name='Legal Hold Approvers').exists()

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('message', 'owner', 'notify_type', 'seen', 'created_at')
    list_filter = ('notify_type', 'seen', 'created_at')
    search_fields = ('message', 'owner__email')

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('profile', 'get_activity_type_display', 'timestamp')
    list_filter = ('activity_type', 'timestamp')
    search_fields = ('profile__email', 'description')

@admin.register(ProfileStorage)
class ProfileStorageAdmin(admin.ModelAdmin):
    list_per_page = 10
    list_display = ('user', 'total_mb', 'supabase_bytes', 'calculated_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('calculated_at',)

class CustomPeriodicTaskAdmin(PeriodicTaskAdmin):
    list_per_page = 10
    list_display = ["name", "task", "enabled", "interval", "crontab", "last_run_at", "total_run_count"]
    list_filter = ["enabled", "task", "interval", "crontab"]
    search_fields = ["name", "task"]