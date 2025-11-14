from django.db.models import (
    Model, UUIDField, EmailField, CharField, URLField, BooleanField, DateTimeField,
    ImageField, TextField, ForeignKey, CASCADE, Index, JSONField
)
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import uuid
from django.core.files.uploadedfile import InMemoryUploadedFile
from PIL import Image
from io import BytesIO
import sys

from accounts.choices import ActivityLogTypes, AudienceChoices, NotificationStatus, PurposeChoices

class ProfileManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        raise NotImplementedError("Use Supabase Auth to create users")

    def create_superuser(self, email, password=None, **extra_fields):
        raise NotImplementedError("Use Supabase Auth to create users")

def avatar_upload_path(instance, filename):
    return f"avatars/{instance.id}.webp"

class Profile(Model):
    """
    Mirrors Supabase auth.users + raw_user_meta_data
    """
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = EmailField()
    first_name = CharField(max_length=255, blank=True, null=True)
    last_name = CharField(max_length=255, blank=True, null=True)
    avatar = ImageField(
        upload_to=avatar_upload_path,
        blank=True,
        null=True,
        help_text="User profile picture",
    )
    avatar_url = TextField(blank=True, null=True)

    company = CharField(max_length=255, blank=True, null=True)
    company_notes = CharField(max_length=500, blank=True, null=True)
    position = CharField(max_length=255, blank=True, null=True)
    audience = CharField(choices=AudienceChoices.choices, max_length=50, blank=True, null=True)
    purpose = CharField(max_length=200, blank=True, null=True)

    sso_provider = CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="SSO provider: google, microsoft, email, etc."
    )

    # Supabase metadata
    is_active = BooleanField(default=True)
    confirmed_at = DateTimeField(null=True, blank=True)
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)

    objects = ProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    class Meta:
        db_table = 'profiles'
        managed = True  # Let Django manage migrations

    def log_activity(self, activity_type, description, meta_data={}):
        ActivityLog.objects.create(
            profile=self,
            activity_type=activity_type,
            description=description,
            meta_data=meta_data
        )


class Notification(Model):
    message = TextField(blank=False, null=False)
    meta_data = TextField(blank=True, null=True)
    created_at = DateTimeField(auto_now_add=True)
    seen = BooleanField(default=False)

    notify_type = CharField(
        "Status of the notification, warning, success or error",
        choices=NotificationStatus.choices,
        max_length=20,
        default=NotificationStatus.SUCCESS,
    )

    owner = ForeignKey(Profile, on_delete=CASCADE, related_name='notifications')

    class Meta:
        ordering = ['-created_at']
        indexes = [
            Index(fields=['owner', '-created_at']),
            Index(fields=['seen']),
        ]

    def __str__(self):
        return f"{self.message[:30]} - {self.owner.email}"


class ActivityLog(Model):
    """
    Activity log model for tracking user actions and system events.

    Records user activities with categories, types, and object references
    for audit trails and activity monitoring.
    """
    profile = ForeignKey(Profile, on_delete=CASCADE, related_name='activity_logs')
    activity_type = CharField(max_length=255, choices=ActivityLogTypes.choices)
    timestamp = DateTimeField(auto_now_add=True)
    description = TextField(null=True, blank=True)
    meta_data = JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            Index(fields=['profile', '-timestamp']),
            Index(fields=['activity_type']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.get_activity_type_display()} - {self.timestamp}"
