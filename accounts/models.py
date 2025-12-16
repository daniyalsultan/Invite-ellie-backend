from django.db.models import (
    Model, UUIDField, EmailField, CharField, URLField, BooleanField, DateTimeField,
    ImageField, TextField, ForeignKey, CASCADE, Index, JSONField, OneToOneField, BigIntegerField, FloatField,
    DateField, SET_NULL
)
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import uuid
from django.core.files.uploadedfile import InMemoryUploadedFile
from PIL import Image
from io import BytesIO
import sys
from django.contrib.auth import get_user_model

from accounts.choices import ActivityLogTypes, AudienceChoices, NotificationType, PurposeChoices
from core import settings

User = get_user_model()

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

    first_login = BooleanField(default=True)
    show_tour = BooleanField(default=True)

    objects = ProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    stripe_customer_id = CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Stripe Customer ID (for paid users)"
    )
    stripe_subscription_id = CharField(max_length=100, blank=True, null=True)
    subscription_status = CharField(max_length=20, default='free')
    subscription_end_date = DateTimeField(null=True, blank=True)
    subscription_auto_renew = BooleanField(default=True)

    # GDPR deletion tracking
    deletion_requested_at = DateTimeField(null=True, blank=True, db_index=True)
    deletion_requested_by_ip = CharField(max_length=50, null=True, blank=True)  # String IP, no GenericIPAddressField
    deletion_type = CharField(max_length=20, choices=[
        ('IMMEDIATE', 'Immediate Deletion'),
        ('GRACE_PERIOD', '7-Day Grace Period')
    ], blank=True)
    data_exported = BooleanField(default=False)
    data_export_completed_at = DateTimeField(null=True, blank=True)
    deleted_at = DateTimeField(null=True, blank=True)
    deletion_completed_at = DateTimeField(null=True, blank=True)
    deletion_verified_at = DateTimeField(null=True, blank=True)

    # Legal hold support (Article 17(3))
    legal_hold = BooleanField(default=False, db_index=True)
    legal_hold_reason = TextField(blank=True)
    legal_hold_reason_user_facing = TextField(blank=True)
    legal_hold_case_number = CharField(max_length=100, blank=True)
    legal_hold_placed_at = DateTimeField(null=True, blank=True)
    legal_hold_placed_by = ForeignKey(
        User, null=True, blank=True, on_delete=SET_NULL,
        related_name='legal_holds_placed'
    )
    legal_hold_approved_by = ForeignKey(
        User, null=True, blank=True, on_delete=SET_NULL,
        related_name='legal_holds_approved'
    )
    retention_basis = CharField(max_length=200, blank=True)
    legal_hold_review_date = DateField(null=True, blank=True)

    # Multi-factor verification
    deletion_verification_token = CharField(max_length=128, blank=True)
    deletion_verification_sent_at = DateTimeField(null=True, blank=True)
    deletion_verification_confirmed_at = DateTimeField(null=True, blank=True)

    # Backup exclusion
    excluded_from_backups = BooleanField(default=False)
    backup_exclusion_verified_at = DateTimeField(null=True, blank=True)

    # Geographic scope
    user_country = CharField(max_length=2, blank=True)
    is_eu_resident = BooleanField(default=False)
    privacy_regulation = CharField(max_length=20, default='GDPR')



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

    def noftify(self, message, notify_type=NotificationType.SUCCESS, meta_data={}):
        Notification.objects.create(
            owner=self,
            message=message,
            notify_type=notify_type,
            meta_data=meta_data
        )


class Notification(Model):
    message = TextField(blank=False, null=False)
    meta_data = TextField(blank=True, null=True)
    created_at = DateTimeField(auto_now_add=True)
    seen = BooleanField(default=False)

    notify_type = CharField(
        "Status of the notification, warning, success or error",
        choices=NotificationType.choices,
        max_length=20,
        default=NotificationType.SUCCESS,
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
        return f"{self.profile.email} - {self.get_activity_type_display()} - {self.timestamp}"


class ProfileStorage(Model):
    """
    One-row-per-user: current storage snapshot.
    """
    user = OneToOneField(
        Profile, on_delete=CASCADE, related_name='storage'
    )
    total_bytes = BigIntegerField(default=0)
    total_mb = FloatField(default=0.0)
    # Optional breakdown (JSON for flexibility)
    breakdown = JSONField(default=dict, blank=True)
    calculated_at = DateTimeField(auto_now=True)
    # Optional: Supabase bucket size
    supabase_bytes = BigIntegerField(default=0)

    class Meta:
        verbose_name_plural = "User storage"

    def __str__(self):
        return f"{self.user.username} – {self.total_mb:.2f} MiB"


# Audit Log for deletions (separate model as per doc)
class DeletionAuditLog(Model):
    profile = ForeignKey(Profile, on_delete=SET_NULL, null=True)
    action = CharField(max_length=50)
    timestamp = DateTimeField(auto_now_add=True)
    metadata = JSONField(default=dict, blank=True)
    pseudonymized = BooleanField(default=False)
    pseudonymized_at = DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.action} - {self.timestamp}"