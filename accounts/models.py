from django.db.models import (
    Model,
    UUIDField,
    EmailField,
    CharField,
    URLField,
    BooleanField,
    DateTimeField,
)

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import uuid

from accounts.choices import AudienceChoices, PurposeChoices

class ProfileManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        raise NotImplementedError("Use Supabase Auth to create users")

    def create_superuser(self, email, password=None, **extra_fields):
        raise NotImplementedError("Use Supabase Auth to create users")

class Profile(Model):
    """
    Mirrors Supabase auth.users + raw_user_meta_data
    """
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = EmailField(unique=True)
    first_name = CharField(max_length=255, blank=True)
    last_name = CharField(max_length=255, blank=True)
    avatar_url = URLField(blank=True, null=True)

    company = CharField(max_length=255, blank=True)
    position = CharField(max_length=255, blank=True)
    audience = CharField(choices=AudienceChoices.choices, max_length=50, blank=True)
    purpose = CharField(choices=PurposeChoices.choices, max_length=50, blank=True)

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