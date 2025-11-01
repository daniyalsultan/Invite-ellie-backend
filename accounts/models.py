from django.db import models

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import uuid

class ProfileManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        raise NotImplementedError("Use Supabase Auth to create users")

    def create_superuser(self, email, password=None, **extra_fields):
        raise NotImplementedError("Use Supabase Auth to create users")

class Profile(models.Model):
    """
    Mirrors Supabase auth.users + raw_user_meta_data
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=255, blank=True)
    last_name = models.CharField(max_length=255, blank=True)
    avatar_url = models.URLField(blank=True, null=True)

    # Supabase metadata
    is_active = models.BooleanField(default=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    class Meta:
        db_table = 'profiles'
        managed = True  # Let Django manage migrations