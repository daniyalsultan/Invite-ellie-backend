# accounts/serializers.py
from django.conf import settings
from rest_framework import serializers
from .models import Profile, Notification, ActivityLog
from django.core.validators import FileExtensionValidator
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import InMemoryUploadedFile
from PIL import Image
from io import BytesIO
import sys
import logging

logger = logging.getLogger(__name__)

class ProfileSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(
        required=False,
        allow_null=True,
        allow_empty_file=True,
        validators=[
            FileExtensionValidator(
                allowed_extensions=['jpg', 'jpeg', 'png', 'webp'],
                message="Only .jpg, .jpeg, .png, and .webp files are allowed."
            )
        ])
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = ['id', 'email', 'first_name', 'last_name', 'avatar_url', 'created_at' ,
                  'company' , 'position' , 'audience' , 'purpose', 'avatar']
        read_only_fields = ['id', 'created_at', 'email', 'avatar_url']

    def validate_avatar(self, value):
        """Validate image size as per the settings"""
        if value:
            max_size = settings.AVATAR_MAX_SIZE
            if value.size > max_size:
                raise serializers.ValidationError(
                    "Image size cannot exceed 5 MB."
                )
        return value

    def get_avatar_url(self, obj):
        if not obj.avatar:
            return None
        # Use custom method on storage
        return default_storage.signed_url(obj.avatar.name, expire=3600)

    # --- WRITE: preprocess + delete old ---
    def update(self, instance, validated_data):
        avatar_file = validated_data.pop('avatar', None)

        # 1. Delete old file (if exists and different)
        old_path = instance.avatar.name if instance.avatar else None
        if old_path and default_storage.exists(old_path):
            try:
                default_storage.delete(old_path)
                logger.info(f"Deleted old avatar: {old_path}")
            except Exception as e:
                logger.warning(f"Failed to delete old avatar {old_path}: {e}")

        # 2. If new file → preprocess
        if avatar_file:
            processed_file = self._process_image(avatar_file, instance.id)
            validated_data['avatar'] = processed_file

        # 3. Save
        return super().update(instance, validated_data)

    def _process_image(self, uploaded_file, user_id):
        """Resize, convert to WebP, return InMemoryUploadedFile"""
        img = Image.open(uploaded_file)

        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        img.thumbnail((400, 400), Image.Resampling.LANCZOS)

        buffer = BytesIO()
        img.save(buffer, format='WEBP', quality=85, optimize=True)
        buffer.seek(0)

        filename = f"{user_id}.webp"  # e.g. 123.webp

        return InMemoryUploadedFile(
            file=buffer,
            field_name='avatar',
            name=filename,
            content_type='image/webp',
            size=buffer.getbuffer().nbytes,
            charset=None,
        )

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=6, write_only=True)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class EmailConfirmationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    token = serializers.CharField(write_only=True)

class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'message', 'notify_type', 'created_at', 'seen', 'meta_data']
        read_only_fields = ['created_at']

class MarkSeenSerializer(serializers.Serializer):
    ids = serializers.ListField(
        child=serializers.IntegerField(required=True),
        allow_empty=False,
        min_length=1,
    )

class ActivityLogSerializer(serializers.ModelSerializer):
    activity_type_display = serializers.CharField(source='get_activity_type_display', read_only=True)

    class Meta:
        model = ActivityLog
        fields = ['id', 'activity_type', 'activity_type_display', 'timestamp', 'description', 'meta_data']
        read_only_fields = ['timestamp', 'activity_type_display']

