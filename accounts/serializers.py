# accounts/serializers.py
from django.conf import settings
from rest_framework import serializers
from .models import Profile
from django.core.validators import FileExtensionValidator
from django.core.files.storage import default_storage

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