# accounts/serializers.py
from rest_framework import serializers
from .models import Profile

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['id', 'email', 'first_name', 'last_name', 'avatar_url', 'created_at' ,
                  'company' , 'position' , 'audience' , 'purpose']
        read_only_fields = ['id', 'created_at', 'email']

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