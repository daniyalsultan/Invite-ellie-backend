# accounts/serializers.py
from rest_framework import serializers
from .models import Profile

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['id', 'email', 'full_name', 'avatar_url', 'created_at']
        read_only_fields = ['id', 'created_at']