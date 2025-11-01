from django.contrib import admin

from .models import Profile

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('email', 'full_name', 'is_active', 'created_at')
    search_fields = ('email', 'full_name')
    readonly_fields = ('id', 'created_at', 'updated_at')