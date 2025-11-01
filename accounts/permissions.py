# accounts/permissions.py
from rest_framework.permissions import BasePermission
import jwt
from django.conf import settings

# class IsSupabaseAuthenticated(BasePermission):
#     def has_permission(self, request, view):
#         token = request.headers.get('Authorization', '').replace('Bearer ', '')
#         if not token:
#             return False
#         try:
#             payload = jwt.decode(token, settings.SUPABASE_JWT_SECRET, algorithms=["HS256"])
#             request.user = type('User', (), {'id': payload['sub'], 'email': payload['email']})
#             return True
#         except:
#             return False


class IsSupabaseAuthenticated(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)