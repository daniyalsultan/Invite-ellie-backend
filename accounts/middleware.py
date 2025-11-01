import jwt
from django.http import JsonResponse
from core.supabase import supabase_service
import os

class SupabaseJWTAuthentication:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if token:
            try:
                payload = jwt.decode(token, os.getenv("SUPABASE_JWT_SECRET"), algorithms=["HS256"])
                request.user_id = payload['sub']
                profile = supabase_service.table("profiles").select("email, full_name").eq("id", request.user_id).single().execute()
                request.user = profile.data
            except:
                pass  # Invalid token
        else:
            request.user_id = None
        return self.get_response(request)