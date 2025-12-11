import jwt
import logging
from django.http import JsonResponse
from core.supabase import supabase_service
from django.conf import settings
from accounts.models import Profile
from django_guid import get_guid


class SupabaseJWTAuthentication:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        logging.getLogger().correlation_id = get_guid()
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            request.user_id = None
            request.is_authenticated = False
            request.profile = None
            return self.get_response(request)

        token = auth_header.split(' ')[1]

        try:
            payload = jwt.decode(
                token,
                settings.SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                audience="authenticated",
                options={"verify_exp": True}
            )
            profile = Profile.objects.get(id=payload['sub'], is_active=True)
            profile.is_authenticated = True
            request.profile = profile
            request.user_id = payload['sub']
            request.user_email = payload.get('email')
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token expired"}, status=401)
        except jwt.InvalidAudienceError:
            return JsonResponse({"error": "Invalid audience"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)
        except Profile.DoesNotExist:
            return JsonResponse({"error": "Invalid credentials or email verification pending"}, status=401)            

        return self.get_response(request)