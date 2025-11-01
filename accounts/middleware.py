import jwt
from django.http import JsonResponse
from core.supabase import supabase_service
from django.conf import settings
from accounts.models import Profile

class SupabaseJWTAuthentication:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            request.user_id = None
            request.is_authenticated = False
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
            profile = Profile.objects.get(id=payload['sub'])
            profile.is_authenticated = True
            request.user = profile
            request.is_authenticated = True
            request.user_id = payload['sub']
            request.user_email = payload.get('email')
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token expired"}, status=401)
        except jwt.InvalidAudienceError:
            return JsonResponse({"error": "Invalid audience"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)

        return self.get_response(request)