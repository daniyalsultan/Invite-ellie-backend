from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from core.supabase import supabase, supabase_service
from .models import Profile
from .serializers import ProfileSerializer
import json
import jwt
import os

# === AUTH ENDPOINTS ===
@csrf_exempt
def register(request):
    if request.method != 'POST':
        return JsonResponse({"error": "POST required"}, status=405)
    data = json.loads(request.body)
    try:
        res = supabase.auth.sign_up({
            "email": data['email'],
            "password": data['password'],
            "options": {
                "data": {"full_name": data.get('full_name', '')}
            }
        })
        return JsonResponse({
            "user_id": res.user.id,
            "message": "Check your email to confirm"
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def login(request):
    if request.method != 'POST':
        return JsonResponse({"error": "POST required"}, status=405)
    data = json.loads(request.body)
    try:
        res = supabase.auth.sign_in_with_password({
            "email": data['email'],
            "password": data['password']
        })
        return JsonResponse({
            "access_token": res.session.access_token,
            "refresh_token": res.session.refresh_token,
            "user_id": res.user.id
        })
    except Exception as e:
        return JsonResponse({"error": "Invalid credentials"}, status=401)

@csrf_exempt
def sso_login(request, provider):
    if provider not in ['google', 'microsoft']:
        return JsonResponse({"error": "Invalid provider"}, status=400)
    try:
        res = supabase.auth.sign_in_with_oauth({
            "provider": provider,
            "options": {"redirect_to": "http://localhost:3000/auth/callback"}
        })
        return JsonResponse({"url": res.url})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

# === PROFILE ENDPOINTS ===
class ProfileView(APIView):
    def get(self, request):
        if not request.user_id:
            return Response({"error": "Unauthorized"}, status=401)
        try:
            profile = Profile.objects.get(id=request.user_id)
            serializer = ProfileSerializer(profile)
            return Response(serializer.data)
        except Profile.DoesNotExist:
            return Response({"error": "Profile not found"}, status=404)

    def patch(self, request):
        if not request.user_id:
            return Response({"error": "Unauthorized"}, status=401)
        try:
            profile = Profile.objects.get(id=request.user_id)
            serializer = ProfileSerializer(profile, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        except Profile.DoesNotExist:
            return Response({"error": "Profile not found"}, status=404)