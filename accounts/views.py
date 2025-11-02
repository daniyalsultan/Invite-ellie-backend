import jwt
import logging
import traceback

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from drf_spectacular.utils import extend_schema, OpenApiResponse

from django.http import JsonResponse
from django.conf import settings

from accounts.permissions import IsSupabaseAuthenticated
from core.supabase import supabase

from .models import Profile
from .serializers import (
    EmailConfirmationSerializer, EmailSerializer, PasswordResetSerializer, RegisterSerializer, LoginSerializer, ProfileSerializer
)

logger = logging.getLogger(__name__)

class RegisterView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        tags=['auth'],
        request=RegisterSerializer,
        description="Register a new user",
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            res = supabase.auth.sign_up({
                "email": serializer.validated_data['email'],
                "password": serializer.validated_data['password'],
            })
            return Response({
                "user_id": res.user.id,
                "message": "Check your email to confirm"
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.critical(traceback.format_exc())
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        tags=['auth'],
        request=LoginSerializer,
        description="Login user",
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            res = supabase.auth.sign_in_with_password({
                "email": serializer.validated_data['email'],
                "password": serializer.validated_data['password']
            })
            return Response({
                "access_token": res.session.access_token,
                "refresh_token": res.session.refresh_token,
                "user_id": res.user.id,
                "expires_in": res.session.expires_in
            })
        except:
            logger.critical(traceback.format_exc())
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class GoogleSSOView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        tags=['auth'],
        description="Google SSO",
    )
    def get(self, request):
        try:
            res = supabase.auth.sign_in_with_oauth({
                "provider": "google",
                "options": {"redirect_to": "http://localhost:3000/auth/callback"}
            })
            return Response({"url": res.url})
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(APIView):
    permission_classes = [IsSupabaseAuthenticated]

    @extend_schema(
        tags=['auth'],
        description="Get profile",
    )
    def get(self, request):
        profile = Profile.objects.get(id=request.profile.id)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data)

    @extend_schema(
        tags=['auth'],
        request=ProfileSerializer,
        description="Update profile",
    )
    def patch(self, request):
        profile = Profile.objects.get(id=request.profile.id)
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetView(APIView):
    """Password Reset"""
    permission_classes = [AllowAny]

    @extend_schema(
        tags=['auth'],
        request=EmailSerializer,
        description="Reset the password for the user",
    )
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            supabase.auth.reset_password_for_email(serializer.validated_data['email'])
            return Response({"message": "Reset link sent"})
        except Exception as e:
            logger.critical(traceback.format_exc())
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    """ Confirm new password with token from email """
    @extend_schema(
        tags=['auth'],
        request=PasswordResetSerializer,
        description="Reset the password against the token",
    )
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Verify OTP + update password
            res = supabase.auth.verify_otp({
                "type": "recovery",
                "token": serializer.validated_data['token'],
            })
            supabase.auth.update_user({"password": serializer.validated_data['password']})
            logger.info("Password reset successful", extra={'user_id': res.user.id})
            return Response({"message": "Password reset successful"})
        except Exception as e:
            logger.critical(traceback.format_exc())
            return Response({"error": "Invalid or expired token"}, status=400)

class ResendConfirmationView(APIView):
    """Resend email confirmation link (if user didn't receive it)"""
    permission_classes = [AllowAny]

    @extend_schema(
        tags=['auth'],
        request=EmailSerializer,
        description="Resend account confirmation link",
    )
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Supabase: Resend confirmation
            res = supabase.auth.resend({
                "type": "signup",
                "email": serializer.validated_data['email'],
                "options": {
                    "email_redirect_to": "http://localhost:3000/auth/confirm"
                }
            })
            return Response({"message": "Confirmation email sent"})
        except Exception as e:
            logger.critical(traceback.format_exc())
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ConfirmEmailView(APIView):
    """Verify email from link (called by frontend after redirect)"""

    permission_classes = [AllowAny]

    @extend_schema(
        tags=['auth'],
        request=EmailConfirmationSerializer,
        description="Email confirmation",
    )
    def post(self, request):
        serializer = EmailConfirmationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            res = supabase.auth.verify_otp({
                "type": "email",
                "token": serializer.validated_data['token'],
                "email": serializer.validated_data['email']
            })
            return Response({
                "message": "Email confirmed",
                "access_token": res.session.access_token,
                "refresh_token": res.session.refresh_token,
                "user_id": res.user.id,
                "expires_in": res.session.expires_in
            })
        except Exception as e:
            logger.critical(traceback.format_exc())
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)