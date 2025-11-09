import jwt
import logging
import traceback
import os
import uuid

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter

from django.http import JsonResponse
from django.conf import settings
from django.core.files.storage import default_storage

from accounts.permissions import IsSupabaseAuthenticated
from core.supabase import supabase
from .models import Profile
from .serializers import (
    EmailConfirmationSerializer, EmailSerializer, PasswordResetSerializer, RefreshTokenSerializer, RegisterSerializer, LoginSerializer, ProfileSerializer
)

logger = logging.getLogger(__name__)

class RegisterView(APIView):
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

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
    serializer_class = LoginSerializer

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


class ProfileView(APIView):
    permission_classes = [IsSupabaseAuthenticated]
    serializer_class = ProfileSerializer

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
    @action(
        detail=False, methods=["patch"], parser_classes=[MultiPartParser, FormParser]
    )
    # views.py
    def patch(self, request):
        profile = request.profile
        serializer = ProfileSerializer(profile, data=request.data, partial=True)

        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        avatar_file = request.FILES.get('avatar')
        if avatar_file:
            # Validate file size and type
            max_size = 5 * 1024 * 1024  # 5MB
            if avatar_file.size > max_size:
                return Response({"avatar": ["File too large. Max 5MB allowed."]}, status=400)

            allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
            if avatar_file.content_type not in allowed_types:
                return Response({"avatar": ["Invalid file type. Only images allowed."]}, status=400)

            try:
                # Delete old avatar if exists
                if profile.avatar:
                    try:
                        default_storage.delete(profile.avatar.name)
                        logger.info(f"Deleted old avatar: {profile.avatar.name}")
                    except Exception as e:
                        logger.warning(f"Failed to delete old avatar: {e}")

                # Generate path and save new avatar
                file_ext = os.path.splitext(avatar_file.name)[1]
                unique_filename = f"{uuid.uuid4().hex[:8]}{file_ext}"
                save_path = f"avatars/{request.profile.id}/{unique_filename}"

                # Save file
                saved_path = default_storage.save(save_path, avatar_file)

                # Update profile
                profile.avatar = saved_path
                profile.save()

                # Get URL (this will be handled by the storage backend)
                logger.info(f"Avatar saved successfully: {saved_path}")

                return Response(ProfileSerializer(profile).data)

            except Exception as e:
                logger.error(f"Avatar upload failed: {e}", exc_info=True)
                return Response({"avatar": [f"Upload failed: {str(e)}"]}, status=500)

        # If no avatar file, just save other profile data
        serializer.save()
        return Response(ProfileSerializer(profile).data)

class PasswordResetView(APIView):
    """Password Reset"""
    permission_classes = [AllowAny]
    serializer_class = EmailSerializer

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
    permission_classes = [AllowAny]
    serializer_class = PasswordResetSerializer

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
    serializer_class = EmailSerializer

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
    serializer_class = EmailConfirmationSerializer

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
                "expires_in": res.session.expires_in,
                "perform_onboarding": True
            })
        except Exception as e:
            logger.critical(traceback.format_exc())
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

class RefreshTokenView(APIView):
    """
    Exchange a valid refresh token for a new access token + refresh token
    """
    permission_classes = [AllowAny]
    serializer_class = RefreshTokenSerializer

    @extend_schema(
        tags=['auth'],
        request=RefreshTokenSerializer,
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        refresh_token = serializer.validated_data['refresh_token']

        try:
            # Exchange refresh token via Supabase
            res = supabase.auth.refresh_session(refresh_token)
            logger.info("Token refreshed", extra={'user_id': res.user.id})
            return Response({
                "access_token": res.session.access_token,
                "refresh_token": res.session.refresh_token,
                "expires_in": res.session.expires_in
            })
        except Exception as e:
            logger.warning("Invalid refresh token", exc_info=True)
            return Response({"error": "Invalid or expired refresh token"}, status=401)


class SSOInitiateView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['auth'],
        parameters=[OpenApiParameter(name='provider', type=str, location=OpenApiParameter.PATH)],
        responses={200: {'type': 'object', 'properties': {'url': {'type': 'string'}}}}
    )
    def get(self, request, provider):
        if provider not in {'google', 'microsoft'}:
            return Response({'error': 'Invalid provider'}, status=400)

        try:
            redirect_to = f"{settings.FRONTEND_CONFIG['FRONTEND_URL']}auth/callback"
            res = supabase.auth.sign_in_with_oauth({
                "provider":provider,
                "options":{'redirect_to': redirect_to}
            })
            logger.info("SSO URL generated", extra={'provider': provider})
            return Response({'url': res.url})
        except Exception as e:
            logger.error("SSO initiation failed", exc_info=True, extra={'provider': provider})
            return Response({'error': str(e)}, status=500)


class SSOCallbackView(APIView):
    permission_classes = [AllowAny]
    @extend_schema(
        tags=['auth'],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'code': {
                        'type': 'string',
                        'description': 'Code for SSO'
                    }
                },
                'required': ['email']
            },
        },
        responses={200: {
            'type': 'object',
            'properties': {
                'access_token': {'type': 'string'},
                'refresh_token': {'type': 'string'},
                'expires_in': {'type': 'integer'},
                'user_id': {'type': 'string'}
            }
        }}
    )
    def post(self, request):
        code = request.data.get('code')
        if not code:
            return Response({'error': 'code required'}, status=400)

        try:
            # Supabase exchanges the code for a session
            session = supabase.auth.exchange_code_for_session(code)
            logger.info("SSO login successful", extra={'user_id': session.user.id})
            return Response({
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'expires_in': session.expires_in,
                'user_id': str(session.user.id)
            })
        except Exception as e:
            logger.warning("SSO callback failed", exc_info=True, extra={'code': code[:8]})
            return Response({'error': 'Invalid or expired code'}, status=401)