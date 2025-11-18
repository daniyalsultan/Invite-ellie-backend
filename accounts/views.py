import jwt
import logging
import traceback
import os
import uuid
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.serializers import ValidationError
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter

from django.http import JsonResponse
from django.conf import settings
from django.core.files.storage import default_storage

from accounts.filters import ActivityLogFilter, NotificationFilter
from accounts.permissions import IsSupabaseAuthenticated
from accounts.tasks import calculate_user_storage
from accounts.utils import _pkce_pair, check_user_exists, email_exists_in_supabase
from core.supabase import supabase
from .models import Notification, Profile

from .serializers import (
    ActivityLogSerializer, EmailConfirmationSerializer, EmailSerializer, MarkSeenSerializer, NotificationSerializer, PasswordResetSerializer, RefreshTokenSerializer, RegisterSerializer, LoginSerializer, ProfileSerializer
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

        if check_user_exists(serializer.validated_data['email']):
            logger.warning(f"Signup blocked: Email already exists: {serializer.validated_data['email']}")
            raise ValidationError({"email": "This email is already in use."})

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
        serializer = ProfileSerializer(profile, data=request.data, partial=True, context={'request': request})

        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        serializer.save()
        return Response(serializer.data)

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

        access_token = serializer.validated_data['access_token']
        refresh_token = serializer.validated_data['refresh_token']
        password = serializer.validated_data['password']

        try:
            supabase.auth.set_session(
                access_token=access_token,
                refresh_token=refresh_token
            )

            res = supabase.auth.update_user({"password": password})
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
        if provider not in {'google', 'azure'}:
            return Response({'error': 'Invalid provider'}, status=400)

        verifier, challenge = _pkce_pair()

        request.session['sso_pkce_verifier'] = verifier
        request.session.save()
        request.session.modified = True   # force write

        redirect_to = f"{settings.FRONTEND_CONFIG['FRONTEND_URL']}auth/callback"
        auth_url = (
            f"https://{settings.SUPABASE_PROJECT_REF}.supabase.co/auth/v1/authorize"
            f"?provider={provider}"
            f"&redirect_to={redirect_to}"
            f"&code_challenge={challenge}"
            f"&code_challenge_method=S256"
        )

        logger.info("SSO URL generated", extra={'provider': provider})
        logger.info("Session ID after save", extra={
            'sessionid': request.session.session_key,
            'verifier_set': 'sso_pkce_verifier' in request.session
        })
        return Response({'url': auth_url})


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
                'required': ['code']
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
        logger.info("Session in callback", extra={
            'sessionid': request.session.session_key,
            'has_verifier': 'sso_pkce_verifier' in request.session
        })
        if not code:
            return Response({'error': 'code required'}, status=400)

        verifier = request.session.pop('sso_pkce_verifier', None)
        if not verifier:
            logger.warning("PKCE verifier missing in session")
            return Response({'error': 'PKCE verifier missing'}, status=400)

        try:
            session = supabase.auth.exchange_code_for_session({
                "auth_code":code,
                "code_verifier":verifier
            })

            logger.info(
                "SSO login successful",
                extra={'user_id': session.user.id}
            )
            return Response({
                'access_token': session.session.access_token,
                'refresh_token': session.session.refresh_token,
                'expires_in': session.session.expires_in,
                'user_id': str(session.user.id),
            })

        except Exception as e:
            logger.warning(
                "SSO callback failed",
                exc_info=True,
                extra={'code': code[:8]}
            )
            return Response({'error': 'Invalid or expired code'}, status=401)

class NotificationView(APIView):
    permission_classes = [IsAuthenticated]
    filterset_class = NotificationFilter
    search_fields = ['message', 'meta_data']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get(self, request):
        notifications = request.user.profile.notifications.all()[:50]
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)

    @extend_schema(
        request=MarkSeenSerializer,
        description="Mark notifications as seen.",
    )
    @action(detail=False, methods=["post"])
    def mark_seen(self, request):
        """
        Mark multiple notifications as seen.
        """
        data = request.data

        try:
            Notification.objects.filter(
                id__in=data['ids'],
                user=request.user
            ).update(seen=True)
            return Response({
                'message': 'Notification(s) updated successfully'
            }, status=status.HTTP_200_OK)
        except Exception:
            return Response({
                'message': 'Unable to update the notification(s)'
            }, status=status.HTTP_400_BAD_REQUEST)

class ActivityLogView(APIView):
    permission_classes = [IsAuthenticated]
    filterset_class = ActivityLogFilter
    search_fields = ['description']
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']

    def get(self, request):
        logs = request.user.profile.activity_logs.all()[:100]
        serializer = ActivityLogSerializer(logs, many=True)
        return Response(serializer.data)

class UserStorageAsyncView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        task = calculate_user_storage.delay(request.user.id)
        return Response({"task_id": task.id, "status": "queued"})