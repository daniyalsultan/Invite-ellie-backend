import jwt
import logging
import traceback
import os
import stripe
import uuid
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.viewsets import ReadOnlyModelViewSet
from rest_framework.response import Response
from rest_framework.serializers import ValidationError
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter

from django.http import JsonResponse
from django.conf import settings
from django.utils import timezone
from django.core.files.storage import default_storage
from django.db import transaction

from accounts.filters import ActivityLogFilter, NotificationFilter
from accounts.permissions import IsSupabaseAuthenticated
from accounts.services import DataExportService, DeletionService
from accounts.tasks import calculate_user_storage, check_deletion_grace_periods
from accounts.utils import StripeService, _pkce_pair, check_user_exists, email_exists_in_supabase
from core.supabase import supabase
from .models import ActivityLog, Notification, Profile, ProfileStorage
from workspaces.models import Workspace, Folder

from .serializers import (
    ActivityLogSerializer, EmailConfirmationSerializer, EmailSerializer, MarkSeenSerializer, NotificationSerializer, PasswordResetSerializer, ProfileStorageSerializer, RefreshTokenSerializer, RegisterSerializer, LoginSerializer, ProfileSerializer
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
    permission_classes = [AllowAny]
    serializer_class = EmailConfirmationSerializer

    @extend_schema(
        tags=['auth'],
        request=EmailConfirmationSerializer,
        description="Email confirmation + create domain-based workspace",
    )
    @transaction.atomic  # Everything or nothing
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

            profile = Profile.objects.select_for_update().get(id=res.user.id)

            # Only run once — prevent double workspace creation
            if profile.is_active:
                return Response({
                    "message": "Email already confirmed",
                    "access_token": res.session.access_token,
                    "refresh_token": res.session.refresh_token,
                    "user_id": res.user.id,
                    "expires_in": res.session.expires_in,
                    "perform_onboarding": False
                })

            # Activate profile
            profile.is_active = True
            profile.save()

            # === NEW: Create domain-based workspace ===
            email_domain = profile.email.split('@')[-1].lower()

            workspace_name = "Personal"

            personal_domains = settings.PERSONAL_EMAIL_DOMAINS

            if email_domain not in personal_domains:
                workspace_name = email_domain.split('.')[0].replace('-', ' ').title()

            # Create workspace (idempotent)
            workspace, created = Workspace.objects.get_or_create(
                owner=profile,
                name=workspace_name,
                defaults={'created_at': timezone.now(), 'updated_at': timezone.now()}
            )

            # Create default folder if workspace was just created
            if created:
                Folder.objects.create(
                    workspace=workspace,
                    name='Default Folder',
                    is_pinned=False
                )

            return Response({
                "message": "Email confirmed and workspace created",
                "access_token": res.session.access_token,
                "refresh_token": res.session.refresh_token,
                "user_id": res.user.id,
                "expires_in": res.session.expires_in,
                "perform_onboarding": True,
                "workspace_name": workspace_name
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
            Profile.objects.filter(id=session.user.id).update(is_active=True)
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


@extend_schema(tags=['auth'])
class NotificationViewSet(ReadOnlyModelViewSet):
    permission_classes = [IsSupabaseAuthenticated]
    serializer_class = NotificationSerializer
    queryset = Notification.objects.all()
    filterset_class = NotificationFilter
    search_fields = ['message', 'meta_data']
    ordering_fields = ['created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        return self.queryset.filter(owner=self.request.profile)

    def get(self, request):
        notifications = request.user.profile.notifications.all()[:50]
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)

    @extend_schema(
        request=MarkSeenSerializer,
        description="Mark notifications as seen.",
        tags=['auth'],
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


@extend_schema(tags=['auth'])
class ActivityLogViewSet(ReadOnlyModelViewSet):
    permission_classes = [IsSupabaseAuthenticated]
    serializer_class = ActivityLogSerializer
    queryset = ActivityLog.objects.all()
    filterset_class = ActivityLogFilter
    search_fields = ['description']
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']

    def get_queryset(self):
        return self.queryset.filter(profile=self.request.profile)

    def get(self, request):
        logs = request.user.profile.activity_logs.all()[:100]
        serializer = ActivityLogSerializer(logs, many=True)
        return Response(serializer.data)


@extend_schema(tags=['auth'])
class ProfileStorageViewSet(ReadOnlyModelViewSet):
    permission_classes = [IsSupabaseAuthenticated]
    queryset = ProfileStorage.objects.all()
    serializer_class = ProfileStorageSerializer

    def get_queryset(self):
        return self.queryset.filter(user=self.request.profile)

    def get(self, request):
        task = calculate_user_storage.delay(request.user.id)
        return Response({"task_id": task.id, "status": "queued"})


class DeletionRequestView(APIView):
    permission_classes = [IsSupabaseAuthenticated]

    @extend_schema(
        tags=['deletion'],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'deletion_type': {
                        'type': 'string',
                        'description': 'IMMEDIATE or GRACE_PERIOD'
                    }
                },
                'required': ['deletion_type']
            },
        },
        description="Request account deletion (GDPR Article 17). Triggers data export and schedules deletion. IMMEDIATE or GRACE_PERIOD",
        responses={200: dict}
    )
    def post(self, request):
        deletion_type = request.data.get('deletion_type', 'GRACE_PERIOD')
        ip = request.META.get('REMOTE_ADDR')
        success, export_url = DeletionService.request_deletion(request.profile, deletion_type, ip)
        if success:
            return Response({"message": "Deletion requested. Download your data.", "export_url": export_url})
        return Response({"error": export_url}, status=400)


class DataExportView(APIView):
    permission_classes = [IsSupabaseAuthenticated]

    @extend_schema(
        tags=['deletion'],
        description="Export user data (GDPR Article 20). Returns URL to machine-readable JSON.",
        responses={200: dict}
    )
    def get(self, request):
        success, export_url, error = DataExportService.generate_export(request.profile)
        if success:
            return Response({"message": "Export generated", "export_url": export_url})
        return Response({"error": error}, status=400)


class CancelDeletionRequestView(APIView):
    permission_classes = [IsSupabaseAuthenticated]
    serializer_class = None

    @extend_schema(
        tags=['deletion'],
        description="Cancel a pending deletion request if within 7-day grace period",
    )
    def post(self, request):
        profile = request.profile  # your custom request.profile

        # No deletion request active
        if not profile.deletion_requested_at:
            return Response(
                {"error": "No deletion request found"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Already completed (past grace period or immediate)
        if profile.deletion_completed_at:
            return Response(
                {"error": "Deletion already completed — cannot cancel"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Grace period expired?
        if profile.deletion_type == 'GRACE_PERIOD':
            days_elapsed = (timezone.now() - profile.deletion_requested_at).days
            if days_elapsed >= 7:
                return Response(
                    {"error": "Grace period expired — deletion will proceed soon"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # CANCEL IT
        profile.deletion_requested_at = None
        profile.deletion_requested_by_ip = None
        profile.deletion_type = ''
        profile.save()

        # Optional: log cancellation
        from .models import DeletionAuditLog
        DeletionAuditLog.objects.create(
            profile=profile,
            action="DELETION_CANCELLED",
            metadata={"cancelled_at": timezone.now().isoformat()}
        )

        return Response({
            "message": "Deletion request successfully cancelled",
            "grace_period_remaining_days": 7 - days_elapsed if profile.deletion_type == 'GRACE_PERIOD' else 0
        }, status=status.HTTP_200_OK)


class CreateCheckoutSessionView(APIView):
    permission_classes = [IsSupabaseAuthenticated]
    serializer_class = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        stripe.api_key = settings.STRIPE_SECRET_KEY

    @extend_schema(
        tags=['stripe'],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'plan': {
                        'type': 'string',
                        'description': 'CLARITY or INSIGHT or ALIGNMENT'
                    }
                },
                'required': ['plan']
            },
        },
        description="Select subscription plan and create Stripe checkout session.",
        responses={200: dict},
    )
    def post(self, request):
        plan = request.data.get('plan')

        price_map = {
            'CLARITY': settings.STRIPE_PRICE_CLARITY,
            'INSIGHT': settings.STRIPE_PRICE_INSIGHT,
            'ALIGNMENT': settings.STRIPE_PRICE_ALIGNMENT,
        }

        price_id = price_map.get(plan)
        if not price_id:
            return Response({"error": "Invalid plan"}, status=400)

        # PREVENT DUPLICATE SUBSCRIPTION TO SAME PLAN
        if request.profile.stripe_subscription_id:
            try:
                current_sub = stripe.Subscription.retrieve(request.profile.stripe_subscription_id)
                if current_sub.status in ['active', 'trialing'] and current_sub['items']['data'][0]['price']['id'] == price_id:
                    return Response({
                        "error": "You are already subscribed to this plan",
                    }, status=400)
            except Exception:
                pass

        # Get or create customer
        if not request.profile.stripe_customer_id:
            customer = stripe.Customer.create(email=request.profile.email)
            request.profile.stripe_customer_id = customer.id
            request.profile.save()

        session = stripe.checkout.Session.create(
            customer=request.profile.stripe_customer_id,
            mode='subscription',
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            success_url=settings.STRIPE_SUCCESS_URL,
            cancel_url=settings.STRIPE_CANCEL_URL,
            metadata={'plan': plan, 'profile_id': str(request.profile.id)}
        )

        return Response({"url": session.url})


class StripeWebhookView(APIView):
    serializer_class = None
    permission_classes = [AllowAny]

    @extend_schema(
        tags=['stripe'],
        description="Stripe webhook endpoint.",
    )
    def post(self, request):
        payload = request.body
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
        event = None

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
            )
        except ValueError:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        except stripe.error.SignatureVerificationError:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if event['type'] == 'checkout.session.completed':
            logger.info("Stripe event received: checkout.session.completed")
            session = event['data']['object']
            profile_id = session['metadata'].get('profile_id')
            if profile_id:
                profile = Profile.objects.get(id=profile_id)
                profile.stripe_subscription_id = session['subscription']
                profile.subscription_status = 'active'
                profile.save()

        elif event['type'] == 'customer.subscription.deleted':
            logger.info("Stripe event received: customer.subscription.deleted")
            subscription = event['data']['object']
            profile = Profile.objects.filter(stripe_subscription_id=subscription['id']).first()
            if profile:
                profile.subscription_status = 'canceled'
                profile.stripe_subscription_id = None
                profile.save()

        return Response(status=status.HTTP_200_OK)


class CheckDeletionPeriodsView(APIView):
    permission_classes = [IsSupabaseAuthenticated]

    @extend_schema(
        tags=['celery'],
        description="Run task.",
        responses={200: dict}
    )
    def get(self, request):
        check_deletion_grace_periods.delay()
        return Response({"message": "check_deletion_grace_periods run queued"})
