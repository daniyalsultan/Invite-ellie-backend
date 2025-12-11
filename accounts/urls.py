# accounts/urls.py
from django.urls import path
from .views import (
    ActivityLogViewSet, CancelDeletionRequestView, CheckDeletionPeriodsView, DataExportView, DeletionRequestView, NotificationViewSet, PasswordResetConfirmView, RefreshTokenView, RegisterView, LoginView,
    ProfileView, PasswordResetView, ResendConfirmationView,
    ConfirmEmailView, SSOCallbackView, SSOInitiateView
)

from rest_framework.routers import DefaultRouter
from .views import NotificationViewSet, ActivityLogViewSet, ProfileStorageViewSet

router = DefaultRouter()
router.register(r'accounts/notifications', NotificationViewSet, basename='notification')
router.register(r'accounts/activity', ActivityLogViewSet, basename='activity-logs')
router.register(r'accounts/storage', ProfileStorageViewSet, basename='storage')

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token-refresh'),
    path('me/', ProfileView.as_view(), name='profile'),

    path('password/reset/', PasswordResetView.as_view(), name='reset-password'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    # EMAIL CONFIRMATION
    path('confirm/resend/', ResendConfirmationView.as_view(), name='resend-confirmation'),
    path('confirm/verify/', ConfirmEmailView.as_view(), name='verify-email'),

    path('sso/providers/<str:provider>/', SSOInitiateView.as_view(), name='sso-initiate'),
    path('sso/callback/', SSOCallbackView.as_view(), name='sso-callback'),

    path('deletion/request/', DeletionRequestView.as_view(), name='deletion-request'),
    path('deletion/data/export/', DataExportView.as_view(), name='data-export'),
    path('deletion/cancel/', CancelDeletionRequestView.as_view(), name='cancel-deletion'),

    path('celery/run/check_deletion_grace_periods/', CheckDeletionPeriodsView.as_view(), name='run-check-deletion-grace-periods'),
]