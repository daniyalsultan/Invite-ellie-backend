# accounts/urls.py
from django.urls import path
from .views import (
    ActivityLogView, NotificationView, PasswordResetConfirmView, RefreshTokenView, RegisterView, LoginView,
    ProfileView, PasswordResetView, ResendConfirmationView,
    ConfirmEmailView, SSOCallbackView, SSOInitiateView
)

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

    path('sso/<str:provider>/', SSOInitiateView.as_view(), name='sso-initiate'),
    path('sso/callback/', SSOCallbackView.as_view(), name='sso-callback'),

    path('notifications/', NotificationView.as_view(), name='notifications'),
    path('activity/', ActivityLogView.as_view(), name='activity-logs'),
]