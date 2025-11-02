# accounts/urls.py
from django.urls import path
from .views import (
    PasswordResetConfirmView, RegisterView, LoginView, GoogleSSOView,
    ProfileView, PasswordResetView, ResendConfirmationView,
    ConfirmEmailView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('sso/google/', GoogleSSOView.as_view(), name='sso-google'),
    path('me/', ProfileView.as_view(), name='profile'),

    path('password/reset/', PasswordResetView.as_view(), name='reset-password'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    # EMAIL CONFIRMATION
    path('confirm/resend/', ResendConfirmationView.as_view(), name='resend-confirmation'),
    path('confirm/verify/', ConfirmEmailView.as_view(), name='verify-email'),
]