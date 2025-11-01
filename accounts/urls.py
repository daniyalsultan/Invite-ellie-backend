from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register),
    path('login/', views.login),
    path('sso/<str:provider>/', views.sso_login),
    path('me/', views.ProfileView.as_view()),
]