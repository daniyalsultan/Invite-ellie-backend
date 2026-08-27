# workspaces/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import GlobalSearchView, WorkspaceViewSet

router = DefaultRouter()
router.register(r'workspaces', WorkspaceViewSet)

urlpatterns = [
    path('search/', GlobalSearchView.as_view(), name='global-search'),
]
