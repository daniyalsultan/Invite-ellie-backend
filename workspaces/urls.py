# workspaces/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import WorkspaceViewSet, FolderViewSet, MeetingViewSet

router = DefaultRouter()
router.register(r'workspaces', WorkspaceViewSet)
router.register(r'folders', FolderViewSet)
router.register(r'meetings', MeetingViewSet)

urlpatterns = [
]