from django.conf import settings
from rest_framework.routers import DefaultRouter

from workspaces.urls import router as workspace_router

router = DefaultRouter()
router.registry.extend(workspace_router.registry)

app_name = "core"

urlpatterns = router.urls
