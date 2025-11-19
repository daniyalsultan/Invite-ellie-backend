from django.conf import settings
from rest_framework.routers import DefaultRouter

from workspaces.urls import router as workspace_router
from accounts.urls import router as account_router

router = DefaultRouter()
router.registry.extend(workspace_router.registry)
router.registry.extend(account_router.registry)

app_name = "core"

urlpatterns = router.urls
