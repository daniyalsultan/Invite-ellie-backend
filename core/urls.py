from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from workspaces.views import InviteAcceptView, InviteDetailView

urlpatterns = [
    path("api/schema/", SpectacularAPIView.as_view(), name="api-schema"),
    path("api/docs/",
        SpectacularSwaggerView.as_view(url_name="api-schema"),
        name="api-docs",
    ),
    path('api/accounts/', include('accounts.urls')),
    path("api/workspaces/", include("workspaces.urls")),
    path("api/", include("core.router")),
    # Invitation links: the recipient may have no account yet, so these sit
    # outside the workspace routes, which require membership.
    path("api/invites/<str:token>/", InviteDetailView.as_view(), name="invite-detail"),
    path("api/invites/<str:token>/accept/", InviteAcceptView.as_view(), name="invite-accept"),

    path('admin/', admin.site.urls),
]
