from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("api/schema/", SpectacularAPIView.as_view(), name="api-schema"),
    path("api/docs/",
        SpectacularSwaggerView.as_view(url_name="api-schema"),
        name="api-docs",
    ),
    path('api/accounts/', include('accounts.urls')),
    path("api/workspaces/", include("workspaces.urls")),
    path("api/", include("core.router")),

    path('admin/', admin.site.urls),
]
