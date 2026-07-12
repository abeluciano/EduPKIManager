from django.contrib import admin
from django.urls import include, path

from api.views import StandardOcspView


urlpatterns = [
    path("admin/", admin.site.urls),
    path("ocsp/", StandardOcspView.as_view(), name="standard-ocsp-root"),
    path("api/", include("api.urls")),
]
