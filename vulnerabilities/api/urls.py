from django.urls import path, include
from rest_framework.routers import DefaultRouter

from vulnerabilities.api.views import VulnerabilityFetchView, ScanView, VulnerabilityReadOnlyViewSet, CalculateView

router = DefaultRouter()
router.register(r"vulnerabilities", VulnerabilityReadOnlyViewSet, basename="vulnerability")

urlpatterns = [
    path("fetch-cve/<str:cve_id>/", VulnerabilityFetchView.as_view(), name="fetch-cve"),
    path("scan/<str:vuln_id>/", ScanView.as_view()),
    path("calculate/<str:vuln_id>/", CalculateView.as_view()),
    path("", include(router.urls)),
    ]
