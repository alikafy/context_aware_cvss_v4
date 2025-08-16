from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.exceptions import NotFound
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets, filters

from assets.api.serializers import AssetSerializer
from vulnerabilities.api.filters import VulnerabilityFilter
from vulnerabilities.models import Vulnerability
from vulnerabilities.api.serializers import VulnerabilitySerializer
from vulnerabilities.sevcies.fetch_cve import FetchCVEService
from vulnerabilities.sevcies.scan import Scan


class VulnerabilityFetchView(APIView):
    """
    Given a CVE ID, fetch vulnerability details from service,
    save/update in DB, and return serialized object.
    """
    serializer_class = VulnerabilitySerializer

    def get(self, request, cve_id):
        try:
            vulnerability = Vulnerability.objects.get(cve_id=cve_id)
        except Vulnerability.DoesNotExist:
            data = FetchCVEService(cve_id).fetch_cve()
            vulnerability = Vulnerability.objects.create(**data)

        serializer = VulnerabilitySerializer(vulnerability)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ScanView(APIView):
    serializer_class = AssetSerializer

    def post(self, request, vuln_id):
        try:
            model_name = request.data.get('model_name', None)
            vulnerability = Vulnerability.objects.get(id=vuln_id)
        except Vulnerability.DoesNotExist:
            raise NotFound('vulnerability is not exists', 'InvalidVulnerability')

        impacted_assets = Scan(vulnerability, model_name).scan()
        vulnerability.impacted_assets.set(impacted_assets)
        serializer = AssetSerializer(impacted_assets, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CalculateView(APIView):
    serializer_class = VulnerabilitySerializer

    def post(self, request, vuln_id):
        try:
            model_name = request.data.get('model_name', None)
            vulnerability = Vulnerability.objects.get(id=vuln_id)
        except Vulnerability.DoesNotExist:
            raise NotFound('vulnerability is not exists', 'InvalidVulnerability')

        impacted_assets = Scan(vulnerability, model_name).scan()
        vulnerability.impacted_assets.set(impacted_assets)
        serializer = AssetSerializer(impacted_assets, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class VulnerabilityReadOnlyViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only endpoints:
      - list:    GET /api/vulnerabilities/?ordering=-base_score&is_resolve=false&base_severity=High
      - retrieve GET /api/vulnerabilities/<pk>/
    """
    queryset = Vulnerability.objects.all().order_by("cve_id")
    serializer_class = VulnerabilitySerializer

    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_class = VulnerabilityFilter

    # allow sorting by these fields (ASC/DESC via ?ordering= or ?ordering=-field)
    ordering_fields = ["cve_id", "base_score", "agent_score", "rule_score"]
    ordering = ["cve_id"]  # default