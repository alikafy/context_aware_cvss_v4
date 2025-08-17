from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.exceptions import NotFound
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets, filters

from assets.api.serializers import AssetSerializer
from vulnerabilities.api.filters import VulnerabilityFilter
from vulnerabilities.models import Vulnerability
from vulnerabilities.api.serializers import VulnerabilitySerializer
from vulnerabilities.sevcies.agent_calculator import AgentCalculator
from vulnerabilities.sevcies.fetch_cve import FetchCVEService
from vulnerabilities.sevcies.rule_base_calculator import rule_base_answer
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
            agent_model = request.data.get('agent_model', None)
            vulnerability = Vulnerability.objects.get(id=vuln_id)
        except Vulnerability.DoesNotExist:
            raise NotFound('vulnerability is not exists', 'InvalidVulnerability')

        impacted_assets = Scan(vulnerability, agent_model).scan()
        vulnerability.impacted_assets.set(impacted_assets)
        serializer = AssetSerializer(impacted_assets, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CalculateView(APIView):

    def post(self, request, vuln_id):
        try:
            agent_model = request.data.get('agent_model', None)
            vulnerability = Vulnerability.objects.get(id=vuln_id)
        except Vulnerability.DoesNotExist:
            raise NotFound('vulnerability is not exists', 'InvalidVulnerability')

        serializer = VulnerabilitySerializer(vulnerability)
        values = []
        for asset in vulnerability.impacted_assets.all():
            if not asset.is_active:
                continue
            agent_response = AgentCalculator(vulnerability, asset, agent_model).calculate()
            rule_base_response = rule_base_answer(asset, vulnerability)
            values.append({'agent_response': agent_response, 'rule_base_response': rule_base_response, 'asset': AssetSerializer(asset).data})
        response = {'vulnerability': serializer.data, 'values': values}
        return Response(response, status=status.HTTP_200_OK)


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