from rest_framework import serializers

from assets.api.serializers import AssetSerializer
from assets.models import Asset
from vulnerabilities.models import Vulnerability, Response


class VulnerabilitySerializer(serializers.ModelSerializer):
    agent_model_display = serializers.CharField(source='get_agent_model_display')
    impacted_assets = serializers.PrimaryKeyRelatedField(
        queryset=Asset.objects.all(), many=True
    )

    class Meta:
        model = Vulnerability
        fields = [
            'id',
            'cve_id',
            'cve_description',
            'cve_status',
            'is_resolve',
            'weaknesses',
            'base_vector',
            'base_score',
            'agent_model_display',
            'base_severity',
            'impacted_assets',
            # 'cve_response',
        ]


class ResponseSerializer(serializers.ModelSerializer):
    vulnerability  = VulnerabilitySerializer(read_only=True)
    impacted_asset  = AssetSerializer(read_only=True)
    vulnerability_id = serializers.PrimaryKeyRelatedField(
        queryset=Vulnerability.objects.all(),
        source='vulnerability',
        write_only=True
    )

    class Meta:
        model = Response
        fields = [
            'id', 'vulnerability', 'vulnerability_id',
            'impacted_asset',
            'agent_score', 'rule_score',
            'agent_severity', 'rule_severity',
            'agent_response', 'rule_response',
        ]
