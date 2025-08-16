from rest_framework import serializers

from assets.models import Asset
from vulnerabilities.models import Vulnerability


class VulnerabilitySerializer(serializers.ModelSerializer):
    agent_model_display = serializers.CharField(source='get_agent_model_display')
    impacted_assets = serializers.PrimaryKeyRelatedField(
        queryset=Asset.objects.all(), many=True
    )
    base_severity = serializers.CharField(read_only=True)
    agent_severity = serializers.CharField(read_only=True)
    rule_severity  = serializers.CharField(read_only=True)

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
            'agent_response',
            'rule_response',
            'base_score',
            'agent_score',
            'rule_score',
            'cve_response',
            'agent_model',
            'agent_model_display',
            'base_severity',
            'agent_severity',
            'rule_severity',
            'impacted_assets',
            "base_severity", "agent_severity", "rule_severity",
        ]
