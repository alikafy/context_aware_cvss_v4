from django.db import models

from assets.models import Asset
from vulnerabilities.sevcies.cvss_v4 import score_to_severity


class Vulnerability(models.Model):
    AGENT_MODEL = [
        ('gpt_4o', 'gpt-4o'),
        ('deepseek_chat', 'deepseek-chat'),
    ]

    cve_id = models.CharField(max_length=50)
    cve_description = models.TextField()
    cve_status = models.CharField(max_length=50)

    is_resolve = models.BooleanField(default=False)

    weaknesses = models.JSONField(null=True, blank=True)

    base_vector = models.JSONField(null=True, blank=True)
    base_score = models.FloatField(null=True, blank=True)

    cve_response = models.JSONField(null=True, blank=True)

    agent_model = models.CharField(max_length=32, null=True, choices=AGENT_MODEL)

    impacted_assets = models.ManyToManyField(Asset)

    @property
    def base_severity(self):
        """Returns severity level based on base_score."""
        return score_to_severity(self.base_score)

    def __str__(self):
        return f"{self.cve_id} - {self.cve_status}"


class Response(models.Model):
    agent_response = models.JSONField(null=True, blank=True)
    rule_response = models.JSONField(null=True, blank=True)

    agent_score = models.FloatField(null=True, blank=True)
    rule_score = models.FloatField(null=True, blank=True)
    impacted_asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)


    @property
    def agent_severity(self):
        """Returns severity level based on agent_score."""
        return score_to_severity(self.agent_score)

    @property
    def rule_severity(self):
        """Returns severity level based on rule_score."""
        return score_to_severity(self.rule_score)

    def __str__(self):
        return f"{self.impacted_asset.name} - {self.vulnerability.cve_id}"
