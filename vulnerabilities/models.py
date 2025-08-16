from django.db import models

from assets.models import Asset


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
    agent_response = models.JSONField(null=True, blank=True)
    rule_response = models.JSONField(null=True, blank=True)

    base_score = models.FloatField(null=True, blank=True)
    agent_score = models.FloatField(null=True, blank=True)
    rule_score = models.FloatField(null=True, blank=True)

    cve_response = models.JSONField(null=True, blank=True)

    agent_model = models.CharField(max_length=32, null=True, choices=AGENT_MODEL)

    impacted_assets = models.ManyToManyField(Asset)

    @property
    def base_severity(self):
        """Returns severity level based on base_score."""
        return self._score_to_severity(self.base_score)

    @property
    def agent_severity(self):
        """Returns severity level based on agent_score."""
        return self._score_to_severity(self.agent_score)

    @property
    def rule_severity(self):
        """Returns severity level based on rule_score."""
        return self._score_to_severity(self.rule_score)

    def _score_to_severity(self, score):
        """Helper: Convert numeric CVSS score to qualitative severity."""
        if score is None:
            return None
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0.0:
            return "Low"
        return "None"

    def __str__(self):
        return f"{self.cve_id} - {self.cve_status}"
