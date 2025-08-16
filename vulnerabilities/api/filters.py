import django_filters
from django.db.models import Q
from vulnerabilities.models import Vulnerability

SEVERITY_CHOICES = (
    ("Critical", "Critical"),
    ("High", "High"),
    ("Medium", "Medium"),
    ("Low", "Low"),
    ("None", "None"),
)

class VulnerabilityFilter(django_filters.FilterSet):
    # simple boolean filter
    is_resolve = django_filters.BooleanFilter()

    # allow one or many severities via ?base_severity=High&base_severity=Critical
    base_severity  = django_filters.MultipleChoiceFilter(choices=SEVERITY_CHOICES, method="filter_base")
    agent_severity = django_filters.MultipleChoiceFilter(choices=SEVERITY_CHOICES, method="filter_agent")
    rule_severity  = django_filters.MultipleChoiceFilter(choices=SEVERITY_CHOICES, method="filter_rule")

    class Meta:
        model = Vulnerability
        fields = ["is_resolve", "base_severity", "agent_severity", "rule_severity"]

    # --- helpers ---
    def _q_for(self, score_field, sev):
        """
        Map severity label to a Q() condition on the numeric score field.
        Mirrors your _score_to_severity():
          Critical: >= 9.0
          High:     [7.0, 9.0)
          Medium:   [4.0, 7.0)
          Low:      (0.0, 4.0)
          None:     == 0.0
        (NULL scores are excluded from all labels, matching your property logic.)
        """
        if sev == "Critical":
            return Q(**{f"{score_field}__gte": 9.0})
        if sev == "High":
            return Q(**{f"{score_field}__gte": 7.0}) & Q(**{f"{score_field}__lt": 9.0})
        if sev == "Medium":
            return Q(**{f"{score_field}__gte": 4.0}) & Q(**{f"{score_field}__lt": 7.0})
        if sev == "Low":
            return Q(**{f"{score_field}__gt": 0.0}) & Q(**{f"{score_field}__lt": 4.0})
        if sev == "None":
            return Q(**{f"{score_field}": 0.0})
        return Q()

    def _apply_severity_filter(self, queryset, score_field, values):
        if not values:
            return queryset
        q = Q()
        for v in values:
            q |= self._q_for(score_field, v)
        # exclude NULL scores unless requested explicitly via another param
        return queryset.filter(q)

    def filter_base(self, queryset, name, values):
        return self._apply_severity_filter(queryset, "base_score", values)

    def filter_agent(self, queryset, name, values):
        return self._apply_severity_filter(queryset, "agent_score", values)

    def filter_rule(self, queryset, name, values):
        return self._apply_severity_filter(queryset, "rule_score", values)
