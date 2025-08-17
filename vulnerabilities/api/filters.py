import django_filters
from django.db.models import Q
from vulnerabilities.models import Response

SEVERITY_CHOICES = (
    ("Critical", "Critical"),
    ("High", "High"),
    ("Medium", "Medium"),
    ("Low", "Low"),
    ("None", "None"),
)

class VulnerabilityFilter(django_filters.FilterSet):
    is_resolve = django_filters.BooleanFilter(field_name="vulnerability__is_resolve")

    base_severity  = django_filters.MultipleChoiceFilter(choices=SEVERITY_CHOICES,  method="filter_base")
    agent_severity = django_filters.MultipleChoiceFilter(choices=SEVERITY_CHOICES,  method="filter_agent")
    rule_severity  = django_filters.MultipleChoiceFilter(choices=SEVERITY_CHOICES,  method="filter_rule")

    cve_id         = django_filters.CharFilter(field_name="vulnerability__cve_id", lookup_expr="icontains")
    impacted_asset = django_filters.NumberFilter(field_name="impacted_asset_id")

    class Meta:
        model = Response
        fields = []

    def _q_for(self, score_field, sev):
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
        return queryset.filter(q)

    def filter_base(self, queryset, name, values):
        return self._apply_severity_filter(queryset, "vulnerability__base_score", values)

    def filter_agent(self, queryset, name, values):
        return self._apply_severity_filter(queryset, "agent_score", values)

    def filter_rule(self, queryset, name, values):
        return self._apply_severity_filter(queryset, "rule_score", values)
