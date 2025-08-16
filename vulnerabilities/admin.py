from django.contrib import admin
from django import forms
from .models import Vulnerability

class VulnerabilityAdminForm(forms.ModelForm):
    # Use JSONField form widgets (validates JSON)
    weaknesses = forms.JSONField(required=False)
    base_vector = forms.JSONField(required=False)
    agent_response = forms.JSONField(required=False)
    rule_response = forms.JSONField(required=False)
    cve_response = forms.JSONField(required=False)

    class Meta:
        model = Vulnerability
        fields = "__all__"

    def clean(self):
        cleaned = super().clean()
        # keep CVSS-like scores sane
        for f in ("base_score", "agent_score", "rule_score"):
            v = cleaned.get(f)
            if v is not None and not (0.0 <= v <= 10.0):
                self.add_error(f, "Score must be between 0.0 and 10.0")
        return cleaned

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    form = VulnerabilityAdminForm

    list_display = (
        "cve_id", "cve_status", "is_resolve",
        "base_score", "agent_score", "rule_score",
        "agent_model", "impacted_assets_count",
    )
    list_filter = ("is_resolve", "cve_status", "agent_model")
    search_fields = ("cve_id", "cve_description", "impacted_assets__name")
    ordering = ("cve_id",)
    list_per_page = 50

    # ManyToMany selector UI
    filter_horizontal = ("impacted_assets",)

    fieldsets = (
        ("CVE", {"fields": ("cve_id", "cve_status", "cve_description", "is_resolve", "agent_model")}),
        ("Vectors & Responses", {"fields": ("weaknesses", "base_vector", "agent_response", "rule_response", "cve_response")}),
        ("Scores", {"fields": ("base_score", "agent_score", "rule_score")}),
        ("Relations", {"fields": ("impacted_assets",)}),
    )

    def impacted_assets_count(self, obj):
        return obj.impacted_assets.count()
    impacted_assets_count.short_description = "Assets"
