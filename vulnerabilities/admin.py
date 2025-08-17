from django.contrib import admin
from vulnerabilities.models import Vulnerability, Response


class ResponseInline(admin.TabularInline):
    model = Response
    extra = 0
    raw_id_fields = ("impacted_asset",)
    readonly_fields = ("agent_severity", "rule_severity")
    fields = (
        "impacted_asset",
        "agent_score", "agent_severity",
        "rule_score", "rule_severity",
        "agent_response", "rule_response",
    )


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = (
        "cve_id",
        "cve_status",
        "base_score",
        "base_severity",
        "agent_model",
        "is_resolve",
        "impacted_assets_count",
    )
    list_filter = ("agent_model", "is_resolve", "cve_status")
    search_fields = ("cve_id", "cve_description")
    readonly_fields = ("base_severity",)
    filter_horizontal = ("impacted_assets",)
    inlines = [ResponseInline]
    actions = ["mark_as_resolved", "mark_as_unresolved"]

    @admin.display(description="Impacted assets")
    def impacted_assets_count(self, obj):
        return obj.impacted_assets.count()

    @admin.action(description="Mark selected as resolved")
    def mark_as_resolved(self, request, queryset):
        updated = queryset.update(is_resolve=True)
        self.message_user(request, f"Marked {updated} vulnerabilities as resolved.")

    @admin.action(description="Mark selected as unresolved")
    def mark_as_unresolved(self, request, queryset):
        updated = queryset.update(is_resolve=False)
        self.message_user(request, f"Marked {updated} vulnerabilities as unresolved.")


@admin.register(Response)
class ResponseAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "vulnerability",
        "impacted_asset",
        "agent_score", "agent_severity",
        "rule_score", "rule_severity",
    )
    list_filter = ("vulnerability__agent_model", "vulnerability__cve_status")
    search_fields = ("vulnerability__cve_id", "impacted_asset__name")
    raw_id_fields = ("vulnerability", "impacted_asset")
    readonly_fields = ("agent_severity", "rule_severity")
    list_select_related = ("vulnerability", "impacted_asset")
