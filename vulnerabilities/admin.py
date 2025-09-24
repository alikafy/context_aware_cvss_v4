from django.contrib import admin
from django.db import transaction
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
    actions = ["mark_as_resolved", "mark_as_unresolved", "clear_responses"]

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

    @admin.action(description="Clear impacted assets (deletes related Responses)")
    def clear_responses(self, request, queryset):
        with transaction.atomic():
            for obj in queryset:
                obj.impacted_assets.set([])
            qs = Response.objects.filter(vulnerability__in=queryset)
            removed = qs.count()
            qs.delete()
        self.message_user(
            request,
            f"Removed {removed} impacted asset relation(s) across {queryset.count()} vulnerability(ies)."
        )


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


# logs/admin.py
import csv
import json
from django.contrib import admin
from django.http import HttpResponse
from .models import APICallLog


@admin.register(APICallLog)
class APICallLogAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "method",
        "response_status",
        "short_endpoint",
        "has_error",
    )
    list_filter = (
        "method",
        "response_status",
        ("created_at", admin.DateFieldListFilter),
    )
    search_fields = (
        "endpoint",
        "request_body",
        "response_body",
        "error_message",
    )
    readonly_fields = (
        "created_at",
        "endpoint",
        "method",
        "request_headers",
        "request_body",
        "response_status",
        "response_headers",
        "response_body",
        "error_message",
    )
    date_hierarchy = "created_at"
    ordering = ("-created_at",)
    actions = ["export_as_json", "export_as_csv"]

    fieldsets = (
        ("Request", {
            "fields": ("created_at", "method", "endpoint", "request_headers", "request_body"),
        }),
        ("Response", {
            "fields": ("response_status", "response_headers", "response_body"),
        }),
        ("Error", {
            "fields": ("error_message",),
        }),
    )

    @admin.display(boolean=True, description="Error?")
    def has_error(self, obj: APICallLog):
        return not bool(obj.error_message)

    def export_as_json(self, request, queryset):
        data = []
        for obj in queryset:
            data.append({
                "id": obj.id,
                "created_at": obj.created_at.isoformat(),
                "endpoint": obj.endpoint,
                "method": obj.method,
                "request_headers": obj.request_headers,
                "request_body": obj.request_body,
                "response_status": obj.response_status,
                "response_headers": obj.response_headers,
                "response_body": obj.response_body,
                "error_message": obj.error_message,
            })
        resp = HttpResponse(json.dumps(data, ensure_ascii=False, indent=2), content_type="application/json")
        resp["Content-Disposition"] = 'attachment; filename="api_call_logs.json"'
        return resp
    export_as_json.short_description = "Export selected logs as JSON"

    def export_as_csv(self, request, queryset):
        resp = HttpResponse(content_type="text/csv")
        resp["Content-Disposition"] = 'attachment; filename="api_call_logs.csv"'
        writer = csv.writer(resp)
        writer.writerow([
            "id","created_at","endpoint","method","response_status","error_message",
            "request_headers","request_body","response_headers","response_body",
        ])
        for obj in queryset:
            writer.writerow([
                obj.id,
                obj.created_at.isoformat(),
                obj.endpoint,
                obj.method,
                obj.response_status,
                (obj.error_message or "")[:5000],
                json.dumps(obj.request_headers, ensure_ascii=False) if obj.request_headers else "",
                (obj.request_body or "")[:500000],
                json.dumps(obj.response_headers, ensure_ascii=False) if obj.response_headers else "",
                (obj.response_body or "")[:500000],
            ])
        return resp
    export_as_csv.short_description = "Export selected logs as CSV"
