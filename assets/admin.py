from django.contrib import admin
from .models import Asset

@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = (
        "id", "name", "version", "tp", "exposure_level",
        "network_segmentation", "firewall_configuration",
        "vpn_access", "is_active",
    )
    list_filter = (
        "tp",
        "exposure_level",
        "network_segmentation",
        "firewall_configuration",
        "vpn_access",
        "system_hardening_level",
        "software_patch_level",
        "authentication_requirement",
        "asset_criticality",
        "data_sensitivity",
        "encryption_protection_level",
        "availability_redundancy",
        "asset_dependency_level",
        "connected_systems_criticality",
        "network_connectivity",
        "cascading_impact_potential",
        "connection_security_controls",
        "is_active",
    )
    search_fields = ("name", "version")
    ordering = ("name", "tp")
    list_per_page = 50
    list_editable = ("is_active",)

    fieldsets = (
        ("Basic Info", {
            "fields": ("name", "version", "tp", "is_active")
        }),
        ("Exposure & Network", {
            "fields": (
                "exposure_level", "network_segmentation", "firewall_configuration",
                "vpn_access", "ssh_remote_access", "physical_access_required",
            )
        }),
        ("Security Controls", {
            "fields": (
                "network_access_complexity",
                "security_controls_waf", "security_controls_firewall",
                "security_controls_ids", "security_controls_ips",
                "security_controls_edr", "system_hardening_level",
                "software_patch_level", "privilege_escalation_protection",
            )
        }),
        ("Auth & Access", {
            "fields": (
                "authentication_requirement",
                "user_privilege_level_required",
                "access_control_strength",
                "user_awareness_level",
            )
        }),
        ("Requirements (CIA)", {
            "fields": (
                "security_requirements_confidentiality",
                "security_requirements_integrity",
                "security_requirements_availability",
            )
        }),
        ("Risk & Dependencies", {
            "fields": (
                "asset_criticality", "data_sensitivity",
                "encryption_protection_level", "availability_redundancy",
                "asset_dependency_level", "connected_systems_criticality",
                "network_connectivity", "cascading_impact_potential",
                "connection_security_controls",
            )
        }),
    )
