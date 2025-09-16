from django.contrib import admin
from .models import Asset

@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    """
    Custom admin interface for the Asset model.
    Organizes the extensive fields into logical groups for better usability.
    """

    # --- List View Configuration ---
    list_display = (
        'name',
        'version',
        'tp',
        'asset_criticality',
        'network_accessibility',
        'is_active',
        'updated_at',
    )
    list_filter = (
        'is_active',
        'tp',
        'asset_criticality',
        'network_accessibility',
        'system_hardening_level',
    )
    search_fields = ('name', 'version')

    # --- Form View Configuration ---
    fieldsets = (
        ('Core Identification', {
            'fields': (
                ('name', 'version'),
                ('tp', 'is_active'),
            )
        }),
        ('Business Context', {
            'fields': (
                ('asset_criticality', 'data_sensitivity'),
            )
        }),
        ('Security Requirements (Asset)', {
            'fields': (
                ('security_requirement_confidentiality', 'security_requirement_integrity', 'security_requirement_availability'),
            )
        }),
        ('Network & Access Posture', {
            'fields': ('network_accessibility', 'remote_management_access')
        }),
        ('System Configuration & Hardening', {
            'fields': (
                'system_hardening_level',
                'software_patch_level',
                ('availability_redundancy', 'data_encryption_level'),
            )
        }),
        ('Compensating Security Controls', {
            'fields': (
                'network_protection',
                'endpoint_protection',
                'integrity_protection_level',
                'privilege_escalation_protection',
            )
        }),
        ('User & Authentication Context', {
            'fields': ('authentication_strength', 'user_awareness_level')
        }),
        ('Downstream Impact (Subsequent Systems)', {
            'fields': (
                'propagation_risk',
                ('subsequent_system_confidentiality_req', 'subsequent_system_integrity_req', 'subsequent_system_availability_req'),
            )
        }),
        ('Timestamps', {
            'classes': ('collapse',),
            'fields': ('created_at', 'updated_at')
        }),
    )

    readonly_fields = ('created_at', 'updated_at')
