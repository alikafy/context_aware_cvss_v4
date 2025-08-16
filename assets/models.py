from django.db import models


class Asset(models.Model):
    TP_CHOICES = [
        ('database', 'Database'),
        ('application', 'Application'),
        ('webserver', 'Webserver'),
        ('security_tools', 'Security Tools'),
    ]

    EXPOSURE_LEVEL_CHOICES = [
        ('external', 'External'),
        ('internal', 'Internal'),
        ('local', 'Local'),
        ('physical', 'Physical'),
    ]

    NETWORK_SEGMENTATION_CHOICES = [
        ('isolated', 'Isolated'),
        ('highly_isolated', 'Highly Isolated'),
        ('none', 'None'),
    ]

    FIREWALL_CONFIGURATION_CHOICES = [
        ('allow_external_inbound', 'Allow External Inbound'),
        ('block_external_allow_internal_only', 'Block External Allow Internal Only'),
        ('block_internal_external_inbound', 'Block Internal External Inbound'),
    ]

    VPN_ACCESS_CHOICES = [
        ('required', 'Required'),
        ('not_required', 'Not Required'),
    ]

    TRUE_FALSE_CHOICES = [
        ('true', 'True'),
        ('false', 'False'),
    ]

    PRESENT_ABSENT_CHOICES = [
        ('present', 'Present'),
        ('absent', 'Absent'),
    ]

    SYSTEM_HARDENING_CHOICES = [
        ('fully_hardened', 'Fully Hardened'),
        ('partially_hardened', 'Partially Hardened'),
        ('not_hardened', 'Not Hardened'),
    ]

    SOFTWARE_PATCH_CHOICES = [
        ('up_to_date', 'Up to Date'),
        ('partially_updated', 'Partially Updated'),
        ('outdated', 'Outdated'),
    ]

    NETWORK_ACCESS_COMPLEXITY_CHOICES = [
        ('multiple_steps', 'Multiple Steps'),
        ('moderate_steps', 'Moderate Steps'),
        ('direct_access', 'Direct Access'),
    ]

    AUTHENTICATION_CHOICES = [
        ('none', 'None'),
        ('single_factor', 'Single Factor'),
        ('multi_factor', 'Multi Factor'),
    ]

    USER_PRIVILEGE_CHOICES = [
        ('none', 'None'),
        ('basic_user', 'Basic User'),
        ('admin_or_elevated', 'Admin or Elevated'),
    ]

    ACCESS_CONTROL_STRENGTH_CHOICES = [
        ('weak', 'Weak'),
        ('moderate', 'Moderate'),
        ('strong', 'Strong'),
    ]

    SECURITY_REQUIREMENT_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('not_defined', 'Not Defined'),
    ]

    ASSET_CRITICALITY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    DATA_SENSITIVITY_CHOICES = [
        ('highly_sensitive', 'Highly Sensitive'),
        ('operationally_critical', 'Operationally Critical'),
        ('non_sensitive', 'Non-sensitive'),
    ]

    ENCRYPTION_PROTECTION_CHOICES = [
        ('strong', 'Strong'),
        ('moderate', 'Moderate'),
        ('weak', 'Weak'),
    ]

    AVAILABILITY_REDUNDANCY_CHOICES = [
        ('high', 'High'),
        ('moderate', 'Moderate'),
        ('low', 'Low'),
    ]

    ASSET_DEPENDENCY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    CONNECTION_SECURITY_CHOICES = [
        ('strong', 'Strong'),
        ('moderate', 'Moderate'),
        ('weak', 'Weak'),
    ]

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    tp = models.CharField(max_length=20, choices=TP_CHOICES)
    exposure_level = models.CharField(max_length=20, choices=EXPOSURE_LEVEL_CHOICES)
    network_segmentation = models.CharField(max_length=20, choices=NETWORK_SEGMENTATION_CHOICES)
    firewall_configuration = models.CharField(max_length=50, choices=FIREWALL_CONFIGURATION_CHOICES)
    vpn_access = models.CharField(max_length=20, choices=VPN_ACCESS_CHOICES)
    ssh_remote_access = models.CharField(max_length=5, choices=TRUE_FALSE_CHOICES)
    physical_access_required = models.CharField(max_length=5, choices=TRUE_FALSE_CHOICES)

    security_controls_waf = models.CharField(max_length=7, choices=PRESENT_ABSENT_CHOICES)
    security_controls_firewall = models.CharField(max_length=7, choices=PRESENT_ABSENT_CHOICES)
    security_controls_ids = models.CharField(max_length=7, choices=PRESENT_ABSENT_CHOICES)
    security_controls_ips = models.CharField(max_length=7, choices=PRESENT_ABSENT_CHOICES)
    security_controls_edr = models.CharField(max_length=7, choices=PRESENT_ABSENT_CHOICES)

    system_hardening_level = models.CharField(max_length=20, choices=SYSTEM_HARDENING_CHOICES)
    software_patch_level = models.CharField(max_length=20, choices=SOFTWARE_PATCH_CHOICES)
    network_access_complexity = models.CharField(max_length=20, choices=NETWORK_ACCESS_COMPLEXITY_CHOICES)

    authentication_requirement = models.CharField(max_length=20, choices=AUTHENTICATION_CHOICES)
    user_privilege_level_required = models.CharField(max_length=20, choices=USER_PRIVILEGE_CHOICES)
    access_control_strength = models.CharField(max_length=10, choices=ACCESS_CONTROL_STRENGTH_CHOICES)
    privilege_escalation_protection = models.CharField(max_length=7, choices=PRESENT_ABSENT_CHOICES)

    user_awareness_level = models.CharField(max_length=5, choices=[('low', 'Low'), ('high', 'High')])

    security_requirements_confidentiality = models.CharField(max_length=15, choices=SECURITY_REQUIREMENT_CHOICES)
    security_requirements_integrity = models.CharField(max_length=15, choices=SECURITY_REQUIREMENT_CHOICES)
    security_requirements_availability = models.CharField(max_length=15, choices=SECURITY_REQUIREMENT_CHOICES)

    asset_criticality = models.CharField(max_length=6, choices=ASSET_CRITICALITY_CHOICES)
    data_sensitivity = models.CharField(max_length=25, choices=DATA_SENSITIVITY_CHOICES)
    encryption_protection_level = models.CharField(max_length=8, choices=ENCRYPTION_PROTECTION_CHOICES)
    availability_redundancy = models.CharField(max_length=8, choices=AVAILABILITY_REDUNDANCY_CHOICES)

    asset_dependency_level = models.CharField(max_length=6, choices=ASSET_DEPENDENCY_CHOICES)
    connected_systems_criticality = models.CharField(max_length=6, choices=ASSET_DEPENDENCY_CHOICES)
    network_connectivity = models.CharField(max_length=6, choices=ASSET_DEPENDENCY_CHOICES)
    cascading_impact_potential = models.CharField(max_length=6, choices=ASSET_DEPENDENCY_CHOICES)
    connection_security_controls = models.CharField(max_length=8, choices=CONNECTION_SECURITY_CHOICES)


    def __str__(self):
        return f"{self.name} ({self.version})"
