from django.db import models


class NetworkAccessibilityChoices(models.TextChoices):
    PUBLIC_UNPROTECTED = 'Public_Unprotected', 'Publicly accessible with no WAF/firewall'
    PUBLIC_BEHIND_WAF = 'Public_Behind_WAF', 'Publicly accessible, filtered by a WAF'
    PRIVATE_VPN_ONLY = 'Private_VPN_Access_Only', 'Reachable only via corporate VPN'
    PRIVATE_CORPORATE = 'Private_Corporate_Network', 'Accessible on the general internal network'
    PRIVATE_RESTRICTED = 'Private_Highly_Restricted_Segment', 'Accessible only from a secure, isolated segment'
    LOCAL_ONLY = 'Local_Only', 'Requires local (console) access'
    PHYSICAL_ONLY = 'Physical_Only', 'Requires physical interaction'


class RemoteManagementChoices(models.TextChoices):
    PUBLIC = 'Publicly_Exposed', 'Administrative ports are open to the internet'
    INTERNAL = 'Internal_Only', 'Administrative ports are internal-only'
    DISABLED = 'Disabled', 'All remote administrative services are disabled'


class HardeningLevelChoices(models.TextChoices):
    NONE = 'Not_Hardened', 'Default, out-of-the-box installation'
    PARTIAL = 'Partially_Hardened', 'Basic security best practices applied'
    FULL = 'Fully_Hardened', 'Strictly configured per a security standard (e.g., CIS)'


class PatchLevelChoices(models.TextChoices):
    OUTDATED = 'Outdated', 'Missing known critical/high severity patches'
    PARTIAL = 'Partially_Updated', 'Lags behind the latest patches but criticals are applied'
    FULL = 'Fully_Patched', 'Robust, automated process ensures patches are applied promptly'


class NetworkProtectionChoices(models.TextChoices):
    NONE = 'Not_Present', 'No IPS/NGFW inspection is performed'
    MONITORING = 'Monitoring_Only', 'IDS is in place (logs but does not block)'
    BLOCKING = 'Active_Blocking', 'IPS is in place and configured to drop malicious traffic'


class EndpointProtectionChoices(models.TextChoices):
    NONE = 'Not_Present', 'No EDR or advanced agent installed'
    MONITORING = 'Monitoring_Only', 'Agent logs suspicious activity without blocking'
    BLOCKING = 'Active_Blocking', 'Agent is configured to actively block and quarantine threats'


class PresentAbsentChoices(models.TextChoices):
    PRESENT = 'Present', 'The control is present and active'
    ABSENT = 'Absent', 'The control is not present'


class AuthStrengthChoices(models.TextChoices):
    NONE = 'None', 'No authentication is required for access'
    SINGLE_FACTOR = 'Single_Factor', 'Requires a single piece of evidence (e.g., password)'
    MULTI_FACTOR = 'Multi_Factor', 'Requires two or more independent verification methods'


class UserAwarenessChoices(models.TextChoices):
    UNTRAINED = 'Untrained', 'Users are not trained on security best practices'
    STANDARD = 'Standard', 'Users have received basic security awareness training'
    AWARE = 'Security_Aware', 'Users are well-trained and regularly tested'


class RequirementChoices(models.TextChoices):
    LOW = 'Low', 'Low Requirement'
    MEDIUM = 'Medium', 'Medium Requirement'
    HIGH = 'High', 'High Requirement'


class CriticalityChoices(models.TextChoices):
    LOW = 'Low', 'Low: Non-essential asset, minimal operational impact'
    MEDIUM = 'Medium', 'Medium: Supports important business functions'
    HIGH = 'High', 'High: Supports critical business functions'
    MISSION_CRITICAL = 'Mission-Critical', 'Mission-Critical: Core to business survival'


class DataSensitivityChoices(models.TextChoices):
    NONE = 'None', 'Public or non-sensitive data'
    INTERNAL = 'Internal', 'Internal use only; minor harm if disclosed'
    CONFIDENTIAL = 'Confidential', 'Sensitive data (e.g., PII); significant harm if disclosed'
    RESTRICTED = 'Highly-Restricted', 'Regulated data; severe harm if disclosed'


class RedundancyChoices(models.TextChoices):
    NONE = 'None', 'Single point of failure; no redundancy'
    PARTIAL = 'Partial', 'Warm or cold standby systems are available'
    HIGH = 'High', 'Fully redundant with automated, seamless failover'


class EncryptionChoices(models.TextChoices):
    NONE = 'None', 'Data is stored in plaintext'
    WEAK = 'Weak', 'Uses outdated or easily broken encryption'
    STRONG = 'Strong', 'Uses modern, industry-standard strong encryption (e.g., AES-256)'


class PropagationRiskChoices(models.TextChoices):
    LOW = 'Low', 'Asset is highly isolated, making lateral movement difficult'
    MEDIUM = 'Medium', 'Asset is on a standard network with some ability to connect to other systems'
    HIGH = 'High', 'Asset is a prime pivot point (e.g., jump box, domain controller)'

class IntegrityProtectionChoices(models.TextChoices):
    NONE = 'None', 'No specific integrity protection mechanisms are in place.'
    MONITORING = 'Monitoring', 'File Integrity Monitoring (FIM) or similar logging is active to detect unauthorized changes.'
    PREVENTIVE = 'Preventive', 'Strict controls like digital signatures, immutable storage, or HSMs are used to actively prevent modification.'

class Asset(models.Model):

    TP_CHOICES = [
        ('database', 'Database'),
        ('application', 'Application'),
        ('webserver', 'Webserver'),
        ('security_tools', 'Security Tools'),
    ]

    # Core Identification
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    tp = models.CharField(max_length=20, choices=TP_CHOICES)

    # Business Context
    asset_criticality = models.CharField(max_length=20, choices=CriticalityChoices.choices,
                                         default=CriticalityChoices.MEDIUM,
                                         help_text="The asset's operational importance to the business.")
    data_sensitivity = models.CharField(max_length=20, choices=DataSensitivityChoices.choices,
                                        default=DataSensitivityChoices.INTERNAL,
                                        help_text="Sensitivity of the data the asset handles.")

    # Security Requirements
    security_requirement_confidentiality = models.CharField(max_length=10, choices=RequirementChoices.choices,
                                                            default=RequirementChoices.MEDIUM)
    security_requirement_integrity = models.CharField(max_length=10, choices=RequirementChoices.choices,
                                                      default=RequirementChoices.MEDIUM)
    security_requirement_availability = models.CharField(max_length=10, choices=RequirementChoices.choices,
                                                         default=RequirementChoices.MEDIUM)

    # Network & Access Posture
    network_accessibility = models.CharField(max_length=40, choices=NetworkAccessibilityChoices.choices,
                                             default=NetworkAccessibilityChoices.PRIVATE_CORPORATE)
    remote_management_access = models.CharField(max_length=20, choices=RemoteManagementChoices.choices,
                                                default=RemoteManagementChoices.INTERNAL)

    # System Configuration & Hardening
    system_hardening_level = models.CharField(max_length=20, choices=HardeningLevelChoices.choices,
                                              default=HardeningLevelChoices.PARTIAL)
    software_patch_level = models.CharField(max_length=20, choices=PatchLevelChoices.choices,
                                            default=PatchLevelChoices.PARTIAL)
    availability_redundancy = models.CharField(max_length=10, choices=RedundancyChoices.choices,
                                               default=RedundancyChoices.NONE)
    data_encryption_level = models.CharField(max_length=10, choices=EncryptionChoices.choices,
                                             default=EncryptionChoices.NONE)
    integrity_protection_level = models.CharField(max_length=20, choices=IntegrityProtectionChoices.choices,
                                                 default=IntegrityProtectionChoices.NONE)

    # Compensating Security Controls
    network_protection = models.CharField(max_length=20, choices=NetworkProtectionChoices.choices,
                                          default=NetworkProtectionChoices.NONE)
    endpoint_protection = models.CharField(max_length=20, choices=EndpointProtectionChoices.choices,
                                           default=EndpointProtectionChoices.NONE)
    privilege_escalation_protection = models.CharField(max_length=10, choices=PresentAbsentChoices.choices,
                                                       default=PresentAbsentChoices.ABSENT)

    # User & Authentication Context
    authentication_strength = models.CharField(max_length=20, choices=AuthStrengthChoices.choices,
                                               default=AuthStrengthChoices.SINGLE_FACTOR)
    user_awareness_level = models.CharField(max_length=20, choices=UserAwarenessChoices.choices,
                                            default=UserAwarenessChoices.STANDARD)

    # Downstream Impact
    propagation_risk = models.CharField(max_length=10, choices=PropagationRiskChoices.choices,
                                        default=PropagationRiskChoices.MEDIUM)
    subsequent_system_confidentiality_req = models.CharField(max_length=20, choices=RequirementChoices.choices,
                                                             default=RequirementChoices.MEDIUM)
    subsequent_system_integrity_req = models.CharField(max_length=20, choices=RequirementChoices.choices,
                                                       default=RequirementChoices.MEDIUM)
    subsequent_system_availability_req = models.CharField(max_length=20, choices=RequirementChoices.choices,
                                                          default=RequirementChoices.MEDIUM)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.version})"
