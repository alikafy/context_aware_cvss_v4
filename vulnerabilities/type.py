import dataclasses
from typing import Literal, List


@dataclasses.dataclass
class CWEData:
    id: str
    description: str


@dataclasses.dataclass
class Metric:
    value: str
    metric_symbol: str = dataclasses.field(init=False)
    values_description: dict = None
    description: str = None


@dataclasses.dataclass
class AV(Metric):
    value: Literal["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"]
    metric_symbol = 'AV'
    possible_values = ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL", "NOT_DEFINED"]


@dataclasses.dataclass
class AC(Metric):
    value: Literal["LOW", "HIGH"]
    metric_symbol = 'AC'
    possible_values = ["LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class AT(Metric):
    value: Literal["NONE", "PRESENT"]
    metric_symbol = 'AT'
    possible_values = ["NONE", "PRESENT", "NOT_DEFINED"]


@dataclasses.dataclass
class PR(Metric):
    value: Literal["NONE", "LOW", "HIGH"]
    metric_symbol = 'PR'
    possible_values = ["NONE", "LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class UI(Metric):
    value: Literal["NONE", "PASSIVE", "ACTIVE"]
    metric_symbol = 'UI'
    possible_values = ["NONE", "PASSIVE", "ACTIVE", "NOT_DEFINED"]


@dataclasses.dataclass
class VC(Metric):
    metric_symbol = 'VC'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class VI(Metric):
    metric_symbol = 'VI'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class VA(Metric):
    metric_symbol = 'VA'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class SC(Metric):
    metric_symbol = 'SC'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "NEGLIGIBLE", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class SI(Metric):
    metric_symbol = 'SI'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "NEGLIGIBLE", "HIGH", "SAFETY", "NOT_DEFINED"]


@dataclasses.dataclass
class SA(Metric):
    metric_symbol = 'SA'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "NEGLIGIBLE", "HIGH", "SAFETY", "NOT_DEFINED"]


@dataclasses.dataclass
class BaseMetric:
    AV: AV
    AC: AC
    AT: AT
    PR: PR
    UI: UI
    VC: VC
    VI: VI
    VA: VA
    SC: SC
    SI: SI
    SA: SA
    score: float
    severity: str
    description: str = ''

@dataclasses.dataclass
class CVEData:
    id: str
    cve_description: str
    cve_status: str
    weaknesses: List[CWEData]
    base_metric: BaseMetric


@dataclasses.dataclass
class Asset:
    id: int
    name: str
    version: str
    tp: Literal['database', 'application', 'webserver', 'security_tools']
    exposure_level: Literal["external", "internal", "local", "physical"]
    network_segmentation: Literal["isolated", "highly_isolated", "none"]
    firewall_configuration: Literal["allow_external_inbound", "block_external_allow_internal_only", "block_internal_external_inbound"]
    vpn_access: Literal["required", "not_required"]
    ssh_remote_access: Literal["true", "false"]
    physical_access_required: Literal["true", "false"] # ?

    security_controls_waf: Literal["present", "absent"]
    security_controls_firewall: Literal["present", "absent"]
    security_controls_ids: Literal["present", "absent"]
    security_controls_ips: Literal["present", "absent"]
    security_controls_edr: Literal["present", "absent"]
    system_hardening_level: Literal["fully_hardened", "partially_hardened", "not_hardened"] # ?
    software_patch_level: Literal["up_to_date", "partially_updated", "outdated"]
    network_access_complexity: Literal["multiple_steps", "moderate_steps", "direct_access"]

    authentication_requirement: Literal["none", "single_factor", "multi_factor"]
    user_privilege_level_required: Literal["none", "basic_user", "admin_or_elevated"]
    access_control_strength: Literal["weak", "moderate", "strong"]
    privilege_escalation_protection: Literal["present", "absent"]

    user_awareness_level: Literal["low", "high"]

    security_requirements_confidentiality: Literal["high", "medium", "low", "not_defined"]
    security_requirements_integrity: Literal["high", "medium", "low", "not_defined"]
    security_requirements_availability: Literal["high", "medium", "low", "not_defined"]

    asset_criticality: Literal["high", "medium", "low"]
    data_sensitivity: Literal["highly_sensitive", "operationally_critical", "non_sensitive"]
    encryption_protection_level: Literal["strong", "moderate", "weak"]
    availability_redundancy: Literal["high", "moderate", "low"]

    asset_dependency_level: Literal["high", "medium", "low"]
    connected_systems_criticality: Literal["high", "medium", "low"]
    network_connectivity: Literal["high", "medium", "low"]
    cascading_impact_potential: Literal["high", "medium", "low"]
    connection_security_controls: Literal["strong", "moderate", "weak"]
    is_active: int

    def __str__(self):
        return f"""
                name={self.name}
                version={self.version}
                tp={self.tp}
                exposure_level={self.exposure_level}
                network_segmentation={self.network_segmentation}
                firewall_configuration={self.firewall_configuration}
                vpn_access={self.vpn_access}
                ssh_remote_access={self.ssh_remote_access}
                physical_access_required={self.physical_access_required}        
                security_controls_waf={self.security_controls_waf}
                security_controls_firewall={self.security_controls_firewall}
                security_controls_ids={self.security_controls_ids}
                security_controls_ips={self.security_controls_ips}
                security_controls_edr={self.security_controls_edr}
                system_hardening_level={self.system_hardening_level}
                software_patch_level={self.software_patch_level}
                network_access_complexity={self.network_access_complexity}
                authentication_requirement={self.authentication_requirement}
                user_privilege_level_required={self.user_privilege_level_required}
                access_control_strength={self.access_control_strength}
                privilege_escalation_protection={self.privilege_escalation_protection}
                user_awareness_level={self.user_awareness_level}
                security_requirements_confidentiality={self.security_requirements_confidentiality}
                security_requirements_integrity={self.security_requirements_integrity}
                security_requirements_availability={self.security_requirements_availability}
                asset_criticality={self.asset_criticality}
                data_sensitivity={self.data_sensitivity}
                encryption_protection_level={self.encryption_protection_level}
                availability_redundancy={self.availability_redundancy}
                asset_dependency_level={self.asset_dependency_level}
                connected_systems_criticality={self.connected_systems_criticality}
                network_connectivity={self.network_connectivity}
                cascading_impact_potential={self.cascading_impact_potential}
                connection_security_controls={self.connection_security_controls}
        """

metrics_abbreviation={
    "NETWORK": "N",
    "ADJACENT": "A",
    "LOCAL": "L",
    "PHYSICAL": "P",
    "LOW": "L",
    "HIGH": "H",
    "NONE": "N",
    "PRESENT": "P",
    "PASSIVE": "P",
    "ACTIVE": "A",
    "NOT_DEFINED": "X",
    "NEGLIGIBLE": "N",
    "SAFETY": "S",
}

not_defined = {'Not Defined (X)': 'This is the default value. Assigning this value indicates there is insufficient information to choose one of the other values. This has the same effect as assigning High as the worst case.'}

