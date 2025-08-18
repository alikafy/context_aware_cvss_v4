from assets.models import Asset
from vulnerabilities.models import Vulnerability, Response
from vulnerabilities.sevcies.ask_agent import make_request
from vulnerabilities.sevcies.cvss_v4 import calculate_environmental_metric, convert_to_abbreviations, fetch_metrics
from vulnerabilities.type import BaseMetric, metrics_abbreviation


class AgentCalculator:
    def __init__(self, vuln: Vulnerability, asset: Asset, model_name: str):
        self.vuln = vuln
        self.base_metric = fetch_metrics(vuln.base_vector)
        self.asset = asset
        self.model_name = model_name

    def calculate(self):
        agent_answer = self.agent_answer()
        try:
            cvss_values = self.prepare_agent_answer_for_calculator(agent_answer)
            score, severity = calculate_environmental_metric(cvss_values)
        except Exception as e:
            score, severity = None, None
        agent_answer.update({'score': score, 'severity': severity})
        Response.objects.update_or_create(
            impacted_asset=self.asset,
            vulnerability=self.vuln,
            defaults={
                'agent_response': agent_answer,
                'agent_score': score,
            }
        )
        return agent_answer

    def agent_answer(self):
        modified_metrics = {
            'modified_metrics': {},
            'rationale': {},
            'confidence': {}
        }
        prompts = PromptCreator(self.vuln, self.asset, self.base_metric)

        response = make_request(prompts.attack_vector, model=self.model_name)
        modified_metrics['modified_metrics']['MAV'] = response.get('modified_metrics', {}).get('MAV', 'NOT_DEFINED')
        modified_metrics['confidence']['MAV'] = response.get('confidence', {}).get('MAV', None)
        modified_metrics['rationale']['MAV'] = response.get('rationale', {}).get('MAV', None)

        response = make_request(prompts.attack_complicity, model=self.model_name)
        modified_metrics['modified_metrics']['MAC'] = response.get('modified_metrics', {}).get('MAC', 'NOT_DEFINED')
        modified_metrics['confidence']['MAC'] = response.get('confidence', {}).get('MAC', None)
        modified_metrics['rationale']['MAC'] = response.get('rationale', {}).get('MAC', None)

        response = make_request(prompts.attack_required, model=self.model_name)
        modified_metrics['modified_metrics']['MAT'] = response.get('modified_metrics', {}).get('MAT', 'NOT_DEFINED')
        modified_metrics['confidence']['MAT'] = response.get('confidence', {}).get('MAT', None)
        modified_metrics['rationale']['MAT'] = response.get('rationale', {}).get('MAT', None)

        response = make_request(prompts.privilege_required, model=self.model_name)
        modified_metrics['modified_metrics']['MPR'] = response.get('modified_metrics', {}).get('MPR', 'NOT_DEFINED')
        modified_metrics['confidence']['MPR'] = response.get('confidence', {}).get('MPR', None)
        modified_metrics['rationale']['MPR'] = response.get('rationale', {}).get('MPR', None)

        response = make_request(prompts.user_interaction, model=self.model_name)
        modified_metrics['modified_metrics']['MUI'] = response.get('modified_metrics', {}).get('MUI', 'NOT_DEFINED')
        modified_metrics['confidence']['MUI'] = response.get('confidence', {}).get('MUI', None)
        modified_metrics['rationale']['MUI'] = response.get('rationale', {}).get('MUI', None)

        response = make_request(prompts.vulnerable_system, model=self.model_name)
        modified_metrics['modified_metrics']['MVA'] = response.get('modified_metrics', {}).get('MVA', 'NOT_DEFINED')
        modified_metrics['confidence']['MVA'] = response.get('confidence', {}).get('MVA', None)
        modified_metrics['rationale']['MVA'] = response.get('rationale', {}).get('MVA', None)
        modified_metrics['modified_metrics']['MVC'] = response.get('modified_metrics', {}).get('MVC', 'NOT_DEFINED')
        modified_metrics['confidence']['MVC'] = response.get('confidence', {}).get('MVC', None)
        modified_metrics['rationale']['MVC'] = response.get('rationale', {}).get('MVC', None)
        modified_metrics['modified_metrics']['MVI'] = response.get('modified_metrics', {}).get('MVI', 'NOT_DEFINED')
        modified_metrics['confidence']['MVI'] = response.get('confidence', {}).get('MVI', None)
        modified_metrics['rationale']['MVI'] = response.get('rationale', {}).get('MVI', None)

        response = make_request(prompts.vulnerable_sub_system, model=self.model_name)
        modified_metrics['modified_metrics']['MSA'] = response.get('modified_metrics', {}).get('MSA', 'NOT_DEFINED')
        modified_metrics['confidence']['MSA'] = response.get('confidence', {}).get('MSA', None)
        modified_metrics['rationale']['MSA'] = response.get('rationale', {}).get('MSA', None)
        modified_metrics['modified_metrics']['MSC'] = response.get('modified_metrics', {}).get('MSC', 'NOT_DEFINED')
        modified_metrics['confidence']['MSC'] = response.get('confidence', {}).get('MSC', None)
        modified_metrics['rationale']['MSC'] = response.get('rationale', {}).get('MSC', None)
        modified_metrics['modified_metrics']['MSI'] = response.get('modified_metrics', {}).get('MSI', 'NOT_DEFINED')
        modified_metrics['confidence']['MSI'] = response.get('confidence', {}).get('MSI', None)
        modified_metrics['rationale']['MSI'] = response.get('rationale', {}).get('MSI', None)

        return modified_metrics

    def prepare_agent_answer_for_calculator(self, answer: dict):
        base = {
            "AV": metrics_abbreviation[self.base_metric.AV.value],
            "AC": metrics_abbreviation[self.base_metric.AC.value],
            "AT": metrics_abbreviation[self.base_metric.AT.value],
            "PR": metrics_abbreviation[self.base_metric.PR.value],
            "UI": metrics_abbreviation[self.base_metric.UI.value],
            "VC": metrics_abbreviation[self.base_metric.VC.value],
            "VI": metrics_abbreviation[self.base_metric.VI.value],
            "VA": metrics_abbreviation[self.base_metric.VA.value],
            "SC": metrics_abbreviation[self.base_metric.SC.value],
            "SI": metrics_abbreviation[self.base_metric.SI.value],
            "SA": metrics_abbreviation[self.base_metric.SA.value]
        }
        env = {
            "MAV": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MAV", "X")),
            "MAC": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MAC", "X")),
            "MAT": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MAT", "X")),
            "MPR": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MPR", "X")),
            "MUI": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MUI", "X")),
            "MVC": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MVC", "X")),
            "MVI": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MVI", "X")),
            "MVA": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MVA", "X")),
            "MSC": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MSC", "X")),
            "MSI": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MSI", "X")),
            "MSA": convert_to_abbreviations(answer.get("modified_metrics", {}).get("MSA", "X")),
        }

        req = {
            "CR": metrics_abbreviation[self.asset.security_requirements_confidentiality.upper()],
            "IR": metrics_abbreviation[self.asset.security_requirements_integrity.upper()],
            "AR": metrics_abbreviation[self.asset.security_requirements_availability.upper()]
        }
        return {**base, **env, **req}


class AssetAttributeDescription:

    @property
    def exposure_level(self):
        return """
          exposure_level: Describes asset reachability.
            - external: Publicly reachable via internet/external networks
            - internal: Accessible only via internal networks
            - local: Requires local (host-level) access
            - physical:	Requires physical access
        """

    @property
    def network_segmentation(self):
        return """
            network_segmentation: Defines how asset is isolated from other networks.
                - none No: isolation; directly reachable
                - isolated: Asset isolated from external network; reachable internally
                - highly isolated: Requires special local connectivity
        """

    @property
    def firewall_configuration(self):
        return """
            firewall_configuration: Defines firewall rules impacting inbound access.
                - allow external inbound: Asset reachable externally
                - block external, allow internal only: Asset reachable internally only
                - block internal & external inbound:Requires local/physical access
        """

    @property
    def vpn_access(self):
        return """
            vpn_access: Defines VPN requirement to reach the asset.
                - required: Asset reachable only via VPN
                - not required: Asset directly reachable without VPN
        """

    @property
    def ssh_remote_access(self):
        return """
            ssh_remote_access: Determines public accessibility via SSH or Remote Desktop.
                - true: Remote access publicly accessible externally
                - false: Remote access not publicly accessible
        """

    @property
    def physical_access_required(self):
        return """
            physical_access_required: Indicates if physical presence is required.
                - true: Asset requires physical access
                - false: No physical access required
        """

    @property
    def security_controls(self):
        return """
            security_controls_waf:
                - present
                - absent
            security_controls_firewall:
                - present
                - absent
            security_controls_ids:
                - present
                - absent
            security_controls_ips:
                - present
                - absent
            security_controls_edr:
                - present
                - absent
        """

    @property
    def system_hardening_level(self):
        return """
            system_hardening_level:
                - fully_hardened: Strict configurations, minimal attack surface
                - partially_hardened: Some default settings, moderate protection
                - not_hardened: Default settings, easy exploitation
        """

    @property
    def software_patch_level(self):
        return """
            software_patch_level:
                - up_to_date: Fully updated, latest security patches
                - partially_updated: Some critical patches missing
                - outdated: No recent security patches
        """

    @property
    def network_access_complexity(self):
        return """
            network_access_complexity:
                - multiple_steps: Requires multiple complex network steps
                - moderate_steps: Requires moderate network steps or pivoting
                - direct_access: Direct access without network pivoting required
        """

    @property
    def authentication_requirement(self):
        return """
            authentication_requirement: Describes the authentication necessary for accessing the asset.
                - none: No authentication required
                - single-factor: Requires single-factor authentication (password, token)
                - multi-factor(MFA): Requires multi-factor authentication
        """

    @property
    def user_privilege_level_required(self):
        return """
            user_privilege_level_required: Describes the privilege level required for exploiting the vulnerability.
                - none: No privileges required
                - basic_user: Basic user privileges required
                - admin_or_elevated: Administrative or elevated privileges required
        """

    @property
    def access_control_strength(self):
        return """
            access_control_strength: Defines how strictly permissions and authorization controls are implemented.
                - weak: Easily bypassed, minimal controls
                - moderate: Moderate permissions, typical ACL rules
                - strong: Robust access control mechanisms in place
        """

    @property
    def privilege_escalation_protection(self):
        return """
            privilege_escalation_protection: Indicates the presence of controls specifically designed to prevent privilege escalation.
                - present: Privilege escalation is actively prevented
                - absent: No specific escalation protections
        """

    @property
    def user_awareness_level(self):
        return """
            user_awareness_level:Indicates whether users interacting with the system are trained or aware of security best practices.
                - low: Users unaware, prone to risky actions
                - high: Users well-trained, less likely interaction
        """

    @property
    def security_requirements(self):
        return """
            security_requirements_confidentiality: These values are set explicitly per asset based on importance defined by SOC teams or organizational policies.
                - High (H)
                - Medium (M)
                - Low (L)
            security_requirements_integrity: These values are set explicitly per asset based on importance defined by SOC teams or organizational policies.
                - High (H)
                - Medium (M)
                - Low (L)
            security_requirements_availability: These values are set explicitly per asset based on importance defined by SOC teams or organizational policies.
                - High (H)
                - Medium (M)
                - Low (L)
        """

    @property
    def asset_criticality(self):
        return """
            asset_criticality
                - high: Mission-critical asset
                - medium: Important, but not mission-critical
                - low: Non-critical, minimal operational impact
        """

    @property
    def data_sensitivity(self):
        return """
            data_sensitivity: Identifies the sensitivity of data or functions asset manages.
                - highly_sensitive: Financial, healthcare, private user data
                - operationally_critical: Core infrastructure, critical operational systems
                - non_sensitive: Public data, minimal impact on operation
        """

    @property
    def encryption_protection_level(self):
        return """
            encryption_protection_level: Affects impact specifically on Confidentiality and Integrity.
                - strong: Strong encryption/data protection mechanisms
                - moderate: Moderate encryption/data protection
                - weak: Minimal or no encryption/protection
        """

    @property
    def availability_redundancy(self):
        return """
            availability_redundancy: Influences Availability impact:
                - high: Redundant systems, high availability/failover
                - moderate: Partial redundancy
                - low: No redundancy or failover options
        """

    @property
    def asset_dependency_level(self):
        return """
            asset_dependency_level: Defines how other systems rely on this asset.
                - high: Many critical systems directly dependent
                - medium: Some systems moderately dependent
                -low: Few or no critical dependencies
        """

    @property
    def connected_systems_criticality(self):
        return """
            connected_systems_criticality
                - high: Connected systems are highly critical
                - medium: Connected systems moderately critical
                - low: Connected systems have minimal criticality
        """

    @property
    def network_connectivity(self):
        return """
            network_connectivity
                - direct_access: Asset directly connected without controls
                - indirect_access: Asset indirectly connected with some controls
                - isolated: Asset mostly isolated, minimal connectivity
        """

    @property
    def cascading_impact_potential(self):
        return """
            cascading_impact_potential
                - high: Compromise easily propagates to subsequent system
                - moderate: Moderate propagation potential
                - low: Minimal propagation potential
        """

    @property
    def connection_security_controls(self):
        return """
            connection_security_controls
                - strong: Robust isolation and controls
                - moderate: Some controls but partial propagation
                - weak: Minimal or no effective controls
        """


class PromptCreator:
    asset_description = AssetAttributeDescription()

    def __init__(self, vuln: Vulnerability, asset: Asset = None, base_metrics: BaseMetric = None):
        self.vuln = vuln
        self.asset = asset
        self.base_metrics = base_metrics

    def role(self, metric: str):
        return f"""
                ### ROLE
                You are a careful security analyst applying CVSS v4 Environmental metrics.
                Use the provided CVE text and descriptions. If evidence is uncertain, keep the initial value.
                Only output JSON with keys: modified_metrics (just dict of {metric} and just abbreviations values), rationale (dict per metric), and confidence (dict per metric with values High|Medium|Low).
                You can use the descriptions of the metrics and their values provided below. The descriptions for Modified Base Metrics are the same as for the corresponding Base Metrics. For example, MAV (Modified Attack Vector) uses the same description as AV (Attack Vector) and values.                

                ### 1. INPUT - Vulnerability Details
                CVE_ID: {self.vuln.id}
                Description: {self.vuln.cve_description}  
                Base_Score: {self.vuln.base_score} ({self.vuln.base_severity})  
                Vuln_Status: {self.vuln.cve_status} 
                Weakness: {self.vuln.weaknesses} 
                BASE METRIC VALUES: AV={self.base_metrics.AV.value},AC={self.base_metrics.AV.value},AT={self.base_metrics.AV.value},PR={self.base_metrics.AV.value},UI={self.base_metrics.AV.value},VC={self.base_metrics.AV.value},VI={self.base_metrics.AV.value},VA={self.base_metrics.AV.value},SC={self.base_metrics.AV.value},SI={self.base_metrics.AV.value},SA={self.base_metrics.AV.value}
        """

    @property
    def attack_vector(self):
        return f"""
                {self.role("MAV")}
                Attack Vector (AV): {self.base_metrics.AV.description}
                AV values: {self.base_metrics.AV.values_description}

                ### 2. INPUT - Asset Context
                name = “{self.asset.name}”  
                version = {self.asset.version}  
                type = {self.asset.tp}

                ## Asset field explanation
                {self.asset_description.exposure_level}
                {self.asset_description.network_segmentation}
                {self.asset_description.firewall_configuration}
                {self.asset_description.vpn_access}
                {self.asset_description.ssh_remote_access}
                {self.asset_description.physical_access_required}
                {self.asset_description.security_controls}

                | Category | Value |
                |---|---|
                | exposure_level | {self.asset.exposure_level} |
                | network_segmentation | {self.asset.network_segmentation} |
                | firewall_configuration | {self.asset.firewall_configuration} |
                | vpn_access | {self.asset.vpn_access} |
                | ssh_remote_access | {self.asset.ssh_remote_access} |
                | physical_access_required | {self.asset.physical_access_required} |
                | security_controls_waf | {self.asset.security_controls_waf} |
                | security_controls_firewall | {self.asset.security_controls_firewall} |
                | security_controls_ids | {self.asset.security_controls_ids} |
                | security_controls_ips | {self.asset.security_controls_ips} |
                | security_controls_edr | {self.asset.security_controls_edr} |
        """

    @property
    def attack_complicity(self):
        return f"""
                {self.role("MAC")}
                Attack Complexity (AC): {self.base_metrics.AC.description}
                AC values: {self.base_metrics.AC.values_description}

                ### 2. INPUT - Asset Context
                name = “{self.asset.name}”  
                version = {self.asset.version}  
                type = {self.asset.tp}

                ## Asset field explanation
                {self.asset_description.exposure_level}
                {self.asset_description.network_segmentation}
                {self.asset_description.firewall_configuration}
                {self.asset_description.vpn_access}
                {self.asset_description.ssh_remote_access}
                {self.asset_description.physical_access_required}
                {self.asset_description.security_controls}
                {self.asset_description.system_hardening_level}
                {self.asset_description.software_patch_level}
                {self.asset_description.network_access_complexity}
                {self.asset_description.authentication_requirement}
                {self.asset_description.user_privilege_level_required}
                {self.asset_description.access_control_strength}
                {self.asset_description.privilege_escalation_protection}

                | Category | Value |
                |---|---|
                | exposure_level | {self.asset.exposure_level} |
                | network_segmentation | {self.asset.network_segmentation} |
                | firewall_configuration | {self.asset.firewall_configuration} |
                | vpn_access | {self.asset.vpn_access} |
                | ssh_remote_access | {self.asset.ssh_remote_access} |
                | physical_access_required | {self.asset.physical_access_required} |
                | security_controls_waf | {self.asset.security_controls_waf} |
                | security_controls_firewall | {self.asset.security_controls_firewall} |
                | security_controls_ids | {self.asset.security_controls_ids} |
                | security_controls_ips | {self.asset.security_controls_ips} |
                | security_controls_edr | {self.asset.security_controls_edr} |
                | system_hardening_level | {self.asset.system_hardening_level} |
                | software_patch_level | {self.asset.software_patch_level} |
                | network_access_complexity | {self.asset.network_access_complexity} |
                | authentication_requirement | {self.asset.authentication_requirement} |
                | user_privilege_level_required | {self.asset.user_privilege_level_required} |
                | access_control_strength | {self.asset.access_control_strength} |
                | privilege_escalation_protection | {self.asset.privilege_escalation_protection} |
        """

    @property
    def attack_required(self):
        return f"""
                {self.role("MAT")}
                Attack Requirements (AT): {self.base_metrics.AT.description}
                AT values: {self.base_metrics.AT.values_description}

                ### 2. INPUT - Asset Context
                name = “{self.asset.name}”  
                version = {self.asset.version}  
                type = {self.asset.tp}

                ## Asset field explanation
                {self.asset_description.exposure_level}
                {self.asset_description.network_segmentation}
                {self.asset_description.firewall_configuration}
                {self.asset_description.vpn_access}
                {self.asset_description.ssh_remote_access}
                {self.asset_description.physical_access_required}
                {self.asset_description.security_controls}
                {self.asset_description.system_hardening_level}
                {self.asset_description.software_patch_level}
                {self.asset_description.network_access_complexity}
                {self.asset_description.authentication_requirement}
                {self.asset_description.user_privilege_level_required}
                {self.asset_description.access_control_strength}
                {self.asset_description.privilege_escalation_protection}

                | Category | Value |
                |---|---|
                | exposure_level | {self.asset.exposure_level} |
                | network_segmentation | {self.asset.network_segmentation} |
                | firewall_configuration | {self.asset.firewall_configuration} |
                | vpn_access | {self.asset.vpn_access} |
                | ssh_remote_access | {self.asset.ssh_remote_access} |
                | physical_access_required | {self.asset.physical_access_required} |
                | security_controls_waf | {self.asset.security_controls_waf} |
                | security_controls_firewall | {self.asset.security_controls_firewall} |
                | security_controls_ids | {self.asset.security_controls_ids} |
                | security_controls_ips | {self.asset.security_controls_ips} |
                | security_controls_edr | {self.asset.security_controls_edr} |
                | system_hardening_level | {self.asset.system_hardening_level} |
                | software_patch_level | {self.asset.software_patch_level} |
                | network_access_complexity | {self.asset.network_access_complexity} |
                | authentication_requirement | {self.asset.authentication_requirement} |
                | user_privilege_level_required | {self.asset.user_privilege_level_required} |
                | access_control_strength | {self.asset.access_control_strength} |
                | privilege_escalation_protection | {self.asset.privilege_escalation_protection} |
        """

    @property
    def privilege_required(self):
        return f"""
                {self.role("MPR")}
                Privileges Required (PR): {self.base_metrics.PR.description}
                PR values: {self.base_metrics.PR.values_description}                

                ### 2. INPUT - Asset Context
                name = “{self.asset.name}”  
                version = {self.asset.version}  
                type = {self.asset.tp}

                ## Asset field explanation

                {self.asset_description.authentication_requirement}
                {self.asset_description.user_privilege_level_required}
                {self.asset_description.access_control_strength}
                {self.asset_description.privilege_escalation_protection}

                | Category | Value |
                |---|---|
                | authentication_requirement | {self.asset.authentication_requirement} |
                | user_privilege_level_required | {self.asset.user_privilege_level_required} |
                | access_control_strength | {self.asset.access_control_strength} |
                | privilege_escalation_protection | {self.asset.privilege_escalation_protection} |
        """

    @property
    def user_interaction(self):
        return f"""
                {self.role("MUI")}
                User Interaction (UI): {self.base_metrics.UI.description}
                UI values: {self.base_metrics.UI.values_description}               

                ### 2. INPUT - Asset Context
                name = “{self.asset.name}”  
                version = {self.asset.version}  
                type = {self.asset.tp}

                ## Asset field explanation

                {self.asset_description.exposure_level}
                {self.asset_description.network_segmentation}
                {self.asset_description.firewall_configuration}
                {self.asset_description.vpn_access}
                {self.asset_description.ssh_remote_access}
                {self.asset_description.physical_access_required}
                {self.asset_description.security_controls}
                {self.asset_description.system_hardening_level}
                {self.asset_description.software_patch_level}
                {self.asset_description.network_access_complexity}
                {self.asset_description.authentication_requirement}
                {self.asset_description.user_privilege_level_required}
                {self.asset_description.access_control_strength}
                {self.asset_description.privilege_escalation_protection}

                | Category | Value |
                |---|---|
                | exposure_level | {self.asset.exposure_level} |
                | network_segmentation | {self.asset.network_segmentation} |
                | firewall_configuration | {self.asset.firewall_configuration} |
                | vpn_access | {self.asset.vpn_access} |
                | ssh_remote_access | {self.asset.ssh_remote_access} |
                | physical_access_required | {self.asset.physical_access_required} |
                | security_controls_waf | {self.asset.security_controls_waf} |
                | security_controls_firewall | {self.asset.security_controls_firewall} |
                | security_controls_ids | {self.asset.security_controls_ids} |
                | security_controls_ips | {self.asset.security_controls_ips} |
                | security_controls_edr | {self.asset.security_controls_edr} |
                | system_hardening_level | {self.asset.system_hardening_level} |
                | software_patch_level | {self.asset.software_patch_level} |
                | network_access_complexity | {self.asset.network_access_complexity} |
                | authentication_requirement | {self.asset.authentication_requirement} |
                | user_privilege_level_required | {self.asset.user_privilege_level_required} |
                | access_control_strength | {self.asset.access_control_strength} |
                | privilege_escalation_protection | {self.asset.privilege_escalation_protection} |
        """

    @property
    def vulnerable_system(self):
        return f"""
                {self.role("MVC, MVI, MVA")}
                Vulnerable System Confidentiality (VC): {self.base_metrics.VC.description}
                VC values: {self.base_metrics.VC.values_description}
                Vulnerable System Integrity (VI): {self.base_metrics.VI.description}
                VI values: {self.base_metrics.VI.values_description}
                Vulnerable System Availability (VA): {self.base_metrics.VA.description}
                VA values: {self.base_metrics.VA.values_description}

                ### 2. INPUT - Asset Context
                name = “{self.asset.name}”  
                version = {self.asset.version}  
                type = {self.asset.tp}

                ## Asset field explanation

                {self.asset_description.security_requirements}
                {self.asset_description.asset_criticality}
                {self.asset_description.data_sensitivity}
                {self.asset_description.encryption_protection_level}
                {self.asset_description.availability_redundancy}

                | Category | Value |
                |---|---|
                | security_requirements_confidentiality | {self.asset.security_requirements_confidentiality} |
                | security_requirements_integrity | {self.asset.security_requirements_integrity} |
                | security_requirements_availability | {self.asset.security_requirements_availability} |
                | asset_criticality | {self.asset.asset_criticality} |
                | data_sensitivity | {self.asset.data_sensitivity} |
                | encryption_protection_level | {self.asset.encryption_protection_level} |
                | availability_redundancy | {self.asset.availability_redundancy} |
        """

    @property
    def vulnerable_sub_system(self):
        negligible = {
            'Negligible (N)': 'A successful exploit would have little to no effect on subsequent or dependent systems. Any impact would be minimal, non-persistent, and would not compromise trust or correctness of operations beyond the initially affected system.'}
        extra_integrity_values = {
            'Safety (S)': 'The exploited vulnerability will result in integrity impacts that could cause serious injury or worse (categories of &quot;Marginal&quot; or worse as described in IEC 61508) to a human actor or participant.'}
        extra_integrity_values.update(negligible)
        extra_availability_values = {
            "Safety (S)": "The exploited vulnerability will result in availability impacts that could cause serious injury or worse (categories of &quot;Marginal&quot; or worse as described in IEC 61508) to a human actor or participant."}
        extra_availability_values.update(negligible)

        return f"""
                {self.role("MSC, MSI, MSA")}
                Subsequent System Confidentiality (SC): {self.base_metrics.SC.description}
                SC values: {dict(**self.base_metrics.SC.values_description, **negligible)}
                Subsequent System Integrity (SI): {self.base_metrics.SI.description}
                SI values: {dict(**self.base_metrics.SI.values_description, **extra_integrity_values)}
                Subsequent System Availability (SA): {self.base_metrics.SA.description}
                SA values: {dict(**self.base_metrics.SA.values_description, **extra_availability_values)}

                ### 2. INPUT - Asset Context
                name = “{self.asset.name}”  
                version = {self.asset.version}  
                type = {self.asset.tp}

                ## Asset field explanation

                {self.asset_description.asset_dependency_level}
                {self.asset_description.connected_systems_criticality}
                {self.asset_description.network_connectivity}
                {self.asset_description.cascading_impact_potential}
                {self.asset_description.connection_security_controls}

                | Category | Value |
                |---|---|
                | asset_dependency_level | {self.asset.asset_dependency_level} |
                | connected_systems_criticality | {self.asset.connected_systems_criticality} |
                | network_connectivity | {self.asset.network_connectivity} |
                | cascading_impact_potential | {self.asset.cascading_impact_potential} |
                | connection_security_controls | {self.asset.connection_security_controls} |
        """
