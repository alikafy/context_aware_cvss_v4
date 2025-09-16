from assets.models import Asset
from vulnerabilities.models import Vulnerability, Response
from vulnerabilities.sevcies.ask_agent import make_request
from vulnerabilities.sevcies.cvss_v4 import calculate_environmental_metric, convert_to_abbreviations, fetch_metrics
from vulnerabilities.type import metrics_abbreviation


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
            print(e)
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

        prompts = AttackVector(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MAV'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MAV'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MAV'] = response.get('rationale', '-')

        prompts = AttackComplexity(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MAC'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MAC'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MAC'] = response.get('rationale', '-')

        prompts = AttackRequirements(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MAT'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MAT'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MAT'] = response.get('rationale', '-')

        prompts = PrivilegesRequired(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MPR'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MPR'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MPR'] = response.get('rationale', '-')

        prompts = UserInteraction(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MUI'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MUI'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MUI'] = response.get('rationale', '-')

        prompts = Availability(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MVA'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MVA'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MVA'] = response.get('rationale', '-')

        prompts = Confidentiality(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MVC'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MVC'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MVC'] = response.get('rationale', '-')

        prompts = Integrity(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MVI'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MVI'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MVI'] = response.get('rationale', '-')

        prompts = SubsequentAvailability(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MSA'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MSA'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MSA'] = response.get('rationale', '-')

        prompts = SubsequentConfidentiality(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MSC'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MSC'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MSC'] = response.get('rationale', '-')

        prompts = SubsequentIntegrity(self.vuln, self.asset, self.base_metric)
        response = make_request(prompts.prompt, model=self.model_name)
        modified_metrics['modified_metrics']['MSI'] = response.get('modified_metric', 'NOT_DEFINED')
        modified_metrics['confidence']['MSI'] = response.get('confidence', 'Low')
        modified_metrics['rationale']['MSI'] = response.get('rationale', '-')

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
            "CR": metrics_abbreviation[self.asset.security_requirement_confidentiality.upper()],
            "IR": metrics_abbreviation[self.asset.security_requirement_integrity.upper()],
            "AR": metrics_abbreviation[self.asset.security_requirement_availability.upper()]
        }
        return {**base, **env, **req}


class AssetAttributeDescription:

    @property
    def network_accessibility(self):
        return """
            network_accessibility: A single, consolidated field defining the asset's primary network access path and overall exposure.
                - Public_Unprotected: Directly accessible from the public internet (e.g., no firewall, cloud security group open to 0.0.0.0/0).
                - Public_Behind_WAF: Accessible from the internet, but all traffic is filtered through a Web Application Firewall.
                - Private_VPN_Access_Only: Not publicly exposed; requires a successful VPN connection to the corporate network to become reachable.
                - Private_Corporate_Network: Accessible from the general internal corporate network.
                - Private_Highly_Restricted_Segment: Housed in a secure, isolated network segment (e.g., PCI zone, SCADA network) requiring network pivoting or special access to reach even from the internal network.
                - Local_Only: Can only be accessed from the local operating system itself (e.g., console access).
                - Physical_Only: Requires physical interaction with the hardware.
        """

    @property
    def remote_management_access(self):
        return """
            remote_management_access: Specifies if common administrative services like SSH, RDP, or WinRM are exposed to the public internet.
                - Publicly_Exposed: Administrative ports are open to the internet.
                - Internal_Only: Administrative ports are only accessible from the internal network.
                - Disabled: All remote administrative services are disabled.
        """

    @property
    def system_hardening_level(self):
        return """
            system_hardening_level: The degree to which the asset's OS and services have been configured to reduce its attack surface.
                - Not_Hardened: Default, out-of-the-box installation with unnecessary services and default credentials.
                - Partially_Hardened: Basic security best practices have been applied (e.g., changed default passwords, disabled unused services).
                - Fully_Hardened: Strictly configured according to a recognized security standard (e.g., CIS Benchmarks, DISA STIGs).
        """

    @property
    def software_patch_level(self):
        return """
            software_patch_level: The timeliness of security patch application for the OS and critical software on the asset.
                - Outdated: Known critical or high-severity vulnerabilities have not been patched for an extended period.
                - Partially_Updated: Lags behind the latest patch releases but critical patches are eventually applied.
                - Fully_Patched: A robust, automated process ensures patches are applied promptly after release.
        """
    @property
    def network_protection(self):
        return """
            network_protection: The status of active network security controls like an Intrusion Prevention System (IPS) or Next-Gen Firewall (NGFW) monitoring traffic to the asset.
                - Not_Present: No IPS/NGFW inspection is performed.
                - Monitoring_Only: An Intrusion Detection System (IDS) is in place, logging but not blocking threats.
                - Active_Blocking: An IPS is in place and configured to actively drop malicious traffic.
        """

    @property
    def endpoint_protection(self):
        return """
            endpoint_protection: The status of Endpoint Detection & Response (EDR) or other advanced anti-malware solutions on the asset.
                - Not_Present: No EDR or advanced agent installed.
                - Monitoring_Only: The agent is installed but only logs suspicious activity without blocking.
                - Active_Blocking: The agent is configured to actively block and quarantine detected threats.
        """

    @property
    def authentication_strength(self):
        return """
            authentication_strength: The primary authentication method required to access the asset's main services or applications.
                - None: No authentication is required for access.
                - Single_Factor: Requires a single piece of evidence, typically a password or API key.
                - Multi_Factor: Requires two or more independent verification methods (e.g., password + OTP).
        """

    @property
    def privilege_escalation_protection(self):
        return """
            Privilege_escalation_protection: The presence of OS-level controls that prevent a compromised process from gaining higher privileges.
                - Absent: The operating system lacks or is not configured with specific privilege control mechanisms.
                - Present: The system uses mandatory access control or other security modules (e.g., SELinux, AppArmor, AppLocker) to contain processes.
        """

    @property
    def user_awareness_level(self):
        return """
            user_awareness_level: The general security awareness level of the typical user population that interacts with the asset.
                - Untrained: Users are not trained on security best practices and are likely to fall for social engineering.
                - Standard: Users have received basic, general security awareness training.
                - Security_Aware: Users are well-trained, regularly tested, and operate in a high-security context.
        """

    @property
    def integrity_protection_level(self):
        return """
            integrity_protection_level: Controls that prevent or detect unauthorized data/software modification.
                - None: No specific integrity protection mechanisms are in place.
                - Monitoring: File Integrity Monitoring (FIM) or similar logging is active to detect unauthorized changes.
                - Preventive: Strict controls like digital signatures, immutable storage, or HSMs are used to actively prevent modification.
        """

    @property
    def security_requirement_availability(self):
        return """
            security_requirement_availability: The organizational requirement to ensure the availability of this asset and its services.
                - Low (L): Availability is not a primary concern; downtime is acceptable.
                - Medium (M): The asset should be available during normal business operations.
                - High (H): The asset must be continuously available (24/7).
        """

    @property
    def security_requirement_confidentiality(self):
        return """
            security_requirement_confidentiality: The organizational requirement to protect the confidentiality of data on this asset.
                - Low (L): Confidentiality is not a primary concern.
                - Medium (M): Protection of data against unauthorized disclosure is important.
                - High (H): The highest level of protection against disclosure is required.
        """

    @property
    def security_requirement_integrity(self):
        return """               
            security_requirement_integrity: The organizational requirement to protect the integrity of data on this asset.
                - Low (L): Data integrity is not a primary concern.
                - Medium (M): Protection of data against unauthorized modification is important.
                - High (H): The highest level of protection against modification is required.
        """

    @property
    def asset_criticality(self):
        return """
            asset_criticality: Describes the asset's operational importance. A disruption to this asset has a direct and measurable impact on the business's primary mission.
                - Low (L): Non-essential asset, minimal operational impact if compromised.
                - Medium (M): Supports important business functions, but not mission-critical.
                - High (H): Supports critical business functions; downtime would cause significant disruption.
                - Mission_Critical: Core to the business's survival; failure threatens the viability of the organization.
        """

    @property
    def data_sensitivity(self):
        return """
            data_sensitivity: Classifies the sensitivity of the data that the asset processes, stores, or transmits, based on potential damage from disclosure.
                - None: Public or non-sensitive data.
                - Internal: Data intended for internal use only; disclosure would cause minor harm.
                - Confidential: Sensitive data like PII or proprietary business information; disclosure would cause significant harm.
                - Highly-Restricted: Regulated data (e.g., financial, health) or trade secrets; disclosure would cause severe legal, financial, or reputational damage.
        """

    @property
    def data_encryption_level(self):
        return """
            data_encryption_level: The level of encryption applied to sensitive data stored on the asset's disks or databases.
                - None: Data is stored in plaintext.
                - Weak: Uses outdated or easily broken encryption algorithms/protocols.
                - Strong: Uses modern, industry-standard strong encryption (e.g., AES-256) for all sensitive data at rest.
        """

    @property
    def availability_redundancy(self):
        return """
            availability_redundancy: The presence of failover systems or redundancy to maintain availability in case of failure.
                - None: Single point of failure; no redundancy.
                - Partial: Warm or cold standby systems are available but require manual intervention to failover.
                - High: Fully redundant with automated, seamless failover (e.g., active-active cluster, load balancing).
        """

    @property
    def propagation_risk(self):
        return """
            propagation_risk: An expert assessment of the risk that an attacker, after compromising this asset, could successfully move laterally to other systems.
                - Low: The asset is highly isolated with strict egress filtering, making lateral movement very difficult.
                - Medium: The asset is on a standard corporate network segment with some ability to connect to other systems.
                - High: The asset is a "jump box," domain controller, or has privileged access to many other critical systems, making it a prime pivot point.
        """

    @property
    def subsequent_system_confidentiality_req(self):
        return """
            subsequent_system_confidentiality_req: The highest confidentiality requirement of any downstream system that this asset connects to or controls.
                - Low: Low Requirement
                - Medium: Medium Requirement
                - High: High Requirement
        """

    @property
    def subsequent_system_integrity_req(self):
        return """
            subsequent_system_integrity_req: The highest integrity requirement of any downstream system that this asset connects to or controls.
                - Low: Low Requirement
                - Medium: Medium Requirement
                - High: High Requirement
        """

    @property
    def subsequent_system_availability_req(self):
        return """
            subsequent_system_availability_req: The highest availability requirement of any downstream system that this asset connects to or controls.
                - Low: Low Requirement
                - Medium: Medium Requirement
                - High: High Requirement
        """


class PromptCreator:
    """Base class for creating metric-specific prompts.
    This module contains classes for generating tailored prompts for a Retrieval-Augmented
    Generation (RAG) system to determine each CVSS v4.0 Environmental Metric.
"""
    METRIC = 'Base Metric'
    asset_description = AssetAttributeDescription()

    def __init__(self, vuln, asset, base_metrics):
        self.vuln = vuln
        self.asset = asset
        self.base_metrics = base_metrics

    @property
    def prompt(self):
        raise NotImplementedError("Each subclass must implement its own prompt property.")


class AttackVector(PromptCreator):
    METRIC = 'Attack Vector (MAV)'
    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the CVSS v4.0 **Modified Attack Vector (MAV)** for a given vulnerability based on the specific context of an IT asset. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  Review the **CVE Information**, noting the **Base Attack Vector (AV)**.
2.  Analyze the **Asset Context**, focusing on fields describing network exposure and reachability.
3.  Consult the **Metric Definition** to understand the values.
4.  Synthesize all information to decide if the asset's context changes the base AV. Your reasoning must be based **only** on the provided information.
5.  If evidence is uncertain, set the metric to Not Defined (X).
6.  Provide your final output in a single, clean JSON object.

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Description:** {self.vuln.cve_description}
* **Base Attack Vector (AV):** {self.base_metrics.AV.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MAV
* **Relevant Field Definitions:**
    * `NetworkAccessibility`: {self.asset_description.network_accessibility}
    * `RemoteManagementAccess`: {self.asset_description.remote_management_access}
* **Asset Values:**
    * **NetworkAccessibility:** {self.asset.network_accessibility}
    * **RemoteManagementAccess:** {self.asset.remote_management_access}

### 3. Metric Definition: Modified Attack Vector (MAV)
* **Description:** {self.base_metrics.AV.description}
* **Possible Values:** {self.base_metrics.AV.values_description}
---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MAV value (`N`, `A`, `L`, `P`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "A",
  "rationale": "The base Attack Vector is Network (N), but the asset's NetworkAccessibility is 'Private_Corporate_Network'. This control forces an attacker to first gain access to the internal network, making the effective attack vector Adjacent (A).",
  "confidence": "High"
}}
```
"""


class AttackComplexity(PromptCreator):
    METRIC = 'Attack Complexity (MAC)'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the CVSS v4.0 **Modified Attack Complexity (MAC)** for a given vulnerability based on the specific context of an IT asset. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  Review the **CVE Information**, noting the **Base Attack Complexity (AC)**.
2.  Analyze the **Asset Context**, focusing on fields describing system hardening, patch level, and protective controls.
3.  Consult the **Metric Definition** to understand the values.
4.  Synthesize all information to decide if the asset's context makes an attack easier or harder. Your reasoning must be based **only** on the provided information.
5.  If evidence is uncertain, set the metric to Not Defined (X).
6.  Provide your final output in a single, clean JSON object.

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Description:** {self.vuln.cve_description}
* **Base Attack Complexity (AC):** {self.base_metrics.AC.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MAC
* **Relevant Field Definitions:**
    * `SystemHardeningLevel`: {self.asset_description.system_hardening_level}
    * `SoftwarePatchLevel`: {self.asset_description.software_patch_level}
    * `NetworkProtection`: {self.asset_description.network_protection}
    * `EndpointProtection`: {self.asset_description.endpoint_protection}
    * `PrivilegeEscalationProtection`: {self.asset_description.privilege_escalation_protection}

* **Asset Values:**
    * **SystemHardeningLevel:** {self.asset.system_hardening_level}
    * **SoftwarePatchLevel:** {self.asset.software_patch_level}
    * **NetworkProtection:** {self.asset.network_protection}
    * **EndpointProtection:** {self.asset.endpoint_protection}
    * **PrivilegeEscalationProtection:** {self.asset.privilege_escalation_protection}

### 3. Metric Definition: Modified Attack Complexity (MAC)
* **Description:** {self.base_metrics.AC.description}
* **Possible Values:** {self.base_metrics.AC.values_description}
---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MAC value (`L`, `H`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "H",
  "rationale": "The base Attack Complexity is Low (L), but the asset's SystemHardeningLevel is 'Fully_Hardened' and it has 'Active_Blocking' NetworkProtection. These compensating controls increase the difficulty for an attacker, raising the MAC to High (H).",
  "confidence": "Medium"
}}
```
"""


class PrivilegesRequired(PromptCreator):
    METRIC = 'Privileges Required (MPR)'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the CVSS v4.0 **Modified Privileges Required (MPR)** for a given vulnerability based on the specific context of an IT asset. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  Review the **CVE Information**, noting the **Base Privileges Required (PR)**.
2.  Analyze the **Asset Context**, focusing on fields describing authentication and privilege escalation controls.
3.  Consult the **Metric Definition** to understand the values.
4.  Synthesize all information to decide if the asset's context changes the privilege level needed for an attack. Your reasoning must be based **only** on the provided information.
5.  If evidence is uncertain, set the metric to Not Defined (X).
6.  Provide your final output in a single, clean JSON object.

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Description:** {self.vuln.cve_description}
* **Base Privileges Required (PR):** {self.base_metrics.PR.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MPR
* **Relevant Field Definitions:**
    * `AuthenticationStrength`: {self.asset_description.authentication_strength}
    * `PrivilegeEscalationProtection`: {self.asset_description.privilege_escalation_protection}
* **Asset Values:**
    * **AuthenticationStrength:** {self.asset.authentication_strength}
    * **PrivilegeEscalationProtection:** {self.asset.privilege_escalation_protection}

### 3. Metric Definition: Modified Privileges Required (MPR)
* **Description:** {self.base_metrics.PR.description}
* **Possible Values:** {self.base_metrics.PR.values_description}
---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MPR value (`N`, `L`, `H`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "H",
  "rationale": "The base Privileges Required is Low (L), but the asset's AuthenticationStrength is 'Multi_Factor'. This control means an attacker must bypass MFA, effectively raising the privileges required to High (H).",
  "confidence": "High"
}}
```
"""


class UserInteraction(PromptCreator):
    METRIC = 'User Interaction (MUI)'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the CVSS v4.0 **Modified User Interaction (MUI)** for a given vulnerability based on the specific context of an IT asset. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  Review the **CVE Information**, noting the **Base User Interaction (UI)**.
2.  Analyze the **Asset Context**, focusing on the security awareness of the users who interact with the system and cve description.
3.  Consult the **Metric Definition** to understand the values.
4.  Synthesize all information to decide if the user context changes the likelihood of successful interaction. Your reasoning must be based **only** on the provided information.
5.  If evidence is uncertain, set the metric to Not Defined (X).
6.  Provide your final output in a single, clean JSON object.

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Description:** {self.vuln.cve_description}
* **Base User Interaction (UI):** {self.base_metrics.UI.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MUI
* **Relevant Field Definitions:**
    * `UserAwarenessLevel`: {self.asset_description.user_awareness_level}
* **Asset Values:**
    * **UserAwarenessLevel:** {self.asset.user_awareness_level}

### 3. Metric Definition: Modified User Interaction (MUI)
* **Description:** {self.base_metrics.UI.description}
* **Possible Values:** {self.base_metrics.UI.values_description}
---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MUI value (`N`, `P`, `A`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "A",
  "rationale": "The base User Interaction is Passive (P), which assumes a standard user might click a link. However, the asset's UserAwarenessLevel is 'Security_Aware', meaning users are well-trained and less likely to perform such actions. This elevates the requirement to Active (A), as a more significant social engineering effort would be needed.",
  "confidence": "Medium"
}}
```
"""


class AttackRequirements(PromptCreator):
    METRIC = 'Attack Requirements (AT) Analysis'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to **analyze** the CVSS v4.0 **Base Attack Requirements (AT)** in the context of an IT asset. Your goal is to explain if any environmental factors significantly hinder an attacker's ability to meet these requirements. You must produce a structured JSON output.
**INSTRUCTIONS:**
1.  Review the **CVE Information**, noting the **Base Attack Requirements (AT)**.
2.  Analyze the **Asset Context**, looking for any controls that could directly interfere with the specified attack requirement.
3.  Consult the **Metric Definition** to understand the values.
4.  The `modified_metric` should remain the same as the Base AT, as environmental controls typically affect complexity (MAC) or the vector (MAV), not the fundamental requirement itself.
5.  The `rationale` should explain how the environment impacts the feasibility of meeting the AT.
6.  If evidence is uncertain, set the metric to Not Defined (X).
7.  Provide your final output in a single, clean JSON object.

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Description:** {self.vuln.cve_description}
* **Base Attack Requirements (AT):** {self.base_metrics.AT.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for AT Analysis
* **Relevant Field Definitions:**
    * `NetworkAccessibility`: {self.asset_description.network_accessibility}
    * `SystemHardeningLevel`: {self.asset_description.system_hardening_level}
    * `PrivilegeEscalationProtection`: {self.asset_description.privilege_escalation_protection}
* **Asset Values:**
    * **NetworkAccessibility:** {self.asset.network_accessibility}
    * **SystemHardeningLevel:** {self.asset.system_hardening_level}
    * **PrivilegeEscalationProtection:** {self.asset.privilege_escalation_protection}

### 3. Metric Definition: Base Attack Requirements (AT)
* **Description:** {self.base_metrics.AT.description}
* **Possible Values:** {self.base_metrics.AT.values_description}
---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting AT value (`N`, `P`, `I`, `R`, `X`). **This will typically be the same as the base metric.**
* `rationale`: A clear, concise explanation of how environmental factors affect the feasibility of meeting the AT.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT (for a Base AT:P vulnerability):**
```json
{{
  "modified_metric": "P",
  "rationale": "The base Attack Requirement is Physical (P). Although the asset is located in a secure data center ('Private_Highly_Restricted_Segment'), which significantly increases the attack complexity (MAC), it does not change the fundamental requirement that an attacker must have physical access to exploit the vulnerability. Therefore, the requirement remains Physical (P).",
  "confidence": "High"
}}"""


class Confidentiality(PromptCreator):
    METRIC = 'Confidentiality (MVC)'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the CVSS v4.0 **Modified Vulnerable System Confidentiality (MVC)** impact for a given vulnerability based on the specific context of an IT asset. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  Review the **CVE Information**, noting the **Base Vulnerable System Confidentiality Impact (VC)**.
2.  Analyze the **Asset Context**, focusing on the organization's security requirement for confidentiality and any mitigating controls like encryption.
3.  Consult the **Metric Definition** to understand the values.
4.  The primary driver for this metric should be the **SecurityRequirement_Confidentiality**. A High requirement should increase the impact, and a Low requirement should decrease it.
5.  If evidence is uncertain, set the metric to Not Defined (X).
6.  Provide your final output in a single, clean JSON object.
7.  The resulting MVI value (`High(H)`, `Low(L)`, `None(N)`, `Not defined(X)`). **Use only abbreviations.** just this values

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Description:** {self.vuln.cve_description}
* **Base Confidentiality Impact (VC):** {self.base_metrics.VC.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MVC
* **Relevant Field Definitions:**
    * `SecurityRequirement_Confidentiality`: {self.asset_description.security_requirement_confidentiality}
    * `DataSensitivity`: {self.asset_description.data_sensitivity}
    * `AssetCriticality`: {self.asset_description.asset_criticality}
    * `DataEncryptionLevel`: {self.asset_description.data_encryption_level}
* **Asset Values:**
    * **SecurityRequirement_Confidentiality:** {self.asset.security_requirement_confidentiality}
    * **DataSensitivity:** {self.asset.data_sensitivity}
    * **AssetCriticality:** {self.asset.asset_criticality}
    * **DataEncryptionLevel:** {self.asset.data_encryption_level}

### 3. Metric Definition: Modified Confidentiality (MVC)
* **Description:** {self.base_metrics.VC.description}
* **Possible Values:** {self.base_metrics.VC.values_description}
---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MVC value (`H`, `L`, `N`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "L",
  "rationale": "The base Confidentiality impact is High (H), but the asset's SecurityRequirement_Confidentiality is explicitly set to Low (L). The organizational requirement dictates the modified impact, so MVC is Low (L).",
  "confidence": "High"
}}
```
"""


class Integrity(PromptCreator):
    METRIC = 'Integrity (MVI)'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the CVSS v4.0 **Modified Integrity (MVI)** impact for a given vulnerability based on the specific context of an IT asset. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  Review the **CVE Information**, noting the **Base Integrity Impact (VI)**.
2.  Analyze the **Asset Context**, focusing on the organization's security requirement for integrity and mitigating controls.
3.  Consult the **Metric Definition** to understand the values.
4.  The primary driver for this metric should be the **SecurityRequirement_Integrity**.
5.  If evidence is uncertain, set the metric to Not Defined (X).
6.  Provide your final output in a single, clean JSON object.
7.  The resulting MVI value (`High(H)`, `Low(L)`, `None(N)`, `Not defined(X)`). **Use only abbreviations.** just this values

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Description:** {self.vuln.cve_description}
* **Base Integrity Impact (VI):** {self.base_metrics.VI.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MVI
* **Relevant Field Definitions:**
    * `SecurityRequirement_Integrity`: {self.asset_description.security_requirement_integrity}
    * `EndpointProtection`: {self.asset_description.endpoint_protection}
    * `NetworkProtection`: {self.asset_description.network_protection}
    * `IntegrityProtectionLevel`: {self.asset_description.integrity_protection_level}
* **Asset Values:**
    * **SecurityRequirement_Integrity:** {self.asset.security_requirement_integrity}
    * **EndpointProtection:** {self.asset.endpoint_protection}
    * **NetworkProtection:** {self.asset.network_protection}
    * **IntegrityProtectionLevel:** {self.asset.integrity_protection_level}

### 3. Metric Definition: Modified Integrity (MVI)
* **Description:** {self.base_metrics.VI.description}
* **Possible Values:** {self.base_metrics.VI.values_description}
---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MVI value (`H`, `L`, `N`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "H",
  "rationale": "The base Integrity impact is Low (L), but the asset's SecurityRequirement_Integrity is explicitly set to High (H). The organizational requirement dictates the modified impact, so MVI is High (H).",
  "confidence": "High"
}}
```
"""


class Availability(PromptCreator):
    METRIC = 'Availability (MVA)'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the CVSS v4.0 **Modified Availability (MVA)** impact for a given vulnerability based on the specific context of an IT asset. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  Review the **CVE Information**, noting the **Base Availability Impact (VA)**.
2.  Analyze the **Asset Context**, focusing on the organization's security requirement for availability and any mitigating controls like redundancy.
3.  Consult the **Metric Definition** to understand the values.
4.  The primary driver for this metric should be the **SecurityRequirement_Availability**.
5.  If evidence is uncertain, set the metric to Not Defined (X).
6.  Provide your final output in a single, clean JSON object.
7.  The resulting MVI value (`High(H)`, `Low(L)`, `None(N)`, `Not defined(X)`). **Use only abbreviations.** just this values

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Description:** {self.vuln.cve_description}
* **Base Availability Impact (VA):** {self.base_metrics.VA.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MVA
* **Relevant Field Definitions:**
    * `SecurityRequirement_Availability`: {self.asset_description.security_requirement_availability}
    * `AssetCriticality`: {self.asset_description.asset_criticality}
    * `AvailabilityRedundancy`: {self.asset_description.availability_redundancy}
* **Asset Values:**
    * **SecurityRequirement_Availability:** {self.asset.security_requirement_availability}
    * **AssetCriticality:** {self.asset.asset_criticality}
    * **AvailabilityRedundancy:** {self.asset.availability_redundancy}

### 3. Metric Definition: Modified Availability (MVA)
* **Description:** {self.base_metrics.VA.description}
* **Possible Values:** {self.base_metrics.VA.values_description}
---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MVA value (`H`, `L`, `N`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "L",
  "rationale": "The base Availability impact is High (H) and the asset's Availability Requirement is also High (H). However, the asset has 'High' AvailabilityRedundancy. This control provides a failover, mitigating the impact of a loss of availability and reducing the MVA to Low (L).",
  "confidence": "High"
}}
```
"""


class SubsequentConfidentiality(PromptCreator):
    METRIC = 'Subsequent System Confidentiality (MSC)'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the **Modified Subsequent System Confidentiality (MSC)** impact for a given vulnerability based on the asset's context. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  **First, assess the `PropagationRisk`**. If the risk is 'Low', lateral movement is unlikely, and the impact on subsequent systems is Negligible (N).
2.  If propagation risk is not 'Low', then determine the impact based on the **`SubsequentSystem_Confidentiality_Req`**. This value dictates the MSC.
3.  Consult the **Metric Definition** to understand the values.
4.  If evidence is uncertain, set the metric to Not Defined (X).
5.  Provide your final output in a single, clean JSON object.

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Base Subsequent Confidentiality Impact (SC):** {self.base_metrics.SC.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MSC
* **Relevant Field Definitions:**
    * `PropagationRisk`: {self.asset_description.propagation_risk}
    * `SubsequentSystem_Confidentiality_Req`: {self.asset_description.subsequent_system_confidentiality_req}
* **Asset Values:**
    * **PropagationRisk:** {self.asset.propagation_risk}
    * **SubsequentSystem_Confidentiality_Req:** {self.asset.subsequent_system_confidentiality_req}

### 3. Metric Definition: Modified Subsequent System Confidentiality (MSC)
* **Description:** {self.base_metrics.SC.description}
* **Possible Values:** {self.base_metrics.SC.values_description}
---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MSC value (`H`, `L`, `N`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "N",
  "rationale": "The asset's PropagationRisk is 'Low'. This indicates the asset is highly isolated, making it very difficult for an attacker to pivot to downstream systems. Therefore, the impact on subsequent systems is considered None (N).",
  "confidence": "High"
}}
```
"""


class SubsequentIntegrity(PromptCreator):
    METRIC = 'Subsequent System Integrity (MSI)'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the **Modified Subsequent System Integrity (MSI)** impact for a given vulnerability based on the asset's context. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  **First, assess the `PropagationRisk`**. If the risk is 'Low', the impact on subsequent systems is Negligible (N).
2.  If propagation risk is not 'Low', then determine the impact based on the **`SubsequentSystem_Integrity_Req`**.
3.  If evidence is uncertain, set the metric to Not Defined (X).
4.  Provide your final output in a single, clean JSON object.

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Base Subsequent Integrity Impact (SI):** {self.base_metrics.SI.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MSI
* **Relevant Field Definitions:**
    * `PropagationRisk`: {self.asset_description.propagation_risk}
    * `SubsequentSystem_Integrity_Req`: {self.asset_description.subsequent_system_integrity_req}
* **Asset Values:**
    * **PropagationRisk:** {self.asset.propagation_risk}
    * **SubsequentSystem_Integrity_Req:** {self.asset.subsequent_system_integrity_req}

### 3. Metric Definition: Modified Subsequent System Integrity (MSI)
* **Description:** {self.base_metrics.SI.description}
* **Possible Values:** {self.base_metrics.SI.values_description}
Negligible (N): A successful exploit would have little to no effect on subsequent or dependent systems. Any impact would be minimal, non-persistent, and would not compromise trust or correctness of operations beyond the initially affected system.
Safety (S): The exploited vulnerability will result in integrity impacts that could cause serious injury or worse (categories of &quot;Marginal&quot; or worse as described in IEC 61508) to a human actor or participant.

---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MSI value (`S`, `H`, `L`, `N`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "H",
  "rationale": "The asset's PropagationRisk is 'High' and it connects to systems with a SubsequentSystem_Integrity_Req of 'High'. Therefore, the MSI is determined to be High (H).",
  "confidence": "High"
}}
```
"""


class SubsequentAvailability(PromptCreator):
    METRIC = 'Subsequent System Availability (MSA)'

    @property
    def prompt(self):
        return f"""
**ROLE:** You are a senior cybersecurity analyst and an expert in the CVSS v4.0 framework.
**TASK:** Your task is to determine the **Modified Subsequent System Availability (MSA)** impact for a given vulnerability based on the asset's context. You must analyze the provided information and produce a structured JSON output.
**INSTRUCTIONS:**
1.  **First, assess the `PropagationRisk`**. If the risk is 'Low', the impact on subsequent systems is Negligible (N).
2.  If propagation risk is not 'Low', then determine the impact based on the **`SubsequentSystem_Availability_Req`**.
3.  If evidence is uncertain, set the metric to Not Defined (X).
4.  Provide your final output in a single, clean JSON object.

---
**CONTEXT:**
### 1. CVE Information
* **CVE-ID:** {self.vuln.id}
* **Base Subsequent Availability Impact (SA):** {self.base_metrics.SA.value}
* **Base_Score:** {self.vuln.base_score} ({self.vuln.base_severity})  
* **Vuln_Status:** {self.vuln.cve_status} 
* **Weakness:** {self.vuln.weaknesses} 

### 2. Asset Context for MSA
* **Relevant Field Definitions:**
    * `PropagationRisk`: {self.asset_description.propagation_risk}
    * `SubsequentSystem_Availability_Req`: {self.asset_description.subsequent_system_availability_req}
* **Asset Values:**
    * **PropagationRisk:** {self.asset.propagation_risk}
    * **SubsequentSystem_Availability_Req:** {self.asset.subsequent_system_availability_req}

### 3. Metric Definition: Modified Subsequent System Availability (MSA)
* **Description:** {self.base_metrics.SA.description}
* **Possible Values:** {self.base_metrics.SA.values_description}
Negligible (N): A successful exploit would have little to no effect on subsequent or dependent systems. Any impact would be minimal, non-persistent, and would not compromise trust or correctness of operations beyond the initially affected system.
Safety (S): The exploited vulnerability will result in availability impacts that could cause serious injury or worse (categories of &quot;Marginal&quot; or worse as described in IEC 61508) to a human actor or participant.

---
**OUTPUT FORMAT:**
You must provide your response as a single JSON object with the following keys:
* `modified_metric`: The resulting MSA value (`S`, `H`, `L`, `N`, `X`). **Use only abbreviations.**
* `rationale`: A clear, concise explanation for your decision, referencing specific asset attributes.
* `confidence`: Your confidence in the decision (`High`, `Medium`, or `Low`).

**EXAMPLE OUTPUT:**
```json
{{
  "modified_metric": "H",
  "rationale": "The asset's PropagationRisk is 'Medium' and it connects to systems with a SubsequentSystem_Availability_Req of 'High'. Therefore, the MSA is determined to be High (H).",
  "confidence": "High"
}}"""
