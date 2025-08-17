CALCULATOR_MOCK = {
  "values": [
    {
      "agent_response": {
        "MAC": {
          "confidence": {
            "MAC": "High",
            "MAT": "High",
            "MAV": "High",
            "MPR": "High",
            "MSA": "High",
            "MSC": "High",
            "MSI": "High",
            "MUI": "High"
          },
          "modified_metrics": {
            "MAC": "L",
            "MAT": "N",
            "MAV": "N",
            "MPR": "N",
            "MSA": "N",
            "MSC": "N",
            "MSI": "N",
            "MUI": "N"
          },
          "rationale": {
            "MAC": "Modified Attack Complexity is set to Low. Given the information that authentication is bypassed and no specific evasion of security-enhancing techniques is mentioned, the attack does not require actions to overcome significant security measures.",
            "MAT": "Modified Attack Range remains Network, following the same logic as MAV, due to the initial network exposure.",
            "MAV": "Modified Attack Vector remains Network as the asset\"s exposure level is external, though it requires multiple steps within limited access due to the segmentation, it is reachable.",
            "MPR": "Modified Privileges Required remains Network. No prior authentication or specific privilege escalation is required to exploit the vulnerability, despite physical access being required for the asset.",
            "MSC": "Modified Scope remains Unchanged as the vulnerability directly affects the same component where it resides, within the application.",
            "MSI": "Modified Sensitivity Impact remains Network since altering a password can grant broader access without changing the initial boundary.",
            "MUI": "No User Interaction is needed as unauthorized access is achieved through vulnerability exploitation."
          }
        },
        "MAT": {
          "confidence": {
            "MAT": "High"
          },
          "modified_metrics": {
            "MAT": "N"
          },
          "rationale": {
            "MAT": "Given the description of the vulnerability, the successful attack does not seem to depend on specific deployment or execution conditions of the vulnerable system. The attacker appears capable of executing the exploit without needing to meet any particular requirements, thus suggesting the value \"None\"."
          }
        },
        "MAV": {
          "confidence": {
            "MAV": "Medium"
          },
          "modified_metrics": {
            "MAV": "A"
          },
          "rationale": {
            "MAV": "Given the vulnerability details, the exploitation seems to require some level of access within a logical network, as evidenced by the firewall configuration blocking external access. The \"Adjacent\" value is appropriate due to the internal network reachability and that the attack can\"t be executed directly over the internet."
          }
        },
        "MPR": {
          "confidence": {
            "MPR": "High"
          },
          "modified_metrics": {
            "MPR": "N"
          },
          "rationale": {
            "MPR": "The vulnerability description indicates an authentication bypass allowing unauthorized users to overwrite passwords, implying no privileges are required to exploit the vulnerability. The asset context supports this, as it describes that no authentication is necessary for accessing the asset."
          }
        },
        "MS": {
          "confidence": {
            "MSA": "Medium",
            "MSC": "High",
            "MSI": "High"
          },
          "modified_metrics": {
            "MSA": "Low",
            "MSC": "High",
            "MSI": "High"
          },
          "rationale": {
            "MSA": "While the compromises allow unauthorized access and control, there is no explicit mention of complete denial of service or persistent availability impact. Therefore, the impact to availability is considered to be low.",
            "MSC": "The vulnerability allows attackers to gain unauthorized administrative access, potentially exposing all information managed by the system due to password management exploitation. This represents a significant confidentiality breach.",
            "MSI": "The ability to overwrite any user\"s password indicates high potential for unauthorized modification, directly impacting system integrity. The attacker can effectively manipulate user data in a significant way."
          }
        },
        "MUI": {
          "confidence": {
            "MUI": "High"
          },
          "modified_metrics": {
            "MUI": "N"
          },
          "rationale": {
            "MUI": "The vulnerability can be exploited without interaction from any human user, other than the attacker. Given the asset\"s configuration, which includes strong access control and privilege escalation protection, no user interaction is required when considering the capability to manipulate endpoints for password management."
          }
        },
        "MV": {
          "confidence": {
            "MVA": "High",
            "MVC": "High",
            "MVI": "High"
          },
          "modified_metrics": {
            "MVA": "H",
            "MVC": "H",
            "MVI": "H"
          },
          "rationale": {
            "MVA": "Given the asset\"s high availability requirements and lack of redundancy, the vulnerability can severely impact availability by allowing unauthorized administrative actions that could deny access to legitimate users. This supports a \"High\" impact rating.",
            "MVC": "The asset handles operationally critical data with weak encryption protection. The vulnerability allows unauthorized administrative access to the system, likely leading to a complete disclosure of sensitive information, making \"High\" the appropriate value.",
            "MVI": "The vulnerability allows attackers to overwrite user passwords, compromising the system\"s integrity significantly. The weak encryption protection heightens this impact, leading to a \"High\" impact on integrity."
          }
        },
        "score": 9.4,
        "severity": "Critical"
      },
      "asset": {
        "access_control_strength": "strong",
        "asset_criticality": "high",
        "asset_dependency_level": "low",
        "authentication_requirement": "none",
        "availability_redundancy": "low",
        "cascading_impact_potential": "high",
        "connected_systems_criticality": "low",
        "connection_security_controls": "strong",
        "data_sensitivity": "operationally_critical",
        "encryption_protection_level": "weak",
        "exposure_level": "external",
        "firewall_configuration": "block_external_allow_internal_only",
        "id": 1,
        "is_active": True,
        "name": "Elber",
        "network_access_complexity": "multiple_steps",
        "network_connectivity": "high",
        "network_segmentation": "highly_isolated",
        "physical_access_required": "true",
        "privilege_escalation_protection": "present",
        "security_controls_edr": "present",
        "security_controls_firewall": "absent",
        "security_controls_ids": "present",
        "security_controls_ips": "absent",
        "security_controls_waf": "absent",
        "security_requirements_availability": "high",
        "security_requirements_confidentiality": "high",
        "security_requirements_integrity": "high",
        "software_patch_level": "partially_updated",
        "ssh_remote_access": "false",
        "system_hardening_level": "not_hardened",
        "tp": "database",
        "user_awareness_level": "low",
        "user_privilege_level_required": "admin_or_elevated",
        "version": "5.9.0",
        "vpn_access": "not_required"
      },
      "rule_base_response": {
        "confidence": {
          "AR": "High",
          "CR": "High",
          "IR": "High",
          "MAC": "Medium",
          "MAT": "Medium",
          "MAV": "High",
          "MPR": "Medium",
          "MSA": "Medium",
          "MSC": "Medium",
          "MSI": "Medium",
          "MUI": "Low",
          "MVA": "Medium",
          "MVC": "Medium",
          "MVI": "Medium"
        },
        "metrics": {
          "AR": "HIGH",
          "CR": "HIGH",
          "IR": "HIGH",
          "MAC": "HIGH",
          "MAT": "PRESENT",
          "MAV": "PHYSICAL",
          "MPR": "HIGH",
          "MSA": "NEGLIGIBLE",
          "MSC": "NEGLIGIBLE",
          "MSI": "NEGLIGIBLE",
          "MUI": "NONE",
          "MVA": "HIGH",
          "MVC": "HIGH",
          "MVI": "HIGH"
        },
        "rationale": {
          "AR": "Mapped directly from security_requirements_availability: high.",
          "CR": "Mapped directly from security_requirements_confidentiality: high.",
          "IR": "Mapped directly from security_requirements_integrity: high.",
          "MAC": "Base from network_access_complexity=multiple_steps -> HIGH; hardeners=1 adjusted HIGH->HIGH with hardening/patch signals.",
          "MAT": "Some preconditions (single-factor and/or network isolation/VPN). (auth=none, MAV=PHYSICAL, access_control_strength=strong).",
          "MAV": "Derived from reachability and controls: physical_required=True, exposure=external, firewall=block_external_allow_internal_only, segmentation=highly_isolated, vpn_required=False, ssh_remote_access=False.",
          "MPR": "Base from user_privilege_level_required=admin_or_elevated -> HIGH; no change (access_control_strength=strong, privilege_escalation_protection=present).",
          "MSA": "Same adjustment model as MSC.",
          "MSC": "Base=HIGH (internal H) from cascading_impact_potential=high; adjusted by dependency=low, connected_systems_criticality=low, connection_security_controls=strong, network_connectivity=high.",
          "MSI": "Same adjustment model as MSC.",
          "MUI": "Back-end/service context rarely requires user interaction. (tp=database, user_awareness_level=low, MAV=PHYSICAL).",
          "MVA": "Start from asset_criticality=high->HIGH (internal H); availability_redundancy=low, tp=database, network_connectivity=high -> HIGH.",
          "MVC": "Start from data_sensitivity=operationally_critical->LOW (internal M); encryption=weak and asset_criticality=high with exposure=external -> HIGH.",
          "MVI": "Start from asset_criticality=high->HIGH (internal H); hardening/EDR/firewall and access_control_strength=strong, patch_level=partially_updated -> HIGH."
        },
        "score": 5.4,
        "severity": "Medium"
      }
    }
  ],
  "vulnerability_id": 1
}

SCAN_MOCK = [
  {
    "access_control_strength": "strong",
    "asset_criticality": "low",
    "asset_dependency_level": "high",
    "authentication_requirement": "none",
    "availability_redundancy": "high",
    "cascading_impact_potential": "high",
    "connected_systems_criticality": "high",
    "connection_security_controls": "weak",
    "data_sensitivity": "operationally_critical",
    "encryption_protection_level": "strong",
    "exposure_level": "physical",
    "firewall_configuration": "block_internal_external_inbound",
    "id": 1,
    "is_active": True,
    "name": "Elber",
    "network_access_complexity": "multiple_steps",
    "network_connectivity": "low",
    "network_segmentation": "highly_isolated",
    "physical_access_required": "true",
    "privilege_escalation_protection": "absent",
    "security_controls_edr": "present",
    "security_controls_firewall": "present",
    "security_controls_ids": "absent",
    "security_controls_ips": "absent",
    "security_controls_waf": "absent",
    "security_requirements_availability": "high",
    "security_requirements_confidentiality": "low",
    "security_requirements_integrity": "high",
    "software_patch_level": "partially_updated",
    "ssh_remote_access": "true",
    "system_hardening_level": "fully_hardened",
    "tp": "security_tools",
    "user_awareness_level": "low",
    "user_privilege_level_required": "none",
    "version": "5.9.0",
    "vpn_access": "required"
  }
]