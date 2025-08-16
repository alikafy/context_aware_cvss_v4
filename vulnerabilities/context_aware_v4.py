import json
import os
import re
import sqlite3

import requests
from bs4 import BeautifulSoup
from cvss import CVSS4

from type import *
from prompt_creator import PromptCreator


class EnvironmentalMetricCalculater:
    """
    Step 1 Fetch cve_id
      Find CVE by call API and fetch cve_id

    Step 2 Gathering data
      Fetch CVE description
      Fetch CVE base vector
      Fetch CVE base score
      Fetch CVE status
      Fetch CVE severity
      Fetch CWE description by call API
      Add metrics and values explanation

    Step 3 Finding vulnerable system
      Finding vulnerable systems in two-step
      first Finding just vulnerable systems in description by asking from LLM
      Search name of vulnerable system in assets using powerful search
      second Give suspended assets with their version and description then ask again about impaction
      Create couple templates for asking LLM in two-step

    Step 4 Ask LLM
      Create prompt
      Ask LLM for ALL Environmental metrics
      Calculate Environmental metric

    step 5 Rule base
      Create Rule base algorithm
      Calculate Environmental metric
    """

    def __init__(self, cve_id: str, context: str):
        self.cve_id = cve_id
        self.context = context
        self.cve = self.fetch_cve()
        db_path = os.path.abspath("context-aware/context_aware.db")
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def fetch_cve(self):
        response = self.get_cve_record_nvd()
        return CVEData(
            id=self.cve_id,
            cve_description=response['descriptions'][0]['value'],
            cve_status=response['vulnStatus'],
            weaknesses=self.fetch_cwes(response['weaknesses']),
            base_metric=self.fetch_metrics(response['metrics']['cvssMetricV40'][0]['cvssData'])
        )

    def fetch_metrics(self, metrics_data) -> BaseMetric:
        return BaseMetric(
            score=metrics_data['baseScore'],
            severity=metrics_data['baseSeverity'],
            AV=self.fetch_cvss_metric(AV(value=metrics_data['attackVector'])),
            AC=self.fetch_cvss_metric(AC(value=metrics_data['attackComplexity'])),
            AT=self.fetch_cvss_metric(AT(value=metrics_data['attackRequirements'])),
            PR=self.fetch_cvss_metric(PR(value=metrics_data['privilegesRequired'])),
            UI=self.fetch_cvss_metric(UI(value=metrics_data['userInteraction'])),
            VC=self.fetch_cvss_metric(VC(value=metrics_data['vulnConfidentialityImpact'])),
            VI=self.fetch_cvss_metric(VI(value=metrics_data['vulnIntegrityImpact'])),
            VA=self.fetch_cvss_metric(VA(value=metrics_data['vulnAvailabilityImpact'])),
            SC=self.fetch_cvss_metric(SC(value=metrics_data['subConfidentialityImpact'])),
            SI=self.fetch_cvss_metric(SI(value=metrics_data['subIntegrityImpact'])),
            SA=self.fetch_cvss_metric(SA(value=metrics_data['subAvailabilityImpact'])),
        )


    def agent_answer(self, asset: Asset):
        modified_metrics = {}
        prompts = PromptCreator(self.cve, asset)
        response = self.make_request(prompts.attack_vector)
        modified_metrics['MAV'] = response
        response = self.make_request(prompts.attack_complicity)
        modified_metrics['MAC'] = response
        response = self.make_request(prompts.attack_required)
        modified_metrics['MAT'] = response
        response = self.make_request(prompts.privilege_required)
        modified_metrics['MPR'] = response
        response = self.make_request(prompts.user_interaction)
        modified_metrics['MUI'] = response
        response = self.make_request(prompts.vulnerable_system)
        modified_metrics['MV'] = response
        response = self.make_request(prompts.vulnerable_sub_system)
        modified_metrics['MS'] = response
        return modified_metrics

    def prepare_agent_answer_for_calculator(self, answer: dict, asset: Asset):
        base = {
            "AV": metrics_abbreviation[self.cve.base_metric.AV.value],
            "AC": metrics_abbreviation[self.cve.base_metric.AC.value],
            "AT": metrics_abbreviation[self.cve.base_metric.AT.value],
            "PR": metrics_abbreviation[self.cve.base_metric.PR.value],
            "UI": metrics_abbreviation[self.cve.base_metric.UI.value],
            "VC": metrics_abbreviation[self.cve.base_metric.VC.value],
            "VI": metrics_abbreviation[self.cve.base_metric.VI.value],
            "VA": metrics_abbreviation[self.cve.base_metric.VA.value],
            "SC": metrics_abbreviation[self.cve.base_metric.SC.value],
            "SI": metrics_abbreviation[self.cve.base_metric.SI.value],
            "SA": metrics_abbreviation[self.cve.base_metric.SA.value]
        }
        env = {
            "MAV": self.convert_to_abbreviations(answer.get("MAV", {}).get("modified_metrics", {}).get("MAV", "X")),
            "MAC": self.convert_to_abbreviations(answer.get("MAC", {}).get("modified_metrics", {}).get("MAC", "X")),
            "MAT": self.convert_to_abbreviations(answer.get("MAT", {}).get("modified_metrics", {}).get("MAT", "X")),
            "MPR": self.convert_to_abbreviations(answer.get("MPR", {}).get("modified_metrics", {}).get("MPR", "X")),
            "MUI": self.convert_to_abbreviations(answer.get("MUI", {}).get("modified_metrics", {}).get("MUI", "X")),
            "MVC": self.convert_to_abbreviations(answer.get("MV", {}).get("modified_metrics", {}).get("MVC", "X")),
            "MVI": self.convert_to_abbreviations(answer.get("MV", {}).get("modified_metrics", {}).get("MVI", "X")),
            "MVA": self.convert_to_abbreviations(answer.get("MV", {}).get("modified_metrics", {}).get("MVA", "X")),
            "MSC": self.convert_to_abbreviations(answer.get("MS", {}).get("modified_metrics", {}).get("MSC", "X")),
            "MSI": self.convert_to_abbreviations(answer.get("MS", {}).get("modified_metrics", {}).get("MSI", "X")),
            "MSA": self.convert_to_abbreviations(answer.get("MS", {}).get("modified_metrics", {}).get("MSA", "X")),
        }

        req = {
            "CR": metrics_abbreviation[asset.security_requirements_confidentiality.upper()],
            "IR": metrics_abbreviation[asset.security_requirements_integrity.upper()],
            "AR": metrics_abbreviation[asset.security_requirements_availability.upper()]
        }
        return {**base, **env, **req}

    def convert_to_abbreviations(self, value: str):
        changed_value = value.upper()
        if len(changed_value) == 1:
            return changed_value
        changed_value = re.sub(r"\s*\([^)]*\)", "", changed_value).strip()
        return metrics_abbreviation[changed_value]

    def calculate_environmental_metric(self, all_metrics):
        vector = "CVSS:4.0/" + "/".join(f"{k}:{v}" for k, v in all_metrics.items())
        cvss = CVSS4(vector)
        scores = cvss.scores()
        severity = cvss.severity
        return scores, severity

    def calculate_rule_base(self, asset: Asset):
        vul_impact = self.calculate_MVC_MVI_MVA(asset)
        sub_impact = self.calculate_MSC_MSI_MSA(asset)
        metrics = {
              "MAV": metrics_abbreviation[self.calculate_MAV(asset).upper()],
              "MAC": metrics_abbreviation[self.calculate_MAC(asset).upper()],
              "MAT": metrics_abbreviation["NOT_DEFINED"],
              "MPR": metrics_abbreviation[self.calculate_MPR(asset).upper()],
              "MUI": metrics_abbreviation["NOT_DEFINED"],
              "MVC": metrics_abbreviation[vul_impact["MVC"].upper()],
              "MVI": metrics_abbreviation[vul_impact["MVI"].upper()],
              "MVA": metrics_abbreviation[vul_impact["MVA"].upper()],
              "MSC": metrics_abbreviation[sub_impact["MSC"].upper()],
              "MSI": metrics_abbreviation[sub_impact["MSI"].upper()],
              "MSA": metrics_abbreviation[sub_impact["MSA"].upper()]
            }
        req = {
            "CR": metrics_abbreviation[asset.security_requirements_confidentiality.upper()],
            "IR": metrics_abbreviation[asset.security_requirements_integrity.upper()],
            "AR": metrics_abbreviation[asset.security_requirements_availability.upper()]
        }

        base = {
            "AV": metrics_abbreviation[self.cve.base_metric.AV.value],
            "AC": metrics_abbreviation[self.cve.base_metric.AC.value],
            "AT": metrics_abbreviation[self.cve.base_metric.AT.value],
            "PR": metrics_abbreviation[self.cve.base_metric.PR.value],
            "UI": metrics_abbreviation[self.cve.base_metric.UI.value],
            "VC": metrics_abbreviation[self.cve.base_metric.VC.value],
            "VI": metrics_abbreviation[self.cve.base_metric.VI.value],
            "VA": metrics_abbreviation[self.cve.base_metric.VA.value],
            "SC": metrics_abbreviation[self.cve.base_metric.SC.value],
            "SI": metrics_abbreviation[self.cve.base_metric.SI.value],
            "SA": metrics_abbreviation[self.cve.base_metric.SA.value]
        }
        return {**base, **metrics, **req}

    def prepare_rule_base_for_calculator(self, answer: dict, asset: Asset):
        base = {
            "AV": metrics_abbreviation[self.cve.base_metric.AV.value],
            "AC": metrics_abbreviation[self.cve.base_metric.AC.value],
            "AT": metrics_abbreviation[self.cve.base_metric.AT.value],
            "PR": metrics_abbreviation[self.cve.base_metric.PR.value],
            "UI": metrics_abbreviation[self.cve.base_metric.UI.value],
            "VC": metrics_abbreviation[self.cve.base_metric.VC.value],
            "VI": metrics_abbreviation[self.cve.base_metric.VI.value],
            "VA": metrics_abbreviation[self.cve.base_metric.VA.value],
            "SC": metrics_abbreviation[self.cve.base_metric.SC.value],
            "SI": metrics_abbreviation[self.cve.base_metric.SI.value],
            "SA": metrics_abbreviation[self.cve.base_metric.SA.value]
        }
        env = {
            "MAV": self.convert_to_abbreviations(answer['metrics']["MAV"]),
            "MAC": self.convert_to_abbreviations(answer['metrics']["MAC"]),
            "MAT": self.convert_to_abbreviations(answer['metrics']["MAT"]),
            "MPR": self.convert_to_abbreviations(answer['metrics']["MPR"]),
            "MUI": self.convert_to_abbreviations(answer['metrics']["MUI"]),
            "MVC": self.convert_to_abbreviations(answer['metrics']["MVC"]),
            "MVI": self.convert_to_abbreviations(answer['metrics']["MVI"]),
            "MVA": self.convert_to_abbreviations(answer['metrics']["MVA"]),
            "MSC": self.convert_to_abbreviations(answer['metrics']["MSC"]),
            "MSI": self.convert_to_abbreviations(answer['metrics']["MSI"]),
            "MSA": self.convert_to_abbreviations(answer['metrics']["MSA"]),
        }

        req = {
            "CR": metrics_abbreviation[asset.security_requirements_confidentiality.upper()],
            "IR": metrics_abbreviation[asset.security_requirements_integrity.upper()],
            "AR": metrics_abbreviation[asset.security_requirements_availability.upper()]
        }
        return {**base, **env, **req}

    def calculate_MAV(self, asset_context):
        if asset_context.exposure_level == "external" and asset_context.ssh_remote_access == 'true':
            return "network"
        elif asset_context.vpn_access == "required" or asset_context.network_segmentation == "isolated":
            return  "adjacent"
        elif asset_context.exposure_level == "internal":
            return  "adjacent"
        elif asset_context.physical_access_required == "true":
            return  "physical"
        else:
            return  "local"


    def calculate_MAC(self, asset_context: Asset):
        complexity_scores = {"L": 0, "M": 1, "H": 2}

        complexity = complexity_scores["L"]  # Start with Low

        # Check security controls
        if asset_context.security_controls_ips == "present" or asset_context.security_controls_waf == "present":
            complexity = complexity_scores["H"]
        elif asset_context.security_controls_firewall == "present" or asset_context.security_controls_ids == "present":
            complexity = max(complexity, complexity_scores["M"])
        # Check system hardening
        if asset_context.system_hardening_level == "fully_hardened":
            complexity = max(complexity, complexity_scores["H"])
        elif asset_context.system_hardening_level == "partially_hardened":
            complexity = max(complexity, complexity_scores["M"])
        # Check software patch level
        if asset_context.software_patch_level == "up_to_date":
            complexity = max(complexity, complexity_scores["H"])
        elif asset_context.software_patch_level == "partially_updated":
            complexity = max(complexity, complexity_scores["M"])

        # Check network access complexity
        if asset_context.network_access_complexity == "multiple_steps":
            complexity = max(complexity, complexity_scores["H"])
        elif asset_context.network_access_complexity == "moderate_steps":
            complexity = max(complexity, complexity_scores["M"])

        # Reverse mapping
        score_to_label = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}
        return score_to_label[complexity]

    def calculate_MPR(self, asset_context: Asset):
        privilege_levels = {"None": 0, "Low": 1, "High": 2}

        mpr_score = privilege_levels["None"]  # start with lowest privilege

        # Authentication Requirement
        if asset_context.authentication_requirement == "multi-factor":
            mpr_score = max(mpr_score, privilege_levels["High"])
        elif asset_context.authentication_requirement == "single-factor":
            mpr_score = max(mpr_score, privilege_levels["Low"])

        # User Privilege Level Required
        if asset_context.user_privilege_level_required == "admin_or_elevated":
            mpr_score = privilege_levels["High"]
        elif asset_context.user_privilege_level_required == "basic_user":
            mpr_score = max(mpr_score, privilege_levels["Low"])

        # Access Control Strength
        if asset_context.access_control_strength == "strong":
            mpr_score = max(mpr_score, privilege_levels["High"])
        elif asset_context.access_control_strength == "moderate":
            mpr_score = max(mpr_score, privilege_levels["Low"])

        # Privilege Escalation Protection
        if asset_context.privilege_escalation_protection == "present":
            mpr_score = privilege_levels["High"]

        # Reverse mapping
        score_to_label = {0: "NONE", 1: "LOW", 2: "HIGH"}
        return score_to_label[mpr_score]

    def calculate_MVC_MVI_MVA(self, asset_context: Asset):
        weights = {"high": 1.5, "medium": 1.0, "low": 0.5, "none": 0}

        # Confidentiality adjustment (MVC)
        mvc = weights[self.cve.base_metric.VC.value.lower()] * weights[asset_context.security_requirements_confidentiality]
        if asset_context.data_sensitivity == "highly_sensitive":
            mvc *= 1.2  # increase slightly for highly sensitive data
        if asset_context.encryption_protection_level == "strong":
            mvc *= 0.7  # reduce MVC due to strong encryption

        # Integrity adjustment (MVI)
        mvi = weights[self.cve.base_metric.VI.value.lower()] * weights[asset_context.security_requirements_integrity]
        if asset_context.data_sensitivity == "highly_sensitive":
            mvi *= 1.2
        if asset_context.encryption_protection_level == "strong":
            mvi *= 0.7

        # Availability adjustment (MVA)
        mva = weights[self.cve.base_metric.VA.value.lower()] * weights[asset_context.security_requirements_availability]
        if asset_context.availability_redundancy  == "high":
            mva *= 0.5  # significant reduction due to redundancy
        elif asset_context.availability_redundancy == "moderate":
            mva *= 0.8

        def map_value_to_label(value):
            if value == 0:
                return "NONE"
            elif 0 < value <= 3.9:
                return "LOW"
            elif value >= 4.0:
                return "HIGH"
            else:
                return "NOT_DEFINED"
        return {
            "MVC": map_value_to_label(round(min(mvc, 10), 1)),
            "MVI": map_value_to_label(round(min(mvi, 10), 1)),
            "MVA": map_value_to_label(round(min(mva, 10), 1))
        }

    def calculate_MSC_MSI_MSA(self, asset_context: Asset):
        impact_weights = {"low": 0.5, "medium": 1.0, "high": 1.5, "none": 0}
        control_factors = {"strong": 0.5, "moderate": 0.8, "weak": 1.0}

        dependency = impact_weights[asset_context.asset_dependency_level]
        connected_criticality = impact_weights[asset_context.connected_systems_criticality]
        connectivity = impact_weights[asset_context.network_connectivity]
        cascading = impact_weights[asset_context.cascading_impact_potential]
        controls = control_factors[asset_context.connection_security_controls]

        # Calculate MSC, MSI, MSA
        MSC = impact_weights.get(self.cve.base_metric.SC.value.lower(),0) * dependency * connected_criticality * connectivity * cascading * controls
        MSI = impact_weights.get(self.cve.base_metric.SI.value.lower(),0) * dependency * connected_criticality * connectivity * cascading * controls
        MSA = impact_weights.get(self.cve.base_metric.SA.value.lower(),0) * dependency * connected_criticality * connectivity * cascading * controls

        # Helper mapping function
        def map_MSC(value):
            if value == 0:
                return "NONE"
            elif 0 < value <= 2.9:
                return "NEGLIGIBLE"
            elif 3.0 <= value <= 5.9:
                return "LOW"
            elif value >= 6.0:
                return "HIGH"
            else:
                return "NOT_DEFINED"

        def map_MSI_MSA(value):
            if value == 0:
                return "NONE"
            elif 0 < value <= 2.9:
                return "NEGLIGIBLE"
            elif 3.0 <= value <= 5.9:
                return "LOW"
            elif 6.0 <= value <= 8.9:
                return "HIGH"
            elif value >= 9.0:
                return "SAFETY"
            else:
                return "NOT_DEFINED"

        # Round numerical values first
        MSC = round(min(MSC, 10), 1)
        MSI = round(min(MSI, 10), 1)
        MSA = round(min(MSA, 10), 1)

        # Apply mappings
        MSC_label = map_MSC(MSC)
        MSI_label = map_MSI_MSA(MSI)
        MSA_label = map_MSI_MSA(MSA)

        return {
            "MSC": MSC_label,
            "MSI": MSI_label,
            "MSA": MSA_label
        }

    @staticmethod
    def cvss_rating(score):
        if score == 0.0:
            return "NONE"
        elif 0.1 <= score <= 3.9:
            return "LOW"
        elif 4.0 <= score <= 6.9:
            return "MEDIUM"
        elif 7.0 <= score <= 8.9:
            return "HIGH"
        elif 9.0 <= score <= 10.0:
            return "CRITICAL"
        else:
            return "Invalid Score"


class CVEAPIError(Exception):
    pass

