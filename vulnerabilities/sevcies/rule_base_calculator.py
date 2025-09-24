from assets.models import Asset
from vulnerabilities.models import Vulnerability, Response
from vulnerabilities.sevcies.cvss_v4 import calculate_environmental_metric, fetch_metrics, convert_to_abbreviations
from vulnerabilities.type import metrics_abbreviation, BaseMetric, AV, AC, PR

VALUE_X = "X"
VALUE_N = "N"
VALUE_A = "A"
VALUE_L = "L"
VALUE_P = "P"
VALUE_H = "H"
VALUE_M = "M"


# The asset parameter is now type-hinted as the Asset model
def calculate_mav(base_av: AV, asset: Asset) -> dict:
    """Calculates the Modified Attack Vector (MAV) from an Asset object."""
    mav = convert_to_abbreviations(base_av.value)
    rationale = f"Defaulting to base metric AV: {base_av.value} as no specific context rule was met."
    confidence = "High"

    # Accessing attributes directly from the object
    if asset.network_accessibility == 'Local_Only':
        mav = VALUE_L
        rationale = f"MAV is Local (L) because asset accessibility is 'Local_Only', overriding the base metric."
        confidence = "High"
    elif asset.network_accessibility == 'Physical_Only':
        mav = VALUE_P
        rationale = f"MAV is Physical (P) because asset accessibility is 'Physical_Only', overriding the base metric."
        confidence = "High"
    elif convert_to_abbreviations(base_av.value) == VALUE_N and asset.network_accessibility in [
        'Private_VPN_Access_Only',
        'Private_Corporate_Network',
        'Private_Highly_Restricted_Segment'
    ]:
        mav = VALUE_A
        rationale = f"MAV downgraded from Network to Adjacent (A) because the asset is on a private network ('{asset.get_network_accessibility_display()}')."
        confidence = "High"

    return {"modified_metric": mav, "rationale": rationale, "confidence": confidence}


def calculate_mac(base_ac: AC, asset: Asset) -> dict:
    """Calculates the Modified Attack Complexity (MAC) from an Asset object."""
    mac = convert_to_abbreviations(base_ac.value)
    rationale = f"Defaulting to base metric AC: {base_ac.value} as no specific context rule was met."
    confidence = "High"

    if convert_to_abbreviations(base_ac.value) == VALUE_L and (
            asset.system_hardening_level == 'Fully_Hardened' or
            asset.network_accessibility == 'Private_Highly_Restricted_Segment'
    ):
        mac = VALUE_H
        rationale = "MAC increased from Low to High due to strong compensating controls like 'Fully_Hardened' or a 'Highly_Restricted_Segment'."
        confidence = "Medium"

    elif convert_to_abbreviations(base_ac.value) == VALUE_H and (
            asset.system_hardening_level == 'Not_Hardened' and
            asset.software_patch_level == 'Outdated'
    ):
        mac = VALUE_L
        rationale = "MAC decreased from High to Low due to poor security posture ('Not_Hardened' and 'Outdated')."
        confidence = "Medium"

    return {"modified_metric": mac, "rationale": rationale, "confidence": confidence}


def calculate_mpr(base_pr: PR, asset: Asset) -> dict:
    """Calculates the Modified Privileges Required (MPR) from an Asset object."""
    mpr = convert_to_abbreviations(base_pr.value)
    rationale = f"Defaulting to base metric PR: {base_pr.value} as no specific context rule was met."
    confidence = "High"

    if mpr == VALUE_N:
        mpr = VALUE_N
        rationale = "The base Privileges Required is None (N), indicating no authentication is necessary to exploit the vulnerability."
        confidence = "High"
    elif convert_to_abbreviations(base_pr.value) in [VALUE_N, VALUE_L] and asset.authentication_strength == 'Multi_Factor':
        mpr = VALUE_H
        rationale = "MPR increased to High because the asset enforces Multi-Factor Authentication."
        confidence = "High"
    elif convert_to_abbreviations(base_pr.value) == VALUE_L and asset.privilege_escalation_protection == 'Present':
        mpr = VALUE_H
        rationale = "MPR increased from Low to High due to the presence of Privilege Escalation Protection controls."
        confidence = "Medium"

    return {"modified_metric": mpr, "rationale": rationale, "confidence": confidence}


def calculate_impact_metrics(base_metrics: BaseMetric, asset: Asset) -> tuple[dict, dict, dict]:
    """Calculates MVC, MVI, and MVA, each with its own rationale and confidence."""
    vc, vi, va = convert_to_abbreviations(base_metrics.VC.value), convert_to_abbreviations(base_metrics.VI.value), convert_to_abbreviations(base_metrics.VA.value)

    # Using Django's get_..._display() method gets the human-readable value for the rationale
    cr_display = asset.get_security_requirement_confidentiality_display()
    ir_display = asset.get_security_requirement_integrity_display()
    ar_display = asset.get_security_requirement_availability_display()

    # --- Confidentiality ---
    mvc = convert_to_abbreviations(asset.security_requirement_confidentiality) if convert_to_abbreviations(asset.security_requirement_confidentiality) != VALUE_M else vc
    rationale_c = f"MVC set to {mvc} to match the asset's Confidentiality Requirement ({cr_display})." if asset.security_requirement_confidentiality != VALUE_M else f"Defaulting to base VC: {vc}."
    conf_c = "High"
    if asset.data_encryption_level == 'Strong' and mvc == VALUE_H:
        mvc = VALUE_L
        rationale_c = "MVC lowered to Low due to 'Strong' data encryption, which mitigates the impact of data disclosure."
        conf_c = "Medium"

    # --- Integrity (UPDATED LOGIC) ---
    mvi = convert_to_abbreviations(asset.security_requirement_integrity) if convert_to_abbreviations(asset.security_requirement_integrity) != VALUE_M else vi
    rationale_i = f"MVI set to {mvi} to match the asset's Integrity Requirement ({ir_display})." if asset.security_requirement_integrity != VALUE_M else f"Defaulting to base VI: {vi}."
    conf_i = "High"

    # --- NEW RULE ADDED HERE ---
    if asset.integrity_protection_level == 'Preventive' and mvi == VALUE_H:
        mvi = VALUE_L
        rationale_i = "MVI lowered to Low due to 'Preventive' integrity controls (e.g., code signing, immutable storage), which mitigate the impact of unauthorized modification."
        conf_i = "Medium"

    # --- Availability ---
    mva = convert_to_abbreviations(asset.security_requirement_availability) if convert_to_abbreviations(asset.security_requirement_availability) != VALUE_M else va
    rationale_a = f"MVA set to {mva} to match the asset's Availability Requirement ({ar_display})." if convert_to_abbreviations(asset.security_requirement_availability) != VALUE_M else f"Defaulting to base VA: {va}."
    conf_a = "High"
    if asset.availability_redundancy == 'High' and mva == VALUE_H:
        mva = VALUE_L
        rationale_a = "MVA lowered to Low due to 'High' asset redundancy, which provides a failover and mitigates the impact."
        conf_a = "High"

    return (
        {"modified_metric": mvc, "rationale": rationale_c, "confidence": conf_c},
        {"modified_metric": mvi, "rationale": rationale_i, "confidence": conf_i},
        {"modified_metric": mva, "rationale": rationale_a, "confidence": conf_a}
    )

def calculate_subsequent_impact_metrics(base_metrics: BaseMetric, asset: Asset) -> tuple[dict, dict, dict]:
    """Calculates MSC, MSI, and MSA from an Asset object."""
    if asset.propagation_risk == 'Low':
        rationale = "Subsequent system impact is None (N) because Propagation Risk is assessed as 'Low'."
        result = {"modified_metric": VALUE_N, "rationale": rationale, "confidence": "High"}
        return result, result, result

    sc, si, sa = convert_to_abbreviations(base_metrics.SC.value), convert_to_abbreviations(base_metrics.SI.value), convert_to_abbreviations(base_metrics.SA.value)
    sub_cr, sub_ir, sub_ar = convert_to_abbreviations(asset.subsequent_system_confidentiality_req), convert_to_abbreviations(asset.subsequent_system_integrity_req), convert_to_abbreviations(asset.subsequent_system_availability_req)

    msc = sub_cr if sub_cr != VALUE_M else sc
    msi = sub_ir if sub_ir != VALUE_M else si
    msa = sub_ar if sub_ar != VALUE_M else sa

    return (
        {"modified_metric": msc,
         "rationale": f"MSC set to {msc} to match Subsequent System Confidentiality Requirement.",
         "confidence": "High"},
        {"modified_metric": msi, "rationale": f"MSI set to {msi} to match Subsequent System Integrity Requirement.",
         "confidence": "High"},
        {"modified_metric": msa, "rationale": f"MSA set to {msa} to match Subsequent System Availability Requirement.",
         "confidence": "High"}
    )

def separate_result_json(output: dict):
    return output["modified_metric"], output["confidence"], output["rationale"]

def calculate_environmental_metrics(asset: Asset, base_metrics: BaseMetric) -> dict:
    """Main function to orchestrate the calculation using an Asset object."""
    env_metrics = {"modified_metrics": {}, "confidence": {}, "rationale": {}}

    env_metrics["modified_metrics"]["MAV"], env_metrics["confidence"]["MAV"], env_metrics["rationale"]["MAV"] = separate_result_json(calculate_mav(base_metrics.AV, asset))
    env_metrics["modified_metrics"]["MAC"], env_metrics["confidence"]["MAC"], env_metrics["rationale"]["MAC"] = separate_result_json(calculate_mac(base_metrics.AC, asset))
    env_metrics["modified_metrics"]["MPR"], env_metrics["confidence"]["MPR"], env_metrics["rationale"]["MPR"] = separate_result_json(calculate_mpr(base_metrics.PR, asset))

    env_metrics["modified_metrics"]["MUI"] = VALUE_X
    env_metrics["confidence"]["MUI"] = "High"
    env_metrics["rationale"]["MUI"] = "MUI is not modified by this rule-based system."

    env_metrics["modified_metrics"]["MAT"] = VALUE_X
    env_metrics["confidence"]["MAT"] = "High"
    env_metrics["rationale"]["MAT"] = "Attack Requirements (AT) is a base metric not modified in the environmental group."

    mvc_res, mvi_res, mva_res = calculate_impact_metrics(base_metrics, asset)
    env_metrics["modified_metrics"]["MVC"], env_metrics["confidence"]["MVC"], env_metrics["rationale"]["MVC"] = separate_result_json(mvc_res)
    env_metrics["modified_metrics"]["MVI"], env_metrics["confidence"]["MVI"], env_metrics["rationale"]["MVI"] = separate_result_json(mvi_res)
    env_metrics["modified_metrics"]["MVA"], env_metrics["confidence"]["MVA"], env_metrics["rationale"]["MVA"] = separate_result_json(mva_res)

    msc_res, msi_res, msa_res = calculate_subsequent_impact_metrics(base_metrics, asset)

    env_metrics["modified_metrics"]["MSC"], env_metrics["confidence"]["MSC"], env_metrics["rationale"]["MSC"] = separate_result_json(msc_res)
    env_metrics["modified_metrics"]["MSI"], env_metrics["confidence"]["MSI"], env_metrics["rationale"]["MSI"] = separate_result_json(msi_res)
    env_metrics["modified_metrics"]["MSA"], env_metrics["confidence"]["MSA"], env_metrics["rationale"]["MSA"] = separate_result_json(msa_res)

    return env_metrics

def prepare_rule_base_for_calculator(answer: dict, asset: Asset, base_metric: BaseMetric):
    base = {
        "AV": metrics_abbreviation[base_metric.AV.value],
        "AC": metrics_abbreviation[base_metric.AC.value],
        "AT": metrics_abbreviation[base_metric.AT.value],
        "PR": metrics_abbreviation[base_metric.PR.value],
        "UI": metrics_abbreviation[base_metric.UI.value],
        "VC": metrics_abbreviation[base_metric.VC.value],
        "VI": metrics_abbreviation[base_metric.VI.value],
        "VA": metrics_abbreviation[base_metric.VA.value],
        "SC": metrics_abbreviation[base_metric.SC.value],
        "SI": metrics_abbreviation[base_metric.SI.value],
        "SA": metrics_abbreviation[base_metric.SA.value]
    }
    env = {
        "MAV": convert_to_abbreviations(answer['modified_metrics']["MAV"]),
        "MAC": convert_to_abbreviations(answer['modified_metrics']["MAC"]),
        "MAT": convert_to_abbreviations(answer['modified_metrics']["MAT"]),
        "MPR": convert_to_abbreviations(answer['modified_metrics']["MPR"]),
        "MUI": convert_to_abbreviations(answer['modified_metrics']["MUI"]),
        "MVC": convert_to_abbreviations(answer['modified_metrics']["MVC"]),
        "MVI": convert_to_abbreviations(answer['modified_metrics']["MVI"]),
        "MVA": convert_to_abbreviations(answer['modified_metrics']["MVA"]),
        "MSC": convert_to_abbreviations(answer['modified_metrics']["MSC"]),
        "MSI": convert_to_abbreviations(answer['modified_metrics']["MSI"]),
        "MSA": convert_to_abbreviations(answer['modified_metrics']["MSA"]),
    }

    req = {
        "CR": metrics_abbreviation[asset.security_requirement_confidentiality.upper()],
        "IR": metrics_abbreviation[asset.security_requirement_integrity.upper()],
        "AR": metrics_abbreviation[asset.security_requirement_availability.upper()]
    }
    return {**base, **env, **req}

def rule_base_answer(asset: Asset, vuln: Vulnerability):
    base_metric = fetch_metrics(vuln.base_vector)
    answer = calculate_environmental_metrics(asset, base_metric)
    rule_base = prepare_rule_base_for_calculator(answer, asset, base_metric)
    score, severity = calculate_environmental_metric(rule_base)
    answer.update({'score': score, 'severity': severity})
    Response.objects.update_or_create(
        impacted_asset=asset,
        vulnerability=vuln,
        defaults={
            'rule_response': answer,
            'rule_score': score,
        }
    )
    return answer
