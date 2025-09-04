from typing import Dict, Any, Tuple
from assets.models import Asset
from vulnerabilities.models import Vulnerability, Response

from vulnerabilities.sevcies.cvss_v4 import calculate_environmental_metric, convert_to_abbreviations, fetch_metrics
from vulnerabilities.type import metrics_abbreviation, BaseMetric

"""
 ------------------------------------------------------------
 CVSS v4 Environmental - Rule-based evaluator (labels fixed)
 ------------------------------------------------------------
 Output values now match CVSS v4 Environmental enumerations:
   MAV: ["NETWORK","ADJACENT","LOCAL","PHYSICAL","NOT_DEFINED"]
   MAC: ["LOW","HIGH","NOT_DEFINED"]
   MAT: ["NONE","PRESENT","NOT_DEFINED"]
   MPR: ["NONE","LOW","HIGH","NOT_DEFINED"]
   MUI: ["NONE","PASSIVE","ACTIVE","NOT_DEFINED"]
   MVC: ["NONE","LOW","HIGH","NOT_DEFINED"]
   MVI: ["NONE","LOW","HIGH","NOT_DEFINED"]
   MVA: ["NONE","LOW","HIGH","NOT_DEFINED"]
   MSC: ["LOW","NEGLIGIBLE","HIGH","NOT_DEFINED"]
   MSI: ["LOW","NEGLIGIBLE","HIGH","SAFETY","NOT_DEFINED"]
   MSA: ["LOW","NEGLIGIBLE","HIGH","SAFETY","NOT_DEFINED"]
   CR/IR/AR: ["LOW","MEDIUM","HIGH","NOT_DEFINED"]
 ------------------------------------------------------------
"""

# Internal step helpers (use simple ordered ladders for heuristics)
ORDER_IMPACT = ['L', 'M', 'H']          # internal: for MVC/MVI/MVA & subsequent
ORDER_COMPLEXITY = ['L', 'H']           # CVSS v4 MAC has only LOW/HIGH
ORDER_PR = ['N', 'L', 'H']              # internal ordering for MPR

def step(val: str, up: int = 0, down: int = 0, order=('L', 'M', 'H')) -> str:
    if val not in order:
        return val
    i = order.index(val)
    i = min(len(order) - 1, i + up)
    i = max(0, i - down)
    return order[i]

def map_requirements(v: str) -> str:
    v = (v or '').lower()
    if v == 'high': return 'HIGH'
    if v == 'medium': return 'MEDIUM'
    if v == 'low': return 'LOW'
    return 'NOT_DEFINED'

def boolish(v: Any) -> bool:
    return str(v).lower() == 'true'

def present(v: Any) -> bool:
    return str(v).lower() == 'present'

def first_match(*conds_actions: Tuple[bool, str], default: str) -> str:
    for cond, val in conds_actions:
        if cond:
            return val
    return default

def _conf(high=False, med=False, low=False, default='Medium') -> str:
    if high: return 'High'
    if med: return 'Medium'
    if low: return 'Low'
    return default

# ----------- final label mappers (internal -> CVSS v4 strings) -----------

_MAV_TO_STR = {'N':'NETWORK','A':'ADJACENT','L':'LOCAL','P':'PHYSICAL','X':'NOT_DEFINED'}
_MAT_TO_STR = {'N':'NONE','P':'PRESENT','X':'NOT_DEFINED'}
_MPR_TO_STR = {'N':'NONE','L':'LOW','H':'HIGH','X':'NOT_DEFINED'}
_MUI_TO_STR = {'N':'NONE','P':'PASSIVE','A':'ACTIVE','X':'NOT_DEFINED'}

def _impact_internal_to_env(v: str) -> str:
    # For MVC/MVI/MVA allowed: NONE/LOW/HIGH
    # Map internal 'L'->LOW, 'M'->LOW (coerce medium down), 'H'->HIGH, 'X'->NOT_DEFINED
    return {'L':'LOW','M':'LOW','H':'HIGH','N':'NONE','X':'NOT_DEFINED'}.get(v, 'NOT_DEFINED')

def _subseq_internal_to_env(v: str) -> str:
    # For MSC/MSI/MSA allowed: LOW/NEGLIGIBLE/HIGH (plus SAFETY/NOT_DEFINED)
    # Use 'L'->LOW, 'M'->NEGLIGIBLE, 'H'->HIGH
    return {'L':'LOW','M':'NEGLIGIBLE','H':'HIGH','X':'NOT_DEFINED'}.get(v, 'NOT_DEFINED')

def score_environmental(asset: Asset) -> Dict[str, Any]:
    rationale, confidence = {}, {}


    # -------------------------
    # 2) MAV - Modified Attack Vector (internal N/A/L/P -> strings)
    # -------------------------
    exposure = (asset.exposure_level or '').lower()
    fw = (asset.firewall_configuration or '').lower()
    seg = (asset.network_segmentation or '').lower()
    vpn_req = (asset.vpn_access or '').lower() == 'required'
    ssh_pub = boolish(asset.ssh_remote_access)

    MAV_i = first_match(
        (exposure == 'physical', 'P'),
        (exposure == 'local' or fw == 'block_internal_external_inbound', 'L'),
        (seg in ('isolated', 'highly_isolated') or vpn_req, 'A'),
        (exposure == 'internal' and (vpn_req or seg == 'highly_isolated'), 'A'),
        (exposure == 'external' or ssh_pub or fw == 'allow_external_inbound', 'N'),
        default='A'
    )
    MAV = _MAV_TO_STR.get(MAV_i, 'NOT_DEFINED')
    rationale['MAV'] = (
        f"Derived from reachability and controls: physical_required={'yes' if exposure == 'physical' else 'no'}, "
        f"exposure={exposure}, firewall={fw}, segmentation={seg}, vpn_required={vpn_req}, ssh_remote_access={ssh_pub}."
    )
    confidence['MAV'] = _conf(high=True)

    # -------------------------
    # 3) MAC - Modified Attack Complexity (LOW/HIGH only)
    # -------------------------
    base_map = {'multiple_steps': 'H', 'moderate_steps': 'L', 'direct_access': 'L'}  # no MEDIUM in v4
    base_mac_i = base_map.get((asset.network_access_complexity or '').lower(), 'L')

    hardeners = sum([
        present(asset.security_controls_waf),
        present(asset.security_controls_ids),
        present(asset.security_controls_ips),
        present(asset.security_controls_firewall),
        (asset.system_hardening_level or '').lower() == 'fully_hardened'
    ])

    mac_i = base_mac_i
    pre_i = mac_i
    # ORDER_COMPLEXITY is ['L','H']
    if hardeners >= 2:
        mac_i = step(mac_i, down=1, order=ORDER_COMPLEXITY)
    if (asset.system_hardening_level or '').lower() == 'not_hardened' or (asset.software_patch_level or '').lower() == 'outdated':
        mac_i = step(mac_i, up=1, order=ORDER_COMPLEXITY)

    MAC = 'LOW' if mac_i == 'L' else 'HIGH'
    rationale['MAC'] = (
        f"Base from network_access_complexity={asset.network_access_complexity} -> { 'HIGH' if base_mac_i=='H' else 'LOW' }; "
        f"hardeners={hardeners} adjusted { 'HIGH' if pre_i=='H' else 'LOW' }->{MAC} with hardening/patch signals."
    )
    confidence['MAC'] = _conf(med=True)

    # -------------------------
    # 4) MAT - Modified Attack Requirements (NONE/PRESENT)
    # -------------------------
    auth = (asset.authentication_requirement or '').lower()
    acs = (asset.access_control_strength or '').lower()

    if auth != 'none' and MAV in ('NETWORK', 'ADJACENT') and acs == 'strong':
        MAT_i = 'P'
        reason = "Strong auth/controls required before exploit."
    elif auth == 'single_factor' or vpn_req or seg in ('isolated', 'highly_isolated'):
        MAT_i = 'P'
        reason = "Some preconditions (single-factor and/or network isolation/VPN)."
    else:
        MAT_i = 'N'
        reason = "Few or no additional situational requirements."
    MAT = _MAT_TO_STR.get(MAT_i, 'NOT_DEFINED')
    rationale['MAT'] = f"{reason} (auth={auth}, MAV={MAV}, access_control_strength={acs})."
    confidence['MAT'] = _conf(med=True)

    # -------------------------
    # 5) MPR - Modified Privileges Required
    # -------------------------
    upr = (asset.user_privilege_level_required or '').lower()
    base_pr_i = {'none': 'N', 'basic_user': 'L', 'admin_or_elevated': 'H'}.get(upr, 'L')

    pep = (asset.privilege_escalation_protection or '').lower()
    if base_pr_i == 'H' and pep == 'absent' and acs == 'weak':
        MPR_i = 'L'
        adjustment = "downgraded due to weak access control and absent PE protection"
    elif base_pr_i == 'L' and acs == 'strong' and pep == 'present':
        MPR_i = 'H'
        adjustment = "upgraded due to strong access control and present PE protection"
    else:
        MPR_i = base_pr_i
        adjustment = "no change"

    MPR = _MPR_TO_STR.get(MPR_i, 'NOT_DEFINED')
    rationale['MPR'] = (
        f"Base from user_privilege_level_required={upr} -> {_MPR_TO_STR.get(base_pr_i)}; "
        f"{adjustment} (access_control_strength={acs}, privilege_escalation_protection={pep})."
    )
    confidence['MPR'] = _conf(med=True)

    # -------------------------
    # 6) MUI - Modified User Interaction (NONE/PASSIVE/ACTIVE)
    # -------------------------
    tp = (asset.tp or '').lower()
    user_aw = (asset.user_awareness_level or '').lower()

    MUI = _MUI_TO_STR.get("X", 'NOT_DEFINED')
    rationale['MUI'] =  "There is no enough evidence for UI."
    confidence['MUI'] = _conf(low=True)

    # -------------------------
    # 7) MVC / MVI / MVA - Impacts (NONE/LOW/HIGH only)
    # -------------------------
    data_sens = (asset.data_sensitivity or '').lower()
    enc = (asset.encryption_protection_level or '').lower()
    crit = (asset.asset_criticality or '').lower()
    avail_red = (asset.availability_redundancy or '').lower()
    net_conn = (asset.network_connectivity or '').lower()

    # MVC (internal L/M/H then coerced)
    mvc_i = {'highly_sensitive': 'H', 'operationally_critical': 'M', 'non_sensitive': 'L'}.get(data_sens, 'M')
    pre_mvc = mvc_i
    if enc == 'strong':
        mvc_i = step(mvc_i, down=1, order=ORDER_IMPACT)
    if crit == 'high' and (exposure in ('external', 'internal')):
        mvc_i = step(mvc_i, up=1, order=ORDER_IMPACT)
    MVC = _impact_internal_to_env(mvc_i)
    rationale['MVC'] = (
        f"Start from data_sensitivity={data_sens}->{_impact_internal_to_env(pre_mvc)} "
        f"(internal {pre_mvc}); encryption={enc} and asset_criticality={crit} with exposure={exposure} -> {MVC}."
    )
    confidence['MVC'] = _conf(med=True)

    # MVI
    mvi_i = {'high': 'H', 'medium': 'M', 'low': 'L'}.get(crit, 'M')
    pre_mvi = mvi_i
    if (asset.system_hardening_level or '').lower() == 'fully_hardened' \
       and present(asset.security_controls_edr) and present(asset.security_controls_firewall):
        mvi_i = step(mvi_i, down=1, order=ORDER_IMPACT)
    if acs == 'weak' or (asset.software_patch_level or '').lower() == 'outdated':
        mvi_i = step(mvi_i, up=1, order=ORDER_IMPACT)
    MVI = _impact_internal_to_env(mvi_i)
    rationale['MVI'] = (
        f"Start from asset_criticality={crit}->{_impact_internal_to_env(pre_mvi)} "
        f"(internal {pre_mvi}); hardening/EDR/firewall and access_control_strength={acs}, "
        f"patch_level={asset.software_patch_level} -> {MVI}."
    )
    confidence['MVI'] = _conf(med=True)

    # MVA
    mva_i = {'high': 'H', 'medium': 'M', 'low': 'L'}.get(crit, 'M')
    pre_mva = mva_i
    if avail_red == 'high':
        mva_i = step(mva_i, down=1, order=ORDER_IMPACT)
    elif avail_red == 'low':
        mva_i = step(mva_i, up=1, order=ORDER_IMPACT)
    if tp in ('database', 'webserver') and net_conn == 'direct_access':
        mva_i = step(mva_i, up=1, order=ORDER_IMPACT)
    MVA = _impact_internal_to_env(mva_i)
    rationale['MVA'] = (
        f"Start from asset_criticality={crit}->{_impact_internal_to_env(pre_mva)} "
        f"(internal {pre_mva}); availability_redundancy={avail_red}, tp={tp}, "
        f"network_connectivity={net_conn} -> {MVA}."
    )
    confidence['MVA'] = _conf(med=True)


    cascad = (asset.cascading_impact_potential or '').lower()
    base_sub_i = {'high': 'H', 'moderate': 'M', 'low': 'L'}.get(cascad, 'L')
    dep = (asset.asset_dependency_level or '').lower()
    conn_crit = (asset.connected_systems_criticality or '').lower()
    conn_sec = (asset.connection_security_controls or '').lower()
    net_isol = net_conn == 'isolated'

    def adjust_sub(v):
        out = v
        if dep == 'high' or conn_crit == 'high':
            out = step(out, up=1, order=ORDER_IMPACT)
        if conn_sec == 'strong' or net_isol:
            out = step(out, down=1, order=ORDER_IMPACT)
        return out

    MSC_i = adjust_sub(base_sub_i)
    MSI_i = adjust_sub(base_sub_i)
    MSA_i = adjust_sub(base_sub_i)

    # Map to allowed sets (no SAFETY inferred here due to lack of input signal)
    sub_metric = {
        'MSC': _subseq_internal_to_env(MSC_i),
        'MSI': _subseq_internal_to_env(MSI_i),
        'MSA': _subseq_internal_to_env(MSA_i)
    }

    rationale['MSC'] = (
        f"Base={_subseq_internal_to_env(base_sub_i)} (internal {base_sub_i}) from cascading_impact_potential={cascad}; "
        f"adjusted by dependency={dep}, connected_systems_criticality={conn_crit}, "
        f"connection_security_controls={conn_sec}, network_connectivity={net_conn}."
    )
    rationale['MSI'] = "Same adjustment model as MSC."
    rationale['MSA'] = "Same adjustment model as MSC."
    confidence['MSC'] = _conf(med=True)
    confidence['MSI'] = _conf(med=True)
    confidence['MSA'] = _conf(med=True)

    metrics = {
        'MAV': convert_to_abbreviations(MAV), 'MAC': convert_to_abbreviations(MAC), 'MAT': convert_to_abbreviations(MAT), 'MPR': convert_to_abbreviations(MPR), 'MUI': convert_to_abbreviations(MUI),
        'MVC': convert_to_abbreviations(MVC), 'MVI': convert_to_abbreviations(MVI), 'MVA': convert_to_abbreviations(MVA)
    }
    metrics.update(sub_metric)

    return {
        'metrics': metrics,
        'rationale': rationale,
        'confidence': confidence
    }

def rule_base_answer(asset: Asset, vuln: Vulnerability):
    answer = score_environmental(asset)
    base_metric = fetch_metrics(vuln.base_vector)
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
        "MAV": convert_to_abbreviations(answer['metrics']["MAV"]),
        "MAC": convert_to_abbreviations(answer['metrics']["MAC"]),
        "MAT": convert_to_abbreviations(answer['metrics']["MAT"]),
        "MPR": convert_to_abbreviations(answer['metrics']["MPR"]),
        "MUI": convert_to_abbreviations(answer['metrics']["MUI"]),
        "MVC": convert_to_abbreviations(answer['metrics']["MVC"]),
        "MVI": convert_to_abbreviations(answer['metrics']["MVI"]),
        "MVA": convert_to_abbreviations(answer['metrics']["MVA"]),
        "MSC": convert_to_abbreviations(answer['metrics']["MSC"]),
        "MSI": convert_to_abbreviations(answer['metrics']["MSI"]),
        "MSA": convert_to_abbreviations(answer['metrics']["MSA"]),
    }

    req = {
        "CR": metrics_abbreviation[asset.security_requirements_confidentiality.upper()],
        "IR": metrics_abbreviation[asset.security_requirements_integrity.upper()],
        "AR": metrics_abbreviation[asset.security_requirements_availability.upper()]
    }
    return {**base, **env, **req}
