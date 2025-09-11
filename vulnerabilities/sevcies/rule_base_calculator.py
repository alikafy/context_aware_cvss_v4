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
ORDER_IMPACT_SUB = ['N', 'L', 'H', 'S']          # internal: for MSC/MSI/MSA
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
    return {'L':'NONE','M':'LOW','H':'HIGH','N':'NONE','X':'NOT_DEFINED'}.get(v, 'NOT_DEFINED')

def _subseq_internal_to_env(v: str) -> str:
    # For MSC/MSI/MSA allowed: LOW/NEGLIGIBLE/HIGH (plus SAFETY/NOT_DEFINED)
    # Use 'L'->LOW, 'M'->NEGLIGIBLE, 'H'->HIGH
    return {'N':'NEGLIGIBLE', 'L':'LOW','M':'LOW','H':'HIGH', 'S':'SAFETY', 'X':'NOT_DEFINED'}.get(v, 'NOT_DEFINED')

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
    if (asset.software_patch_level or '').lower() == 'outdated':
        hardeners = hardeners - 2
    if (asset.software_patch_level or '').lower() == 'partially_updated':
        hardeners = hardeners - 1
    if hardeners >= 2:
        mac_i = step(mac_i, up=1, order=ORDER_COMPLEXITY)
    if (asset.system_hardening_level or '').lower() == 'not_hardened':
        mac_i = step(mac_i, down=1, order=ORDER_COMPLEXITY)

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
    rationale['MUI'] =  "There is insufficient evidence for UI."
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

    def adjust_sub(v, order):
        out = v
        if dep == 'high' or conn_crit == 'high':
            out = step(out, up=1, order=order)
        if conn_sec == 'strong' or net_isol:
            out = step(out, down=1, order=order)
        return out

    MSC_i = adjust_sub(base_sub_i, ORDER_IMPACT)
    MSI_i = adjust_sub(base_sub_i, ORDER_IMPACT_SUB)
    MSA_i = adjust_sub(base_sub_i, ORDER_IMPACT_SUB)

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
    new_response = compute_env_modified_from_asset(asset)

    metrics = {
        'MAV': convert_to_abbreviations(MAV), 'MAC': convert_to_abbreviations(MAC), 'MAT': convert_to_abbreviations(MAT), 'MPR': convert_to_abbreviations(MPR), 'MUI': convert_to_abbreviations(MUI),
        'MVC': convert_to_abbreviations(MVC), 'MVI': convert_to_abbreviations(MVI), 'MVA': convert_to_abbreviations(MVA)
    }
    metrics.update(sub_metric)

    metrics.update(new_response['metrics'])
    rationale.update(new_response['rationale'])
    # confidence.update(new_response['confidence'])
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
# utils/cvss_env_modified.py

from typing import Dict, List, Tuple, Literal

# Output types
LevelVuln = Literal["H", "L", "N"]           # MVC/MVI/MVA
LevelSubC = Literal["H", "L", "N"]           # MSC (N = Negligible)
LevelSubIA = Literal["S", "H", "L", "N"]     # MSI/MSA (Safety + H/L/N)

def _cap_0_100(x: int) -> int:
    return max(0, min(100, x))

def _bucket_vuln(score: int) -> LevelVuln:
    # vulnerable system: H/L/None
    if score >= 70: return "H"
    if score >= 35: return "L"
    return "N"

def _bucket_sub(score: int) -> LevelSubC:
    # subsequent confidentiality: H/L/Negligible
    if score >= 70: return "H"
    if score >= 35: return "L"
    return "N"

def _fmt(label: str, value: str, delta: int) -> str:
    sgn = "+" if delta >= 0 else "-"
    return f"{label}={value} ({sgn}{abs(delta)})"

def compute_env_modified_from_asset(asset) -> Dict:
    """
    Compute CVSS v4 Environmental Modified Impact metrics from a Django Asset instance.

    Returns:
        {
          'metrics': {'MVC','MVI','MVA','MSC','MSI','MSA'},
          'rationale': {'MVC': str, ...},
          'confidence': 'High'|'Medium'|'Low'
        }
    """
    # --------- pull fields (already normalized by your model choices)
    sr_c = getattr(asset, "security_requirements_confidentiality", "")
    sr_i = getattr(asset, "security_requirements_integrity", "")
    sr_a = getattr(asset, "security_requirements_availability", "")

    asset_crit = getattr(asset, "asset_criticality", "")
    data_sens = getattr(asset, "data_sensitivity", "")
    enc = getattr(asset, "encryption_protection_level", "")
    red = getattr(asset, "availability_redundancy", "")

    dep = getattr(asset, "asset_dependency_level", "")
    conn_crit = getattr(asset, "connected_systems_criticality", "")
    net_conn = getattr(asset, "network_connectivity", "")
    cascade = getattr(asset, "cascading_impact_potential", "")
    conn_ctrls = getattr(asset, "connection_security_controls", "")

    # extra environment/controls (used mainly for subsequent impacts)
    exposure = getattr(asset, "exposure_level", "")
    seg = getattr(asset, "network_segmentation", "")
    fw_cfg = getattr(asset, "firewall_configuration", "")
    vpn = getattr(asset, "vpn_access", "")
    ssh = getattr(asset, "ssh_remote_access", "")

    waf = getattr(asset, "security_controls_waf", "")
    fw = getattr(asset, "security_controls_firewall", "")
    ids = getattr(asset, "security_controls_ids", "")
    ips = getattr(asset, "security_controls_ips", "")
    edr = getattr(asset, "security_controls_edr", "")

    harden = getattr(asset, "system_hardening_level", "")
    patch = getattr(asset, "software_patch_level", "")
    nac = getattr(asset, "network_access_complexity", "")
    auth = getattr(asset, "authentication_requirement", "")
    acs = getattr(asset, "access_control_strength", "")
    priv_esc = getattr(asset, "privilege_escalation_protection", "")
    user_awareness = getattr(asset, "user_awareness_level", "")
    tp = getattr(asset, "tp", "")

    # --------- weights (tune here – simple/transparent)
    SR_W = {"high": 45, "medium": 25, "low": 10, "not_defined": 0, "": 0}
    ASSET_CRIT_W = {"high": 20, "medium": 10, "low": 0, "": 0}

    DATA_C_W = {"highly_sensitive": 30, "operationally_critical": 10, "non_sensitive": 0, "": 0}
    DATA_I_W = {"highly_sensitive": 12, "operationally_critical": 18, "non_sensitive": 0, "": 0}
    DATA_A_W = {"highly_sensitive": 10, "operationally_critical": 22, "non_sensitive": 0, "": 0}

    ENC_C_W = {"strong": -25, "moderate": -10, "weak": 0, "": 0}
    ENC_I_W = {"strong": -10, "moderate": -5, "weak": 0, "": 0}
    AVAIL_RED_W = {"high": -25, "moderate": -10, "low": 0, "": 0}

    DEP_W = {"high": 15, "medium": 8, "low": 0, "": 0}
    CONN_CRIT_W = {"high": 25, "medium": 12, "low": 0, "": 0}
    CASCADE_W = {"high": 30, "medium": 15, "low": 0, "": 0}
    NET_CONN_W = {"direct_access": 15, "indirect_access": 8, "isolated": 0, "": 0}
    CONN_CTRL_W = {"strong": -20, "moderate": -10, "weak": 0, "": 0}

    # Additional containment/exposure signals (mainly for subsequent propagation)
    EXPOSURE_W = {"external": 15, "internal": 8, "local": 2, "physical": 0, "": 0}
    SEG_W = {"none": 12, "isolated": 5, "highly_isolated": 0, "": 0}
    FW_CFG_W = {
        "allow_external_inbound": 12,
        "block_external_allow_internal_only": 6,
        "block_internal_external_inbound": 0,
        "": 0,
    }
    VPN_W = {"not_required": 5, "required": 0, "": 0}
    SSH_W = {"true": 5, "false": 0, "": 0}

    # Technical mitigations (small nudges; primarily affect subsequent)
    CTRL_PRESENT_MINUS = {"present": -4, "absent": 0, "": 0}
    HARDEN_W = {"fully_hardened": -6, "partially_hardened": -3, "not_hardened": 0, "": 0}
    PATCH_W = {"up_to_date": -4, "partially_updated": -2, "outdated": 0, "": 0}
    NAC_W = {"multiple_steps": -5, "moderate_steps": -2, "direct_access": 0, "": 0}
    AUTH_W = {"multi_factor": -8, "single_factor": -3, "none": 0, "": 0}
    ACS_W = {"strong": -8, "moderate": -4, "weak": 0, "": 0}
    PRIV_ESC_W = {"present": -8, "absent": 0, "": 0}
    AWARE_W = {"high": -2, "low": 0, "": 0}

    # --------- VULNERABLE SYSTEM (MVC/MVI/MVA)

    def _score_vc() -> Tuple[int, List[str]]:
        parts: List[str] = []
        s = 0
        d = SR_W[sr_c]; s += d; parts.append(_fmt("security_requirements_confidentiality", sr_c, d))
        d = ASSET_CRIT_W[asset_crit]; s += d; parts.append(_fmt("asset_criticality", asset_crit, d))
        d = DATA_C_W[data_sens]; s += d; parts.append(_fmt("data_sensitivity", data_sens, d))
        d = ENC_C_W[enc]; s += d; parts.append(_fmt("encryption_protection_level", enc, d))
        # minor mitigations
        d = AUTH_W.get(auth, 0); s += d; parts.append(_fmt("authentication_requirement", auth, d))
        d = ACS_W.get(acs, 0); s += d; parts.append(_fmt("access_control_strength", acs, d))
        d = HARDEN_W.get(harden, 0); s += d; parts.append(_fmt("system_hardening_level", harden, d))
        d = PATCH_W.get(patch, 0); s += d; parts.append(_fmt("software_patch_level", patch, d))
        return _cap_0_100(s), parts

    def _score_vi() -> Tuple[int, List[str]]:
        parts: List[str] = []
        s = 0
        d = SR_W[sr_i]; s += d; parts.append(_fmt("security_requirements_integrity", sr_i, d))
        d = ASSET_CRIT_W[asset_crit]; s += d; parts.append(_fmt("asset_criticality", asset_crit, d))
        d = DATA_I_W[data_sens]; s += d; parts.append(_fmt("data_sensitivity", data_sens, d))
        d = ENC_I_W[enc]; s += d; parts.append(_fmt("encryption_protection_level", enc, d))
        # integrity-specific mitigations
        d = PRIV_ESC_W.get(priv_esc, 0); s += d; parts.append(_fmt("privilege_escalation_protection", priv_esc, d))
        d = AUTH_W.get(auth, 0); s += d; parts.append(_fmt("authentication_requirement", auth, d))
        d = ACS_W.get(acs, 0); s += d; parts.append(_fmt("access_control_strength", acs, d))
        d = HARDEN_W.get(harden, 0); s += d; parts.append(_fmt("system_hardening_level", harden, d))
        d = PATCH_W.get(patch, 0); s += d; parts.append(_fmt("software_patch_level", patch, d))
        return _cap_0_100(s), parts

    def _score_va() -> Tuple[int, List[str]]:
        parts: List[str] = []
        s = 0
        d = SR_W[sr_a]; s += d; parts.append(_fmt("security_requirements_availability", sr_a, d))
        d = ASSET_CRIT_W[asset_crit]; s += d; parts.append(_fmt("asset_criticality", asset_crit, d))
        d = DATA_A_W[data_sens]; s += d; parts.append(_fmt("data_sensitivity", data_sens, d))
        d = AVAIL_RED_W[red]; s += d; parts.append(_fmt("availability_redundancy", red, d))
        d = DEP_W[dep]; s += d; parts.append(_fmt("asset_dependency_level", dep, d))
        # small hygiene effects
        d = HARDEN_W.get(harden, 0); s += d; parts.append(_fmt("system_hardening_level", harden, d))
        d = PATCH_W.get(patch, 0); s += d; parts.append(_fmt("software_patch_level", patch, d))
        return _cap_0_100(s), parts

    # --------- SUBSEQUENT SYSTEM (MSC/MSI/MSA)

    def _base_sub_with_env() -> Tuple[int, List[str]]:
        """Connectivity/propagation base + environment/controls."""
        parts: List[str] = []
        s = 0
        # core propagation
        d = CONN_CRIT_W[conn_crit]; s += d; parts.append(_fmt("connected_systems_criticality", conn_rit if (conn_rit:=conn_crit) else conn_crit, d))
        d = DEP_W[dep]; s += d; parts.append(_fmt("asset_dependency_level", dep, d))
        d = CASCADE_W[cascade]; s += d; parts.append(_fmt("cascading_impact_potential", cascade, d))
        d = NET_CONN_W[net_conn]; s += d; parts.append(_fmt("network_connectivity", net_conn, d))
        d = CONN_CTRL_W[conn_ctrls]; s += d; parts.append(_fmt("connection_security_controls", conn_ctrls, d))

        # reachability amplifiers
        d = EXPOSURE_W[exposure]; s += d; parts.append(_fmt("exposure_level", exposure, d))
        d = SEG_W[seg]; s += d; parts.append(_fmt("network_segmentation", seg, d))
        d = FW_CFG_W[fw_cfg]; s += d; parts.append(_fmt("firewall_configuration", fw_cfg, d))
        d = VPN_W[vpn]; s += d; parts.append(_fmt("vpn_access", vpn, d))
        d = SSH_W[ssh]; s += d; parts.append(_fmt("ssh_remote_access", ssh, d))

        # generic mitigations (small reductions)
        d = CTRL_PRESENT_MINUS[waf]; s += d; parts.append(_fmt("security_controls_waf", waf, d))
        d = CTRL_PRESENT_MINUS[fw]; s += d; parts.append(_fmt("security_controls_firewall", fw, d))
        d = CTRL_PRESENT_MINUS[ids]; s += d; parts.append(_fmt("security_controls_ids", ids, d))
        d = CTRL_PRESENT_MINUS[ips]; s += d; parts.append(_fmt("security_controls_ips", ips, d))
        d = CTRL_PRESENT_MINUS[edr]; s += d; parts.append(_fmt("security_controls_edr", edr, d))
        d = HARDEN_W.get(harden, 0); s += d; parts.append(_fmt("system_hardening_level", harden, d))
        d = NAC_W.get(nac, 0); s += d; parts.append(_fmt("network_access_complexity", nac, d))
        d = AWARE_W.get(user_awareness, 0); s += d; parts.append(_fmt("user_awareness_level", user_awareness, d))

        return _cap_0_100(s), parts

    def _score_sc() -> Tuple[int, List[str]]:
        base, parts = _base_sub_with_env()
        extra = 15 if data_sens == "highly_sensitive" else 0
        if extra:
            parts.append(_fmt("data_sensitivity→confidentiality_propagation", data_sens, extra))
        return _cap_0_100(base + extra), parts

    def _score_si() -> Tuple[int, List[str]]:
        base, parts = _base_sub_with_env()
        extra = 12 if data_sens == "operationally_critical" else 0
        if extra:
            parts.append(_fmt("data_sensitivity→integrity_propagation", data_sens, extra))
        return _cap_0_100(base + extra), parts

    def _score_sa() -> Tuple[int, List[str]]:
        base, parts = _base_sub_with_env()
        extra = 15 if data_sens == "operationally_critical" else 0
        if extra:
            parts.append(_fmt("data_sensitivity→availability_propagation", data_sens, extra))
        return _cap_0_100(base + extra), parts

    # Safety signal (lets MSI/MSA become 'S')
    def _score_safety() -> Tuple[int, List[str]]:
        s, parts = 0, []
        # operationally critical processes + strong propagation signals imply safety concerns
        d = 30 if data_sens == "operationally_critical" else 0; s += d; parts.append(_fmt("data_sensitivity", data_sens, d))
        d = 20 if asset_crit == "high" else 10 if asset_crit == "medium" else 0; s += d; parts.append(_fmt("asset_criticality", asset_crit, d))
        d = 25 if conn_crit == "high" else 12 if conn_crit == "medium" else 0; s += d; parts.append(_fmt("connected_systems_criticality", conn_crit, d))
        d = 25 if cascade == "high" else 12 if cascade == "medium" else 0; s += d; parts.append(_fmt("cascading_impact_potential", cascade, d))
        d = 15 if dep == "high" else 8 if dep == "medium" else 0; s += d; parts.append(_fmt("asset_dependency_level", dep, d))
        d = 10 if net_conn == "direct_access" else 5 if net_conn == "indirect_access" else 0; s += d; parts.append(_fmt("network_connectivity", net_conn, d))
        # exposure/seg/fw that increase external reachability
        d = 10 if exposure == "external" else 5 if exposure == "internal" else 0; s += d; parts.append(_fmt("exposure_level", exposure, d))
        d = 10 if seg == "none" else 5 if seg == "isolated" else 0; s += d; parts.append(_fmt("network_segmentation", seg, d))
        d = 10 if fw_cfg == "allow_external_inbound" else 5 if fw_cfg == "block_external_allow_internal_only" else 0; s += d; parts.append(_fmt("firewall_configuration", fw_cfg, d))
        return _cap_0_100(s), parts

    # ---- compute scores
    vc_score, vc_parts = _score_vc()
    vi_score, vi_parts = _score_vi()
    va_score, va_parts = _score_va()

    sc_score, sc_parts = _score_sc()
    si_score, si_parts = _score_si()
    sa_score, sa_parts = _score_sa()

    safety_score, safety_parts = _score_safety()

    MVC = _bucket_vuln(vc_score)
    MVI = _bucket_vuln(vi_score)
    MVA = _bucket_vuln(va_score)

    MSC = _bucket_sub(sc_score)

    def _apply_safety(s_score: int, fallback: LevelSubC) -> LevelSubIA:
        return "S" if s_score >= 60 else fallback

    MSI = _apply_safety(safety_score, _bucket_sub(si_score))
    MSA = _apply_safety(safety_score, _bucket_sub(sa_score))

    # ----- rationale text
    def _explain_vuln(name: str, score: int, parts: List[str], val: str) -> str:
        label = {"H": "High (H)", "L": "Low (L)", "N": "None (N)"}[val]
        return f"Value: {val}\nRationale: {'; '.join(parts)} → score={score} → {label}."

    def _explain_sub_c(name: str, score: int, parts: List[str], val: str) -> str:
        label = {"H": "High (H)", "L": "Low (L)", "N": "Negligible (N)"}[val]
        return f"Value: {val}\nRationale: {'; '.join(parts)} → score={score} → {label}."

    def _explain_sub_ia(name: str, base_score: int, base_parts: List[str], val: str) -> str:
        if val == "S":
            return f"Value: S\nRationale: Safety conditions triggered — {'; '.join(safety_parts)} → safety_score={safety_score} ≥ 60 → Safety (S)."
        label = {"H": "High (H)", "L": "Low (L)", "N": "Negligible (N)"}[val]
        return f"Value: {val}\nRationale: {'; '.join(base_parts)} → score={base_score} → {label}."

    rationale = {
        "MVC": _explain_vuln("MVC", vc_score, vc_parts, MVC),
        "MVI": _explain_vuln("MVI", vi_score, vi_parts, MVI),
        "MVA": _explain_vuln("MVA", va_score, va_parts, MVA),
        "MSC": _explain_sub_c("MSC", sc_score, sc_parts, MSC),
        "MSI": _explain_sub_ia("MSI", si_score, si_parts, MSI),
        "MSA": _explain_sub_ia("MSA", sa_score, sa_parts, MSA),
    }

    metrics = {"MVC": MVC, "MVI": MVI, "MVA": MVA, "MSC": MSC, "MSI": MSI, "MSA": MSA}

    # Confidence: % of key fields filled (simple heuristic)
    expected = [
        "security_requirements_confidentiality","security_requirements_integrity","security_requirements_availability",
        "asset_criticality","data_sensitivity","encryption_protection_level","availability_redundancy",
        "asset_dependency_level","connected_systems_criticality","network_connectivity",
        "cascading_impact_potential","connection_security_controls",
        "exposure_level","network_segmentation","firewall_configuration","vpn_access","ssh_remote_access",
        "security_controls_waf","security_controls_firewall","security_controls_ids","security_controls_ips","security_controls_edr",
    ]
    filled = sum(1 for f in expected if getattr(asset, f, "") not in ("", None))
    cov = filled / len(expected)
    confidence = "High" if cov >= 0.8 else "Medium" if cov >= 0.5 else "Low"

    return {
        "metrics": metrics,
        "rationale": rationale,
        "confidence": confidence,
    }
