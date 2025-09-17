import json
from typing import List

from assets.models import Asset
from vulnerabilities.models import Vulnerability
from vulnerabilities.sevcies.ask_agent import make_request


class Scan:
    def __init__(self, vuln: Vulnerability, model_name: str = None):
        self.vuln = vuln
        self.model_name = model_name

    def scan(self) -> List[Asset]:
        vul_systems_name = self.get_vuln_systems()
        possible_impacted_assets = self.search_vuln_systems_in_assets(list(set(vul_systems_name)))
        if not possible_impacted_assets:
            return []
        impacted_ids = self.match_affected_assets(possible_impacted_assets).get('impacted_asset_ids', [])
        assets = self.get_impacted_assets(impacted_ids, possible_impacted_assets)
        return assets

    def get_vuln_systems(self):
        prompt = f"""
                You are an assistant helping identify vulnerable systems from CVE descriptions.
                From the following CVE description, extract the names of **vulnerable products or systems only**, ignoring versions or fixes. Only include **proper nouns** or identifiable software/hardware names that are explicitly or implicitly affected.
                - Do not include general terms like "system", "firmware", or "application" unless they are brand-specific (e.g., "Intel Firmware").
                - Respond as a **JSON array of strings**, each being the name of a vulnerable product or system.
                CVE description:
                {self.vuln.cve_description}           
        """
        return make_request(prompt, model=self.model_name)

    def search_vuln_systems_in_assets(self, vuln_systems: list) -> List[Asset]:
        impacted_assets = []
        for system in vuln_systems:
            assets = list(Asset.objects.filter(is_active=True, name__icontains=system))
            impacted_assets.extend(assets)
        return impacted_assets

    def format_assets_as_json(self, user_assets: list[Asset]):
        asset_list = [
            {"id": asset.id, "name": asset.name, "version": asset.version}
            for asset in user_assets
        ]
        return json.dumps(asset_list, indent=2)

    def match_affected_assets(self, user_assets: list[Asset]) -> dict:
        prompt = f"""
ROLE: You are a specialized vulnerability intelligence engine. Your sole function is to identify which assets from a provided list are affected by a given CVE description by performing precise name and version range matching.
TASK: Analyze the provided CVE Description and User Assets. Based on the critical rules, determine which assets are impacted and return their IDs in a structured JSON format.

INPUTS:
You will be provided with two pieces of information:

CVE Description: {self.vuln.cve_description}

User Assets: 
{self.format_assets_as_json(user_assets)}

CRITICAL RULES:

Parse CVE First: Meticulously parse the 'CVE Description' to identify the vulnerable product name(s) and all specified version ranges. A single CVE can have multiple distinct ranges (e.g., 'versions before X' and 'versions from Y to Z').

Name Matching: For each asset, perform a case-insensitive match. The asset's name must contain the core product name identified from the CVE (e.g., "Concrete CMS" in the asset name matches the product "Concrete CMS").

Version Range Analysis: If the name matches, you must check if the asset's version falls within any of the vulnerable ranges identified in the CVE.

"versions 9 through 9.3.2" means version >= 9.0.0 AND version <= 9.3.2.

"versions below 8.5.18" means version < 8.5.18.

"versions prior to 9.2" means version < 9.2.

Treat versions lexicographically if needed, but numeric comparison is preferred (e.g., 9.1.1 is less than 9.2).

Strict Adherence: Adhere strictly to the provided text. Do not infer vulnerabilities for products not mentioned or versions outside the specified ranges.

OUTPUT FORMAT:
Respond with a single, clean JSON object. This object must contain one key, "impacted_asset_ids", which is a JSON array of integers representing the matching asset IDs. If no assets are impacted, the array must be empty. Do not include any other text, explanations, or markdown formatting in your response.
                    """.strip()
        return make_request(prompt, model=self.model_name)

    def get_impacted_assets(self, assets_id: List[int], user_assets: List[Asset]) -> List[Asset]:
        impacted_assets = []
        for asset in user_assets:
            if asset.id in assets_id:
                impacted_assets.append(asset)
        return impacted_assets
