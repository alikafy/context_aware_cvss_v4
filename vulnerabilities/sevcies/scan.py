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
        possible_impacted_assets = self.search_vuln_systems_in_assets(vul_systems_name)
        impacted_ids = self.match_affected_assets(possible_impacted_assets)
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

    def match_affected_assets(self, user_assets: list[Asset]) -> list[int]:
        assets_str = "\n".join(
            f"- ID: {asset.id}, asset name: {asset.name}, asset version: {asset.version}" for asset in user_assets)

        prompt = f"""
                You are an assistant helping assess the impact of a known vulnerability on a user's infrastructure using context-aware analysis.

                You are given:
                - A list of user assets (each asset has: ID, name, and version)
                - A CVE description (which may mention affected product names and versions)

                Your task is:
                1. Extract vulnerable product names and versions from the CVE description.
                2. Match them against the user's asset list:
                   - Use **case-insensitive matching**
                   - Allow **partial string matching** (e.g., "Apache HTTP Server" matches "Apache Web Server")
                   - Version match is preferred but not strictly required unless the CVE specifies a known affected version range.
                3. Consider assets impacted if their product name matches a vulnerable product, and their version is equal to or older than the affected version (if version data is given).
                4. Do not reason beyond the data — just match based on name and version.

                Respond with a **numbered list(use []) of only the matching asset IDs** that are likely impacted. If none match, return an empty list.mine return just a list of ID like [1, 2 ,3]

                User Assets:
                {assets_str}

                CVE Description:
                {self.vuln.cve_description}
                    """.strip()
        return make_request(prompt, model=self.model_name)

    def get_impacted_assets(self, assets_id: List[int], user_assets: List[Asset]) -> List[Asset]:
        impacted_assets = []
        for asset in user_assets:
            if asset.id in assets_id:
                impacted_assets.append(asset)
        return impacted_assets
