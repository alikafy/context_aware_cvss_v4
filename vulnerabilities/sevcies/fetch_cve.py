import requests

from vulnerabilities.exceptions import FetchCVEAPIError, CWEFetchError
from bs4 import BeautifulSoup


class FetchCVEService:
    def __init__(self, cve_id: str):
        self.cve_id = cve_id

    def get_cve_record_nvd(self, api_key: str | None = None, timeout: float = 10.0) -> dict:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": api_key} if api_key else {}
        params = {"cveId": self.cve_id}
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("vulnerabilities"):
            raise FetchCVEAPIError(f"{self.cve_id} not found in NVD.")
        return data["vulnerabilities"][0]["cve"]

    def fetch_cve(self):
        response = self.get_cve_record_nvd()
        return dict(
            cve_id=self.cve_id,
            cve_description=response['descriptions'][0]['value'],
            cve_status=response['vulnStatus'],
            weaknesses=self.fetch_weaknesses(response['weaknesses']),
            cve_response=response,
            base_score=float(response['metrics']['cvssMetricV40'][0]['cvssData']['baseScore']),
            base_vector=response['metrics']['cvssMetricV40'][0]['cvssData'],
        )

    def fetch_weaknesses(self, weaknesses: list):
        cwes = []
        for weakness in weaknesses:
            description = self.get_cwe_description(weakness['description'][0]['value'])
            cwes.append(dict(id=weakness['description'][0]['value'], description=description))
        return cwes

    def get_cwe_description(self, cwe_id):
        """
        Fetch the CWE description for a given CWE ID from the MITRE API.
        Example: cwe_id = 'CWE-79'
        """
        url = f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html"

        try:
            response = requests.get(url)
            response.raise_for_status()

            # Extract description from the HTML response
            soup = BeautifulSoup(response.text, 'html.parser')

            # The description is typically in a <div class="detail"> element
            desc_div = soup.find("div", {"id": "Description"})
            if desc_div:
                description = desc_div.text.strip()
                if description.startswith('Description'):
                    description = description.replace("Description", '', 1)
                return description.strip()
            else:
                return CWEFetchError('there is no description')

        except requests.exceptions.RequestException as e:
            raise CWEFetchError(e)
