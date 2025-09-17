import json

import requests

from vulnerabilities.exceptions import FetchCVEAPIError, CWEFetchError
from bs4 import BeautifulSoup

from vulnerabilities.models import APICallLog


class FetchCVEService:
    def __init__(self, cve_id: str):
        self.cve_id = cve_id

    def get_cve_record_nvd(self, api_key: str | None = None, timeout: float = 10.0) -> dict:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": api_key} if api_key else {}
        params = {"cveId": self.cve_id}
        log = APICallLog.objects.create(
            endpoint=url,
            method="GET",
            request_headers=headers,
            request_body=json.dumps(params),
        )
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
            log.response_status = resp.status_code
            log.response_headers = dict(resp.headers)
            log.response_body = resp.text
            resp.raise_for_status()
            data = resp.json()
            if not data.get("vulnerabilities"):
                log.error_message = f"{self.cve_id} not found in NVD."
                log.save()
                raise FetchCVEAPIError(f"{self.cve_id} not found in NVD.")
            log.save()
            return data["vulnerabilities"][0]["cve"]
        except Exception as e:
            log.error_message = str(e)
            log.save()
            raise

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
            try:
                description = self.get_cwe_description(weakness['description'][0]['value'])
                cwes.append(dict(id=weakness['description'][0]['value'], description=description))
            except Exception:
                pass
        return cwes

    def get_cwe_description(self, cwe_id):
        try:
            # Normalize & build URL like https://cwe.mitre.org/data/definitions/310.html
            if isinstance(cwe_id, str) and cwe_id.upper().startswith("CWE-"):
                numeric = cwe_id.split("-", 1)[1].strip()
            else:
                numeric = str(cwe_id).strip()
            url = f"https://cwe.mitre.org/data/definitions/{numeric}.html"

            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; CWEFetcher/1.0)"
            }
            response = requests.get(url, headers=headers, timeout=20)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")

            # Try Description first
            desc_div = soup.find("div", {"id": "Description"})
            summary_div = soup.find("div", {"id": "Summary"})

            def clean_text(node, heading_word):
                # Get text with sensible spacing and strip the section label if present
                text = node.get_text(separator=" ", strip=True)
                # Some pages include the heading word at the start (e.g., "Description")
                if text.startswith(heading_word):
                    text = text[len(heading_word):].strip(" :\u00a0")
                return text

            if desc_div:
                description = clean_text(desc_div, "Description")
                if description:
                    return description

            # Fallback to Summary if Description missing or empty
            if summary_div:
                summary = clean_text(summary_div, "Summary")
                if summary:
                    return summary

            # Nothing useful found
            return ""

        except requests.exceptions.RequestException as e:
            raise CWEFetchError(e)