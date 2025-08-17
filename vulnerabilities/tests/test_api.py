from platform import version

from model_bakery import baker
from rest_framework.test import APITestCase

from assets.models import Asset
from vulnerabilities.models import Vulnerability


class APITest(APITestCase):
    def setUp(self):
        pass

    def test_fetch_cve(self):
        cve_id = "CVE-2025-0674"
        url = f"/api/vuln/fetch-cve/{cve_id}/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        obj = Vulnerability.objects.filter(cve_id=cve_id)
        assert obj.exists()

    def test_scan(self):
        baker.make(
            Asset,
            name="Elber",
            version='5.9.0',
            is_active=True
        )
        cve_id = "CVE-2025-0674"
        url = f"/api/vuln/fetch-cve/{cve_id}/"
        self.client.get(url)
        vuln = Vulnerability.objects.get(cve_id=cve_id)
        url = f"/api/vuln/scan/{vuln.id}/"
        data = {
            'agent_model': 'gpt-4o'
        }
        response = self.client.post(url, data, 'json')
        self.assertEqual(response.status_code, 200)

    def test_calculate(self):
        asset = baker.make(
            Asset,
            name="Elber",
            version='5.9.0',
            is_active=True,
            security_requirements_confidentiality='high',
            security_requirements_integrity='high',
            security_requirements_availability='high',
        )
        cve_id = "CVE-2025-0674"
        url = f"/api/vuln/fetch-cve/{cve_id}/"
        self.client.get(url)
        vuln = Vulnerability.objects.get(cve_id=cve_id)
        vuln.impacted_assets.add(asset)
        url = f"/api/vuln/calculate/{vuln.id}/"
        data = {
            'agent_model': 'gpt-4o'
        }
        response = self.client.post(url, data, 'json')
        self.assertEqual(response.status_code, 200)
