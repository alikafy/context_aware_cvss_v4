import os
from time import sleep
from unittest import TestCase
from unittest.mock import patch
from rule_base import score_environmental
from context_aware_v4 import EnvironmentalMetricCalculater
from answers import example_agent_answer

class CalculaterTest(TestCase):

    @patch('context_aware_v4.EnvironmentalMetricCalculater.agent_answer' ,return_value=example_agent_answer)
    @patch('context_aware_v4.EnvironmentalMetricCalculater.get_vuln_systems' ,return_value=['Wyn Enterprise'])
    @patch('context_aware_v4.EnvironmentalMetricCalculater.match_affected_assets' ,return_value=[1])
    def test_get_cve(self,c,d,s):
        # cve_id = 'CVE-2024-9150'
        # cve_id = 'CVE-2024-51547'
        cve_id = 'CVE-2025-0674'
        environmental = EnvironmentalMetricCalculater(cve_id, 'd')
        log_path='./context.log'
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        vuln = environmental.get_vuln_systems()
        assets = environmental.search_vuln_systems_in_assets(vuln)
        assets_id = environmental.match_affected_assets(assets)
        impacted_assets = environmental.get_impacted_assets(assets_id, assets)
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"agent vuln detect output: {vuln}\n")
            for asset in impacted_assets:
                resp = environmental.agent_answer(asset)
                f.write(f"agent main query output: {resp}\n")
                all_metrics = environmental.prepare_agent_answer_for_calculator(resp, asset)
                e_agent = environmental.calculate_environmental_metric(all_metrics)
                f.write(f"agent e metric: {e_agent}\n")
                
                rule_base = score_environmental(asset, include_subsequent_impacts=True)
                f.write(f"rule base e metric: {rule_base}\n")
                metrics_rule_base = environmental.prepare_rule_base_for_calculator(rule_base, asset)
                f.write(f"rule base  e metric: {metrics_rule_base}\n")
                e_rule = environmental.calculate_environmental_metric(metrics_rule_base)
                f.write(f"rule e metric: {e_rule}\n")
                
                rule_base = environmental.calculate_rule_base(asset)
                f.write(f"rule base e metric 2: {rule_base}\n")
                e_rule = environmental.calculate_environmental_metric(rule_base)
                f.write(f"rule e metric 2: {e_rule}\n")
                
                sleep(1)
        assert True
