import re

import requests
from bs4 import BeautifulSoup
from cvss import CVSS4

from vulnerabilities.type import metrics_abbreviation, BaseMetric, AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA, \
    NOT_DEFINED


def calculate_environmental_metric(all_metrics):
    vector = "CVSS:4.0/" + "/".join(f"{k}:{v}" for k, v in all_metrics.items())
    cvss = CVSS4(vector)
    scores = cvss.scores()
    severity = cvss.severity
    return scores[0], severity

def convert_to_abbreviations(value: str):
    changed_value = value.upper()
    if len(changed_value) == 1:
        return changed_value
    changed_value = re.sub(r"\s*\([^)]*\)", "", changed_value).strip()
    return metrics_abbreviation[changed_value]

def fetch_metrics(metrics_data) -> BaseMetric:
    return BaseMetric(
        AV=fetch_cvss_metric(AV(value=metrics_data['attackVector'])),
        AC=fetch_cvss_metric(AC(value=metrics_data['attackComplexity'])),
        AT=fetch_cvss_metric(AT(value=metrics_data['attackRequirements'])),
        PR=fetch_cvss_metric(PR(value=metrics_data['privilegesRequired'])),
        UI=fetch_cvss_metric(UI(value=metrics_data['userInteraction'])),
        VC=fetch_cvss_metric(VC(value=metrics_data['vulnConfidentialityImpact'])),
        VI=fetch_cvss_metric(VI(value=metrics_data['vulnIntegrityImpact'])),
        VA=fetch_cvss_metric(VA(value=metrics_data['vulnAvailabilityImpact'])),
        SC=fetch_cvss_metric(SC(value=metrics_data['subConfidentialityImpact'])),
        SI=fetch_cvss_metric(SI(value=metrics_data['subIntegrityImpact'])),
        SA=fetch_cvss_metric(SA(value=metrics_data['subAvailabilityImpact'])),
    )

def fetch_cvss_metric(metric_obj):
    """
    Fetches the description and values of a CVSS v4.0 metric (e.g., 'AV')
    from the FIRST CVSS v4.0 specification document.
    """
    metric = metric_obj.metric_symbol
    url = "https://www.first.org/cvss/v4-0/specification-document"
    response = requests.get(url)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")

    # Find the metric section by looking for <h4> or <h3> tags containing the metric
    metric_header = soup.find(lambda tag: tag.name in ["h3", "h4"] and metric in tag.text)
    if not metric_header:
        raise ValueError(f"Metric '{metric}' not found.")

    # The description is usually in the next <p> (paragraph)
    description_tag = metric_header.find_next("p")
    description = description_tag.text.strip() if description_tag else "Description not found."

    # The values are usually in the next <table> (if available)
    values_table = metric_header.find_next("table")
    values = {}
    if values_table:
        rows = values_table.find_all("tr")[1:]  # skip header row
        for row in rows:
            cols = [col.get_text(strip=True) for col in row.find_all("td")]
            if len(cols) >= 2:
                values[cols[0]] = cols[1]
    values.update(NOT_DEFINED)
    metric_obj.description = description
    metric_obj.values_description = values
    return metric_obj

def score_to_severity(score):
    """Helper: Convert numeric CVSS score to qualitative severity."""
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "None"
