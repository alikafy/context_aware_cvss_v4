import dataclasses
from typing import Literal


@dataclasses.dataclass
class Metric:
    value: str
    metric_symbol: str = dataclasses.field(init=False)
    values_description: dict = None
    description: str = None

    def __hash__(self):
        return self.metric_symbol


@dataclasses.dataclass
class AV(Metric):
    value: Literal["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"]
    metric_symbol = 'AV'
    possible_values = ["NETWORK", "ADJACENT", "LOCAL", "PHYSICAL", "NOT_DEFINED"]

@dataclasses.dataclass
class AC(Metric):
    value: Literal["LOW", "HIGH"]
    metric_symbol = 'AC'
    possible_values = ["LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class AT(Metric):
    value: Literal["NONE", "PRESENT"]
    metric_symbol = 'AT'
    possible_values = ["NONE", "PRESENT", "NOT_DEFINED"]


@dataclasses.dataclass
class PR(Metric):
    value: Literal["NONE", "LOW", "HIGH"]
    metric_symbol = 'PR'
    possible_values = ["NONE", "LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class UI(Metric):
    value: Literal["NONE", "PASSIVE", "ACTIVE"]
    metric_symbol = 'UI'
    possible_values = ["NONE", "PASSIVE", "ACTIVE", "NOT_DEFINED"]


@dataclasses.dataclass
class VC(Metric):
    metric_symbol = 'VC'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class VI(Metric):
    metric_symbol = 'VI'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class VA(Metric):
    metric_symbol = 'VA'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class SC(Metric):
    metric_symbol = 'SC'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "NEGLIGIBLE", "HIGH", "NOT_DEFINED"]


@dataclasses.dataclass
class SI(Metric):
    metric_symbol = 'SI'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "NEGLIGIBLE", "HIGH", "SAFETY", "NOT_DEFINED"]


@dataclasses.dataclass
class SA(Metric):
    metric_symbol = 'SA'
    value: Literal["NONE", "LOW", "HIGH"]
    possible_values = ["NONE", "LOW", "NEGLIGIBLE", "HIGH", "SAFETY", "NOT_DEFINED"]


@dataclasses.dataclass
class BaseMetric:
    AV: AV
    AC: AC
    AT: AT
    PR: PR
    UI: UI
    VC: VC
    VI: VI
    VA: VA
    SC: SC
    SI: SI
    SA: SA

metrics_abbreviation={
    "NETWORK": "N",
    "ADJACENT": "A",
    "LOCAL": "L",
    "PHYSICAL": "P",
    "LOW": "L",
    "HIGH": "H",
    "NONE": "N",
    "PRESENT": "P",
    "PASSIVE": "P",
    "ACTIVE": "A",
    "NOT_DEFINED": "X",
    "NOT DEFINED": "X",
    "NEGLIGIBLE": "N",
    "SAFETY": "S",
}

NOT_DEFINED = {'Not Defined (X)': 'This is the default value. Assigning this value indicates there is insufficient information to choose one of the other values. This has the same effect as assigning High as the worst case.'}

