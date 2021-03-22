import math
from typing import Dict, Any, Union


def round_up(n: float, decimals: int = 1) -> float:
    multiplier = 10 ** decimals
    return float(math.ceil(n * multiplier) / multiplier)


class CVSS2:

    _basic: Dict[str, str] = {}
    _fields_basic_group = frozenset({"AV", "AC", "Au", "C", "I", "A"})
    _metrics: Dict[str, Any] = {
        "AV": {"N": 1.0, "A": 0.646, "L": 0.395},
        "AC": {"L": 0.71, "M": 0.61, "H": 0.35},
        "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
        "C": {"N": 0.0, "P": 0.275, "C": 0.660},
        "I": {"N": 0.0, "P": 0.275, "C": 0.660},
        "A": {"N": 0.0, "P": 0.275, "C": 0.660},
    }

    @classmethod
    def using(cls, vector: str) -> "CVSS2":
        kv = map(lambda v: v.split(":"), vector.strip().split("/"))
        basic_group = filter(lambda metric: metric[0] in CVSS2._fields_basic_group, kv)

        obj = CVSS2()
        obj._basic = {v[0]: v[1] for v in basic_group}
        return obj

    @property
    def _impact_subscore(self) -> float:
        confidentiality = self._basic["C"]
        integrity = self._basic["I"]
        availability = self._basic["A"]
        return 1 - (
            (1 - float(self._metrics["C"][confidentiality]))
            * (1 - float(self._metrics["I"][integrity]))
            * (1 - float(self._metrics["A"][availability]))
        )

    @property
    def exploitability_score(self) -> float:
        """Calculate the exploitability score."""
        av = float(self._metrics["AV"][self._basic["AV"]])
        ac = float(self._metrics["AC"][self._basic["AC"]])
        au = float(self._metrics["Au"][self._basic["Au"]])
        return 20.0 * av * ac * au

    @property
    def impact_score(self) -> float:
        """Calculate the impact score."""
        return 10.41 * self._impact_subscore

    @property
    def score(self) -> float:
        """Return the CVSS 2.0 base score."""
        if self.impact_score <= 0:
            return 0.0

        return round(
            1.176
            * ((0.6 * self.impact_score) + (0.4 * self.exploitability_score) - 1.5),
            1,
        )

    @property
    def severity(self) -> str:
        """Return severity level for based on the CVSS 2.0 base score."""
        x = self.score
        if x < 0.001:
            return "NONE"
        elif x < 4:
            return "LOW"
        elif x < 7:
            return "MEDIUM"
        else:
            return "HIGH"


class CVSS3:

    _basic: Dict[str, str] = {}
    _fields_basic_group = frozenset({"AV", "AC", "PR", "UI", "S", "C", "I", "A"})
    _metrics: Dict[str, Any] = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {
            "C": {"N": 0.85, "L": 0.68, "H": 0.50},
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        },
        "UI": {"N": 0.85, "R": 0.62},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }

    @classmethod
    def using(cls, vector: str) -> "CVSS3":
        kv = map(lambda v: v.split(":"), vector.strip().upper().split("/"))
        basic_group = filter(lambda metric: metric[0] in cls._fields_basic_group, kv)

        obj = CVSS3()
        obj._basic = {v[0]: v[1] for v in basic_group}
        return obj

    @property
    def scope(self) -> str:
        return self._basic["S"]

    @property
    def _impact_subscore(self) -> float:
        confidentiality = self._basic["C"]
        integrity = self._basic["I"]
        availability = self._basic["A"]
        return 1 - (
            (1 - float(self._metrics["C"][confidentiality]))
            * (1 - float(self._metrics["I"][integrity]))
            * (1 - float(self._metrics["A"][availability]))
        )

    @property
    def exploitability_score(self) -> float:
        """Calculate the exploitability score."""
        av = float(self._metrics["AV"][self._basic["AV"]])
        ac = float(self._metrics["AC"][self._basic["AC"]])
        pr = float(self._metrics["PR"][self._basic["S"]][self._basic["PR"]])
        ui = float(self._metrics["UI"][self._basic["UI"]])

        return 8.22 * av * ac * pr * ui

    @property
    def impact_score(self) -> float:
        """Calculate the impact score."""
        impact_subscore = self._impact_subscore
        if self.scope == "U":
            return 6.42 * impact_subscore

        return 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15

    @property
    def score(self) -> float:
        """Return the CVSS 3.0 base score."""
        if self.impact_score <= 0:
            return 0.0

        if self.scope == "U":
            return round_up(min((self.impact_score + self.exploitability_score), 10.0))

        return round_up(
            min(1.08 * (self.impact_score + self.exploitability_score), 10.0)
        )

    @property
    def severity(self) -> str:
        """Return severity level for based on the CVSS 3.0 base score."""
        x = self.score
        if x < 0.001:
            return "NONE"
        elif x < 4.0:
            return "LOW"
        elif x < 7.0:
            return "MEDIUM"
        elif x < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"


def parse_cvss(vector: str) -> Union[CVSS2, CVSS3]:
    if vector.startswith("CVSS:3"):
        return CVSS3.using(vector)
    return CVSS2.using(vector)
