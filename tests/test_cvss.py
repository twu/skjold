import pytest

from skjold.cvss import CVSS2, CVSS3, parse_cvss


@pytest.mark.parametrize(
    "vector, impact_score, exploitability_score, base_score",
    [
        ("AV:N/AC:L/Au:N/C:N/I:N/A:C", 6.9, 10.0, 7.8),
        ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0, 10.0, 10.0),
        ("AV:L/AC:H/Au:N/C:C/I:C/A:C", 10.0, 1.9, 6.2),
    ],
    ids=["CVE-2002-0392", "CVE-2003-0818", "CVE-2003-0062"],
)
def test_base_score_calculation_cvss2(
    vector: str, impact_score: float, exploitability_score: float, base_score: float
) -> None:
    obj = CVSS2.using(vector)
    assert round(obj.exploitability_score, 1) == exploitability_score
    assert round(obj.impact_score, 1) == impact_score
    assert obj.score == base_score


@pytest.mark.parametrize(
    "vector, score, severity, scope",
    [
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE", "U"),
        ("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "LOW", "U"),
        ("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N", 1.9, "LOW", "C"),
        ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 2.4, "LOW", "U"),
        ("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.9, "LOW", "U"),
        ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N", 4.0, "MEDIUM", "C"),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N", 4.1, "MEDIUM", "C"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "MEDIUM", "U"),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L", 5.0, "MEDIUM", "C"),
        ("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 6.1, "MEDIUM", "U"),
        ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N", 6.9, "MEDIUM", "C"),
        ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L", 7.0, "HIGH", "U"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH", "U"),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 9.0, "CRITICAL", "C"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL", "U"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL", "C"),
        ("AV:L/AC:H/Au:M/C:N/I:N/A:N", 0.0, "NONE", None),
        ("AV:A/AC:H/Au:N/C:N/I:N/A:N", 0.0, "NONE", None),
        ("AV:L/AC:H/Au:M/C:P/I:P/A:N", 2.3, "LOW", None),
        ("AV:L/AC:H/Au:S/C:N/I:N/A:C", 3.8, "LOW", None),
        ("AV:N/AC:L/Au:S/C:N/I:N/A:P", 4.0, "MEDIUM", None),
        ("AV:L/AC:H/Au:N/C:C/I:C/A:C", 6.2, "MEDIUM", None),
        ("AV:A/AC:M/Au:M/C:C/I:C/A:C", 7.0, "HIGH", None),
        ("AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8, "HIGH", None),
        ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0, "HIGH", None),
    ],
)
def test_correct_cvss_score_and_severity_from_vector(
    vector: str, score: float, severity: str, scope: str
) -> None:

    cvss = parse_cvss(vector)
    if isinstance(cvss, CVSS3):
        assert cvss.scope == scope

    assert cvss.score == score
    assert cvss.severity == severity
