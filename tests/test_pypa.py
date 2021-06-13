from skjold.sources.pypa import PyPAAdvisoryDB


def test_ensure_pypi_advisory_db_update(cache_dir: str) -> None:
    source = PyPAAdvisoryDB(cache_dir, 3600)
    assert source.name == "pypa"
    assert len(source._advisories) == 0

    _ = source.advisories
    assert len(source._advisories) > 0
    assert source.total_count > 100

    assert source.has_security_advisory_for("ansible")

    found, findings = source.is_vulnerable_package("doesnotexist", "1.0.0")
    assert found is False and len(findings) == 0

    found, findings = source.is_vulnerable_package("ansible", "2.8.1")
    assert found and len(findings) > 0

    found, findings = source.is_vulnerable_package("ansible", "2.8.3")
    assert found and len(findings) > 0

    found, findings = source.is_vulnerable_package("ansible", "4.1.0")
    assert found is False and len(findings) == 0
