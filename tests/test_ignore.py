import datetime
import os
from typing import Dict

import pytest

from skjold.ignore import SkjoldIgnore


@pytest.fixture
def ignorelist() -> SkjoldIgnore:
    path = os.path.join(
        os.path.dirname(__file__), "fixtures", "formats", "ignore", "example"
    )
    assert os.path.exists(path)

    obj = SkjoldIgnore.using(path)
    assert obj.version == "1.0"
    assert len(obj.entries) > 0
    return obj


@pytest.mark.parametrize(
    "identifier, package",
    [
        ("CVE-2019-11236", "urllib3"),
        ("CVE-2019-11324", "urllib3"),
        ("CVE-2020-26137", "urllib3"),
        ("PYSEC-2020-149", "urllib3"),
    ],
)
def test_should_ignore_not_expired(
    identifier: str, package: str, ignorelist: SkjoldIgnore
) -> None:
    """Ensure we only ignore if package and identifier are matching."""

    ignored, _ = ignorelist.should_ignore(identifier, package)
    assert ignored

    ignored, _ = ignorelist.should_ignore(identifier, "requests")
    assert not ignored


@pytest.mark.parametrize(
    "identifier, package, entry",
    [
        (
            "CVE-2018-20060",
            "urllib3",
            {
                "expires": "2021-01-01T00:00:00+0000",
                "package": "urllib3",
                "reason": "No remidiation available.",
            },
        ),
    ],
)
def test_should_ignore_expired(
    identifier: str, package: str, entry: Dict[str, str], ignorelist: SkjoldIgnore
) -> None:
    """Ensure we only ignore if package and identifier are matching."""

    ignored, entry = ignorelist.should_ignore(identifier, package)
    assert not ignored
    assert entry == entry


def test_ignore_add_item(ignorelist: SkjoldIgnore) -> None:
    ignored, entry = ignorelist.should_ignore("SKJ-0000-00", "example")
    assert not ignored
    assert entry == {}

    expires = datetime.datetime.utcnow() + datetime.timedelta(days=14)
    expires = expires.replace(tzinfo=datetime.timezone.utc)

    assert ignorelist.add("SKJ-0000-00", "example", expires=expires)

    ignored, entry = ignorelist.should_ignore("SKJ-0000-00", "example")
    assert ignored
    assert entry == {
        "package": "example",
        "reason": "No immediate remidiation.",
        "expires": expires.strftime(SkjoldIgnore.EXPIRES_FMT),
    }
