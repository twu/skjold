import os
import tempfile
from typing import Generator

import pytest


@pytest.fixture(scope="session")
def cache_dir() -> Generator[str, None, None]:
    if os.environ.get("SKJOLD_TESTS_USE_STATIC_CACHE"):
        yield str(os.path.join(os.path.dirname(__file__), "..", "cache"))
    else:
        with tempfile.TemporaryDirectory(prefix="skjold_") as cache:
            assert os.path.exists(cache)
            yield cache
