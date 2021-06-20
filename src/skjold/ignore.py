import datetime
import os
from typing import Dict, Tuple

import yaml


class SkjoldIgnore:
    _doc: Dict
    _path: str

    EXPIRES_FMT = "%Y-%m-%dT%H:%M:%S%z"
    DEFAULT_EXPIRES = datetime.datetime.now() + datetime.timedelta(days=7)
    DEFAULT_REASON = "No immediate remediation."

    def __init__(self, path: str):
        self._path = path
        self._doc = {"version": "1.0", "ignore": {}}

    @classmethod
    def using(cls, path: str) -> "SkjoldIgnore":
        obj = SkjoldIgnore(path)
        if not os.path.exists(path):
            return obj

        with open(path) as fh:
            obj._doc = yaml.safe_load(fh)
        return obj

    @property
    def version(self) -> str:
        return str(self._doc["version"])

    @property
    def entries(self) -> Dict:
        entries = self._doc["ignore"]
        return dict(entries)

    def add(
        self,
        identifier: str,
        package_name: str,
        reason: str,
        expires: datetime.datetime = datetime.datetime.now()
        + datetime.timedelta(days=14),
    ) -> bool:

        expires = expires.replace(tzinfo=datetime.timezone.utc)

        if identifier not in self.entries:
            self._doc["ignore"][identifier] = []

        self._doc["ignore"][identifier].append(
            {
                "package": package_name,
                "reason": reason,
                "expires": expires.strftime(SkjoldIgnore.EXPIRES_FMT),
            }
        )
        return True

    def save(self) -> None:
        with open(self._path, "w") as fh:
            yaml.safe_dump(self._doc, fh)

    def should_ignore(self, identifier: str, package_name: str) -> Tuple[bool, Dict]:
        """Returns True a given identifier has an entry in the blacklist."""
        if identifier not in self.entries:
            return False, {}

        for entry in self.entries.get(identifier, {}):
            if entry["package"] == package_name:
                dt = datetime.datetime.strptime(
                    f"{entry['expires']}", SkjoldIgnore.EXPIRES_FMT
                )
                return datetime.datetime.now(tz=dt.tzinfo) < dt, entry

        return False, {}
