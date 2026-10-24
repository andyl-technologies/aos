"""Selects a connected editor family while retaining Cargo workspace policy."""

import json
import re
import tomllib


def select_workspace(source, members, dependencies):
    """Retains existing exclusions and changes only selected membership fields."""
    original = tomllib.loads(source)
    existing = original["workspace"].get("exclude", [])
    excluded = sorted(set(existing) | set(dependencies))
    if set(members) & set(excluded):
        raise ValueError("selected Cargo editor members overlap excluded packages")

    updated, count = re.subn(
        r"(?m)^members = \[[\s\S]*?^\]", "members = " + json.dumps(members), source,
    )
    if count != 1:
        raise ValueError("Cargo editor oracle workspace selection no longer applies")
    expected = {**original, "workspace": {**original["workspace"], "members": members}}
    if excluded:
        declaration = "exclude = " + json.dumps(excluded)
        if "exclude" in original["workspace"]:
            updated, count = re.subn(r"(?m)^exclude\s*=\s*\[[^\]]*\]", declaration, updated)
        else:
            updated, count = re.subn(r"(?m)^\[workspace\]$", "[workspace]\n" + declaration, updated)
        if count != 1:
            raise ValueError("Cargo editor workspace exclusion declaration requires review")
        expected["workspace"]["exclude"] = excluded
    if tomllib.loads(updated) != expected:
        raise ValueError("Cargo editor selection changed unrelated workspace metadata")
    return updated
