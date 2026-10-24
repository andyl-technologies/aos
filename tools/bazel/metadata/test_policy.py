"""Translates the current nextest scheduling oracle into a Cargo-free policy.

Only the filter/settings forms in the checked-in oracle are accepted. A new
form fails the update/check until its semantics have been implemented.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib


def duration(value):
    """Converts the oracle's explicit seconds/minutes into a fixed duration."""
    match = re.fullmatch(r"([1-9][0-9]*)(s|m)", value)
    if not match:
        raise ValueError(f"unsupported nextest duration: {value}")
    return int(match[1]) * (60 if match[2] == "m" else 1)


def conditions(expression):
    """Translates conjunctions of the supported package/test matchers."""
    result = []
    for term in expression.split("&"):
        match = re.fullmatch(r"(package|test)\((.+)\)", term.strip())
        if not match:
            raise ValueError(f"unsupported nextest filter: {expression}")
        kind, pattern = match.groups()
        if not pattern.startswith("/") and any(character in pattern for character in "()|\"'"):
            raise ValueError(f"unsupported nextest matcher: {pattern}")
        if kind == "package":
            if pattern.startswith(("/", "=", "~")):
                raise ValueError("package matcher requires explicit implementation")
            result.append({"package_substring": pattern})
        elif pattern.startswith("/") and pattern.endswith("/"):
            re.compile(pattern[1:-1])
            result.append({"regex": pattern[1:-1]})
        elif pattern.startswith(("=", "~")):
            raise ValueError("test matcher requires explicit implementation")
        else:
            result.append({"substring": pattern})
    return result


def timeout(value):
    """Preserves the current slow-timeout period and termination count."""
    if set(value) - {"period", "terminate-after", "grace-period"} or not {"period", "terminate-after"} <= set(value):
        raise ValueError("unsupported nextest timeout settings")
    return duration(value["period"]) * value["terminate-after"]


def translate(path):
    """Rejects scheduling drift while producing the declared runtime policy."""
    source = path.read_bytes()
    profiles = tomllib.loads(source.decode())["profile"]
    default = profiles["default"]
    for name, profile in profiles.items():
        if name == "default":
            continue
        if (set(profile) - {"inherits", "fail-fast", "junit"}
                or profile.get("inherits") != "default" or profile.get("fail-fast", False)):
            raise ValueError(f"unsupported scheduling override in nextest profile {name}")
    presentation = {"fail-fast", "failure-output", "success-output", "status-level", "final-status-level", "slow-timeout", "overrides"}
    if set(default) - presentation or default["fail-fast"]:
        raise ValueError("unsupported default nextest scheduling settings")
    overrides = []
    for value in default.get("overrides", []):
        if set(value) - {"filter", "slow-timeout", "threads-required"}:
            raise ValueError("unsupported nextest override settings")
        override = {"conditions": conditions(value["filter"])}
        if "slow-timeout" in value:
            override["timeout_seconds"] = timeout(value["slow-timeout"])
            override["slow_period_seconds"] = duration(value["slow-timeout"]["period"])
            override["termination_grace_seconds"] = duration(value["slow-timeout"].get("grace-period", "10s"))
        if "threads-required" in value:
            if value["threads-required"] != "num-test-threads":
                raise ValueError("unsupported nextest thread reservation")
            override["exclusive"] = True
        overrides.append(override)
    return {
        "schema_version": 1,
        "oracle_sha256": hashlib.sha256(source).hexdigest(),
        "default_timeout_seconds": timeout(default["slow-timeout"]),
        "default_slow_period_seconds": duration(default["slow-timeout"]["period"]),
        # https://nexte.st/docs/features/slow-tests/ defines the default grace.
        "default_termination_grace_seconds": duration(default["slow-timeout"].get("grace-period", "10s")),
        "default_leak_grace_seconds": 0.1,
        "overrides": overrides,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args()
    text = json.dumps(translate(options.oracle), indent=2, sort_keys=True) + "\n"
    if options.check:
        if options.output.read_text() != text:
            raise SystemExit("Bazel test policy differs from the nextest scheduling oracle")
    else:
        options.output.write_text(text)


if __name__ == "__main__":
    main()
