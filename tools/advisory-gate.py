#!/usr/bin/env python3
"""Validate pinned dependency advisory inputs and their dispositions."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class GateError(ValueError):
    """Reports an invalid or rejected advisory-gate input."""


@dataclass(frozen=True)
class Coordinate:
    """Identifies one exact component version."""

    name: str
    version: str

    @property
    def text(self) -> str:
        return f"{self.name}@{self.version}"


def load_json(path: Path) -> dict[str, Any]:
    """Loads a JSON object from ``path``.

    Raises:
        GateError: The file is not a JSON object.
    """

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"cannot read {path}: {error}") from error

    if not isinstance(value, dict):
        raise GateError(f"{path} must contain a JSON object")
    return value


def require_string(value: dict[str, Any], field: str, context: str) -> str:
    """Returns a required non-empty string field."""

    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise GateError(f"{context}.{field} must be a non-empty string")
    return item


def parse_date(value: str, context: str) -> dt.date:
    """Parses an ISO calendar date."""

    try:
        return dt.date.fromisoformat(value)
    except ValueError as error:
        raise GateError(f"{context} must be an ISO date: {value!r}") from error


def lock_packages(path: Path) -> set[Coordinate]:
    """Returns exact package coordinates from one Cargo lockfile."""

    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"cannot read Cargo lockfile {path}: {error}") from error

    packages = document.get("package")
    if not isinstance(packages, list):
        raise GateError(f"{path} has no package array")

    coordinates: set[Coordinate] = set()
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise GateError(f"{path} package {index} must be a table")
        coordinates.add(
            Coordinate(
                require_string(package, "name", f"{path} package {index}"),
                require_string(package, "version", f"{path} package {index}"),
            )
        )
    return coordinates


def nix_literal_version(repository: Path, component: dict[str, Any]) -> str:
    """Reads one deliberately selected version assignment from a Nix recipe."""

    relative_path = require_string(component, "path", "native component")
    field = require_string(component, "field", f"native component {relative_path}")
    source_path = repository / relative_path
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as error:
        raise GateError(f"cannot read {source_path}: {error}") from error

    pattern = re.compile(rf"^\s*{re.escape(field)}\s*=\s*\"([^\"]+)\";", re.MULTILINE)
    matches = pattern.findall(source)
    occurrence = component.get("occurrence", 1)
    if not isinstance(occurrence, int) or occurrence < 1:
        raise GateError(f"native component {relative_path}.occurrence must be positive")
    if len(matches) < occurrence:
        raise GateError(
            f"{source_path} has no {field!r} string assignment at occurrence {occurrence}"
        )
    return matches[occurrence - 1]


def native_coordinates(
    repository: Path,
    inventory: dict[str, Any],
    cargo_locks: dict[str, set[Coordinate]],
) -> set[Coordinate]:
    """Validates native component provenance and returns its exact coordinates."""

    if inventory.get("schema") != "aos.native-advisory-inventory/v1":
        raise GateError("unsupported native inventory schema")
    components = inventory.get("components")
    if not isinstance(components, list) or not components:
        raise GateError("native inventory must contain components")

    result: set[Coordinate] = set()
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise GateError(f"native component {index} must be an object")
        name = require_string(component, "name", f"native component {index}")
        expected_version = require_string(component, "version", f"native component {name}")
        kind = require_string(component, "kind", f"native component {name}")

        if kind == "nix-literal":
            observed_version = nix_literal_version(repository, component)
        elif kind == "cargo-package":
            lock = require_string(component, "lock", f"native component {name}")
            package = require_string(component, "package", f"native component {name}")
            package_version = require_string(
                component, "package_version", f"native component {name}"
            )
            if lock not in cargo_locks:
                raise GateError(f"native component {name} names unknown lockfile {lock}")
            if Coordinate(package, package_version) not in cargo_locks[lock]:
                raise GateError(
                    f"native component {name} source package drifted from "
                    f"{package}@{package_version} in {lock}"
                )
            observed_version = expected_version
        else:
            raise GateError(f"native component {name} has unknown kind {kind!r}")

        if observed_version != expected_version:
            raise GateError(
                f"native component {name} expected {expected_version}, found {observed_version}"
            )
        coordinate = Coordinate(name, expected_version)
        if coordinate in result:
            raise GateError(f"duplicate native component {coordinate.text}")
        result.add(coordinate)

    return result


def rustsec_findings(reports: list[Path]) -> set[tuple[str, str]]:
    """Returns exact findings emitted by cargo-deny JSON reports."""

    result: set[tuple[str, str]] = set()
    for report in reports:
        try:
            lines = report.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise GateError(f"cannot read cargo-deny report {report}: {error}") from error
        for line_number, line in enumerate(lines, 1):
            try:
                diagnostic = json.loads(line)
            except json.JSONDecodeError as error:
                raise GateError(
                    f"{report}:{line_number} is not a cargo-deny JSON diagnostic"
                ) from error
            if not isinstance(diagnostic, dict):
                raise GateError(f"{report}:{line_number} is not a JSON object")
            if diagnostic.get("type") == "log":
                fields = diagnostic.get("fields")
                if isinstance(fields, dict) and fields.get("level") == "ERROR":
                    message = fields.get("message", "cargo-deny failed")
                    raise GateError(f"{report}:{line_number}: {message}")
                continue
            if diagnostic.get("type") != "diagnostic":
                continue
            fields = diagnostic.get("fields")
            if not isinstance(fields, dict):
                raise GateError(f"{report}:{line_number} has invalid diagnostic fields")
            code = fields.get("code")
            if code not in {"vulnerability", "unsound", "notice"}:
                if fields.get("severity") == "error":
                    message = fields.get("message", "cargo-deny failed")
                    raise GateError(
                        f"{report}:{line_number}: cargo-deny {code}: {message}"
                    )
                continue
            advisory = fields.get("advisory")
            graphs = fields.get("graphs")
            if not isinstance(advisory, dict) or not isinstance(graphs, list):
                raise GateError(f"{report}:{line_number} has incomplete advisory fields")
            advisory_id = require_string(
                advisory, "id", f"{report}:{line_number} advisory"
            )
            if not graphs:
                raise GateError(f"{report}:{line_number} advisory has no package graph")
            for graph in graphs:
                if not isinstance(graph, dict) or not isinstance(graph.get("Krate"), dict):
                    raise GateError(f"{report}:{line_number} has invalid package graph")
                package = graph["Krate"]
                name = require_string(package, "name", f"{report}:{line_number} package")
                version = require_string(
                    package, "version", f"{report}:{line_number} package"
                )
                result.add((advisory_id, Coordinate(name, version).text))
    return result


def active_exceptions(
    policy: dict[str, Any], today: dt.date
) -> set[tuple[str, str]]:
    """Validates disposition metadata and returns active advisory coordinates."""

    if policy.get("schema") != "aos.advisory-exceptions/v1":
        raise GateError("unsupported advisory exceptions schema")
    exceptions = policy.get("exceptions")
    if not isinstance(exceptions, list):
        raise GateError("advisory exceptions must be an array")

    result: set[tuple[str, str]] = set()
    for index, item in enumerate(exceptions):
        if not isinstance(item, dict):
            raise GateError(f"advisory exception {index} must be an object")
        advisory_id = require_string(item, "id", f"advisory exception {index}")
        component = require_string(item, "component", f"advisory exception {advisory_id}")
        require_string(item, "owner", f"advisory exception {advisory_id}")
        require_string(item, "reason", f"advisory exception {advisory_id}")
        require_string(item, "remediation", f"advisory exception {advisory_id}")
        expiry = parse_date(
            require_string(item, "expires_on", f"advisory exception {advisory_id}"),
            f"advisory exception {advisory_id}.expires_on",
        )
        if expiry < today:
            raise GateError(f"advisory exception {advisory_id} for {component} expired {expiry}")
        if (expiry - today).days > 90:
            raise GateError(
                f"advisory exception {advisory_id} for {component} exceeds 90 days"
            )
        pair = (advisory_id, component)
        if pair in result:
            raise GateError(f"duplicate advisory exception {advisory_id} for {component}")
        result.add(pair)
    return result


def snapshot_findings(
    snapshot: dict[str, Any], today: dt.date, native: set[Coordinate]
) -> set[tuple[str, str]]:
    """Validates snapshot freshness and returns applicable native findings."""

    if snapshot.get("schema") != "aos.advisory-snapshot/v1":
        raise GateError("unsupported advisory snapshot schema")
    generated = parse_date(
        require_string(snapshot, "generated_on", "advisory snapshot"),
        "advisory snapshot.generated_on",
    )
    maximum_age = snapshot.get("maximum_age_days")
    if not isinstance(maximum_age, int) or maximum_age < 1:
        raise GateError("advisory snapshot.maximum_age_days must be positive")
    age = (today - generated).days
    if age < 0:
        raise GateError("advisory snapshot is dated in the future")
    if age > maximum_age:
        raise GateError(
            f"advisory snapshot is {age} days old; maximum is {maximum_age} days"
        )
    require_string(snapshot, "rustsec_revision", "advisory snapshot")

    findings = snapshot.get("native_findings")
    if not isinstance(findings, list):
        raise GateError("advisory snapshot.native_findings must be an array")
    result: set[tuple[str, str]] = set()
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise GateError(f"native finding {index} must be an object")
        advisory_id = require_string(finding, "id", f"native finding {index}")
        component = require_string(finding, "component", f"native finding {advisory_id}")
        fixed_version = require_string(
            finding, "fixed_version", f"native finding {advisory_id}"
        )
        require_string(finding, "source", f"native finding {advisory_id}")
        if "@" not in component:
            raise GateError(f"native finding {advisory_id} must use an exact coordinate")
        name, version = component.rsplit("@", 1)
        coordinate = Coordinate(name, version)
        if coordinate not in native:
            continue
        if fixed_version == version:
            raise GateError(f"native finding {advisory_id} does not advance {component}")
        pair = (advisory_id, component)
        if pair in result:
            raise GateError(f"duplicate native finding {advisory_id} for {component}")
        result.add(pair)
    return result


def validate(args: argparse.Namespace) -> None:
    """Validates the complete pinned gate input set.

    Raises:
        GateError: Any input is stale, inconsistent, expired, or undisposed.
    """

    repository = args.repository.resolve()
    today = parse_date(args.today, "--today")
    cargo_locks = {
        str(path.relative_to(repository)): lock_packages(path)
        for path in (repository / relative for relative in args.lock)
    }
    native = native_coordinates(
        repository, load_json(args.native_inventory), cargo_locks
    )
    snapshot = load_json(args.snapshot)
    findings = snapshot_findings(snapshot, today, native)
    exceptions = active_exceptions(load_json(args.exceptions), today)
    cargo_findings = rustsec_findings(args.cargo_report)

    undisposed = (findings | cargo_findings) - exceptions
    if undisposed:
        raise GateError(
            "findings lack active dispositions: "
            + ", ".join(f"{item[0]} for {item[1]}" for item in sorted(undisposed))
        )

    recognized = cargo_findings | findings
    unused = exceptions - recognized
    if unused:
        raise GateError(
            "dispositions do not match a current finding: "
            + ", ".join(f"{item[0]} for {item[1]}" for item in sorted(unused))
        )


def parser() -> argparse.ArgumentParser:
    """Builds the command-line parser."""

    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--repository", type=Path, required=True)
    value.add_argument("--snapshot", type=Path, required=True)
    value.add_argument("--exceptions", type=Path, required=True)
    value.add_argument("--native-inventory", type=Path, required=True)
    value.add_argument("--cargo-report", type=Path, action="append", required=True)
    value.add_argument("--lock", action="append", required=True)
    value.add_argument("--today", required=True)
    return value


def main() -> int:
    """Runs the gate and reports a concise failure."""

    try:
        validate(parser().parse_args())
    except GateError as error:
        print(f"advisory gate: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
