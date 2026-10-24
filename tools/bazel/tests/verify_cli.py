"""Checks CLI feature units, executed cases, and Cargo/Bazel test inventories."""

import argparse
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from verify_protocol import compare, doctest_cases


CLI_PATH = "crates/aos/cli/aos-cli"


def cargo_results(log, messages):
    """Binds every Cargo execution section to its retained compiler artifact."""
    binaries = {}
    for line in messages.read_text().splitlines():
        event = json.loads(line)
        if (event.get("reason") != "compiler-artifact"
                or not event.get("profile", {}).get("test")
                or not event.get("executable")
                or not event["manifest_path"].endswith("/" + CLI_PATH + "/Cargo.toml")):
            continue
        target = event["target"]
        kind = target["kind"]
        name = "unit" if "lib" in kind else "bin_" + target["name"] if "bin" in kind else target["name"]
        binary = Path(event["executable"]).name
        if binary in binaries:
            raise ValueError("duplicate Cargo CLI test artifact: " + binary)
        binaries[binary] = "//" + CLI_PATH + ":" + name

    sections = re.split(r"^\s*Running .+ \(([^\n]+)\)\s*$", log, flags=re.MULTILINE)
    results = {}
    for binary, section in zip(sections[1::2], sections[2::2]):
        label = binaries.get(Path(binary).name)
        if label is None or label in results:
            raise ValueError("unknown or duplicate Cargo execution: " + binary)
        # The final libtest section is followed by rustdoc's independent run.
        section = re.split(r"^\s*Doc-tests \S+\s*$", section, flags=re.MULTILINE)[0]
        summaries = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", section, re.MULTILINE)
        # Libtest annotates expected panics in execution output, but not in
        # its discovery inventory or the Bazel runner's retained case names.
        cases = re.findall(r"^test (.+?)(?: - should panic)? \.\.\. (ok|FAILED|ignored(?:, [^\n]*)?)$", section, re.MULTILINE)
        if len(summaries) != 1 or summaries[0][0] != "ok":
            raise ValueError("Cargo CLI test did not pass: " + label)
        counts = tuple(int(value) for value in summaries[0][1:])
        if counts != (len(cases), 0, 0) or any(status != "ok" for _, status in cases):
            raise ValueError("Cargo CLI cases failed, were ignored, or differ from their summary: " + label)
        names = sorted(name for name, _ in cases)
        if len(names) != len(set(names)):
            raise ValueError("duplicate Cargo CLI case: " + label)
        results[label] = names
    if not binaries or set(results) != set(binaries.values()):
        raise ValueError("Cargo CLI artifacts and executed target inventories differ")
    docs = re.split(r"^\s*Doc-tests aos_cli\s*$", log, flags=re.MULTILINE)
    if len(docs) != 2 or doctest_cases(docs[1], CLI_PATH):
        raise ValueError("CLI doctest inventory changed; declare and qualify its Bazel target")
    return results


def verify_cli(tests, inventory, cargo):
    """Rejects feature drift, missing targets, skipped cases, and failed executions."""
    reports = json.loads(inventory.read_text())["configured_targets"]
    packages = {}
    for report in reports:
        name = report.get("rustc_env", {}).get("CARGO_PKG_NAME")
        if report["label"].startswith("//crates/") and name:
            path = report["label"].split(":", 1)[0][2:]
            if name in packages and packages[name] != path:
                raise ValueError("ambiguous first-party package: " + name)
            packages[name] = path
    if packages.get("aos-cli") != CLI_PATH:
        raise ValueError("configured inventory omitted the CLI package")
    messages = cargo / "cargo-messages.jsonl"
    result = compare(
        tests, inventory, messages,
        package_paths={"aos-cli": CLI_PATH},
        dependency_paths=packages,
    )
    executed = cargo_results((cargo / "cargo-tests.log").read_text(), messages)
    expected = {label: target["executed"] for label, target in result["targets"].items()}
    if executed != expected or any(target["ignored"] for target in result["targets"].values()):
        raise ValueError("Cargo and Bazel executed CLI cases differ")
    for event in json.loads((tests / "index.json").read_text())["results"]:
        xml = ET.parse(tests / event["outputs"]["test.xml"])
        for case in xml.findall("testcase"):
            if case.find("skipped") is not None or "skipping " in "".join(case.itertext()).lower():
                raise ValueError("CLI case contains a skip diagnostic: " + case.attrib["name"])
    result["cargo_executed"] = executed
    result["doctests"] = []
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify_cli(options.tests, options.inventory, options.cargo), indent=2, sort_keys=True) + "\n")
