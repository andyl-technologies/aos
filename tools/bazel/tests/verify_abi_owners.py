"""Checks executable Bazel owner evidence against the canonical ABI inventory."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from verify_cache import execution_events


def canonical_owners(source):
    """Reads every guarded owner from the still-authoritative Cargo driver."""
    calls = re.findall(r"^\s*require_test_set\s+(.+?)\\\n\s*([^\s]+)\s+\\", source, re.M)
    count = len(re.findall(r"^\s*require_test_set\s+", source, re.M))
    if not calls or len(calls) != count:
        raise ValueError("canonical ABI owner declarations are missing or unsupported")

    owners = {}
    for declaration, case in calls:
        fields = declaration.split()
        if len(fields) != 2 or not fields[0].isdigit() or int(fields[0]) < 1:
            raise ValueError("invalid canonical ABI owner declaration: " + declaration)
        size, name = fields
        if name in owners:
            raise ValueError("duplicate canonical ABI owner: " + name)
        owners[name] = {"count": int(size), "canonical": case}
    return owners


def validate_selections(source, selections):
    """Rejects omitted, added, renamed, or resized owner selections."""
    expected = canonical_owners(source)
    if set(expected) != set(selections):
        raise ValueError("Bazel selections differ from the complete canonical ABI owner set")
    for name, contract in expected.items():
        if any(selections[name].get(key) != value for key, value in contract.items()):
            raise ValueError("Bazel ABI owner contract differs: " + name)


def verify_owner(build, contract):
    """Authenticates one test action and its complete passing JUnit case set."""
    actions = [event for event in execution_events(build) if event["mnemonic"] == "TestRunner"]
    if len(actions) != 1:
        raise ValueError("expected exactly one ABI owner test action: " + str(build))
    action = actions[0]
    if (action["targetLabel"] != contract["target"] or action["exitCode"] != 0
            or action["runner"] != "linux-sandbox" or action["cacheHit"]):
        raise ValueError("ABI owner action did not execute successfully in the sandbox")

    arguments = [
        "--expected-count=" + str(contract["count"]),
        "--require-case=" + contract["canonical"],
        "--jobs=1",
    ]
    if contract["filter"] is not None:
        arguments.append("--filter=" + contract["filter"])
    guarded_arguments = [argument for argument in action["commandArgs"]
                         if argument.startswith(("--expected-count=", "--require-case=", "--jobs=", "--filter="))]
    if guarded_arguments != arguments:
        raise ValueError("ABI owner action omitted a canonical inventory or execution guard")

    reports = list((build / "evidence/tests").rglob("test.xml"))
    if len(reports) != 1:
        raise ValueError("expected exactly one ABI owner JUnit report")
    report = reports[0]
    suite = ET.parse(report).getroot()
    cases = suite.findall("testcase")
    names = [case.attrib["name"] for case in cases]
    if (suite.tag != "testsuite" or len(cases) != contract["count"]
            or suite.attrib.get("tests") != str(len(cases))
            or suite.attrib.get("failures") != "0" or len(set(names)) != len(names)
            or suite.attrib.get("errors", "0") != "0" or suite.attrib.get("skipped", "0") != "0"
            or contract["canonical"] not in names
            or any(case.find(tag) is not None for case in cases for tag in ["failure", "error", "skipped"])):
        raise ValueError("ABI owner JUnit report differs from its complete passing inventory")

    return {
        "build": str(build),
        "target": contract["target"],
        "cases": sorted(names),
        "runner": action["runner"],
        "arguments": arguments,
        "junit_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "execution_sha256": hashlib.sha256((build / "evidence/execution.json").read_bytes()).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canonical", required=True, type=Path)
    parser.add_argument("--comparison", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()

    source = options.canonical.read_text()
    manifest = json.loads((options.comparison / "selections.json").read_text())
    if manifest["canonical_gate_sha256"] != hashlib.sha256(options.canonical.read_bytes()).hexdigest():
        raise ValueError("canonical ABI source digest differs")
    selections = manifest["selections"]
    validate_selections(source, selections)
    results = {name: verify_owner(options.comparison / "owners" / name, contract)
               for name, contract in sorted(selections.items())}
    output = options.output or options.comparison / "evidence.json"
    output.write_text(json.dumps({
        "schema_version": 1,
        "status": "PASS",
        "owners": results,
        "executed_cases": sum(len(result["cases"]) for result in results.values()),
        "limits": ["Owner comparisons do not satisfy the named ABI gate's prerequisites or source audits."],
    }, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
