"""Resolves declared family libtests and checks their exact runtime inventory."""

from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlparse
import xml.etree.ElementTree as ET


def bazel_binaries(events, targets):
    """Finds one current executable per requested successful libtest target."""
    sets = {}
    completed = {}
    finished = False
    for event in events:
        identity = event.get("id", {})
        if "namedSet" in identity:
            sets[identity["namedSet"]["id"]] = event["namedSetOfFiles"]
        if "buildFinished" in identity:
            finished = event["finished"]["exitCode"].get("code", 0) == 0
        label = identity.get("targetCompleted", {}).get("label")
        if label in targets:
            if label in completed or not event["completed"].get("success"):
                raise ValueError(f"ambiguous or failed test target: {label}")
            completed[label] = event["completed"]
    if not finished or set(completed) != set(targets):
        raise ValueError("missing successful requested libtest targets")
    binaries = {}
    for label, target in completed.items():
        roots = [item["id"] for group in target.get("outputGroup", [])
                 if group["name"] == "default" for item in group.get("fileSets", [])]
        visited = set()
        candidates = set()
        while roots:
            identifier = roots.pop()
            if identifier in visited:
                continue
            visited.add(identifier)
            entry = sets[identifier]
            roots.extend(item["id"] for item in entry.get("fileSets", []))
            for file in entry.get("files", []):
                if Path(file["name"]).name != label.split(":", 1)[1]:
                    continue
                uri = urlparse(file["uri"])
                if uri.scheme != "file" or uri.netloc:
                    raise ValueError("test artifacts must be local files")
                candidates.add(Path(unquote(uri.path)))
        if len(candidates) != 1:
            raise ValueError(f"expected exactly one executable for {label}: {candidates}")
        binaries[label.removesuffix("_binary")] = candidates.pop()
    return binaries


def validate(binaries, expected, workspace, directory, environment, executable_prefix=(), *,
             case_runner=None, policy=None, jobs=4):
    """Requires the qualified case inventory and successful runtime behavior."""
    if bool(case_runner) != bool(policy) or case_runner and executable_prefix:
        raise ValueError("isolated validation requires both runner and policy, without a foreign executable prefix")
    if binaries.keys() != expected.keys():
        raise ValueError(f"compiled test targets differ: {binaries.keys() ^ expected.keys()}")
    for index, (label, binary) in enumerate(sorted(binaries.items())):
        cwd = workspace / label.split(":", 1)[0].removeprefix("//")
        for ignored in [False, True]:
            command = [*map(str, executable_prefix), str(binary), "--list", "--format=terse"] + (["--ignored"] if ignored else [])
            listing = subprocess.run(command, cwd=cwd, env=environment, check=True,
                                     capture_output=True, text=True, timeout=60)
            actual = sorted(line.removesuffix(": test") for line in listing.stdout.splitlines()
                            if line.endswith(": test"))
            oracle = expected[label]["ignored"] if ignored else expected[label]["executed"] + expected[label]["ignored"]
            if actual != sorted(oracle):
                raise ValueError(f"discovered test inventory differs: {label}")
        log_path = directory / f"validation-{index}.log"
        if case_runner:
            junit = directory / f"validation-{index}.xml"
            command = [sys.executable, str(case_runner), "--binary", str(binary),
                       "--package", cwd.name, "--policy", str(policy), "--jobs", str(jobs)]
            if not expected[label]["executed"] and not expected[label]["ignored"]:
                command.append("--allow-empty")
            with log_path.open("w") as log:
                result = subprocess.run(command, cwd=cwd, env=dict(environment, XML_OUTPUT_FILE=str(junit)),
                                        stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                raise ValueError(f"isolated family test execution failed: {label}:\n{log_path.read_text()}")
            cases = ET.parse(junit).findall("testcase")
            if (sorted(case.attrib["name"] for case in cases) != sorted(expected[label]["executed"])
                    or any(case.find("failure") is not None for case in cases)):
                raise ValueError(f"isolated executed test inventory differs: {label}")
            continue
        try:
            with log_path.open("w") as log:
                subprocess.run([*map(str, executable_prefix), str(binary), "--test-threads=1"], cwd=cwd, env=environment,
                               stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            raise ValueError(f"family test execution failed: {label}:\n{log_path.read_text()}") from error
        output = log_path.read_text()
        passed = re.findall(r"^test (.+) \.\.\. ok$", output, re.MULTILINE)
        if sorted(passed) != sorted(expected[label]["executed"]):
            raise ValueError(f"executed test inventory differs: {label}")
