"""Freeze and launch normal fleet inputs with independent private review.

The inputs come from `_hub-direct-controller-inputs.nix` evaluated against an
immutable source. Preparing the bundle requires realized prerequisites but never
builds or boots them. Running the frozen controller uses a new private working
directory, the ordinary guest-agent manifest and only its source-built tools.
The controller records execution; it does not grant provider acceptance.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


STORE_FILE = r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+/[A-Za-z0-9+._/-]+"


def closed_json(body):
    """Reject duplicate fields in frozen metadata."""
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("controller metadata has duplicate fields")
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=pairs)


def captured_inputs(document):
    """Select the exact normal phase's manifest, script and executable."""
    expected = {"version", "source", "separateDatabase", "name", "timeout", "machines",
        "testDerivation", "driverExecutable", "nixExecutable", "runtimePath",
        "controllerPhase", "scope"}
    if set(document) != expected or type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("controller input schema differs")
    if type(document["separateDatabase"]) is not bool or document["timeout"] != 14400:
        raise ValueError("controller topology or timeout differs")
    machines = ["client", "native", "s3", "worker"]
    if document["separateDatabase"]:
        machines.insert(1, "database")
    if document["machines"] != machines:
        raise ValueError("controller machine inventory differs")
    if not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]+", document["source"]):
        raise ValueError("controller source is not immutable")
    selected = {}
    for label, filename in (("manifest", "manifest.json"), ("test", "test.py")):
        matches = re.findall(
            r'^\s*cp (' + STORE_FILE + r')\s+"\$TMPDIR/' + re.escape(filename) + r'"\s*$',
            document["controllerPhase"], re.MULTILINE,
        )
        if len(matches) != 1 or Path(matches[0]).name != filename:
            raise ValueError("normal controller phase input is ambiguous")
        selected[label] = matches[0]
    for name in ("driverExecutable", "nixExecutable"):
        value = document[name]
        if not re.fullmatch(STORE_FILE, value) or "/../" in value:
            raise ValueError("controller executable is not an immutable store input")
    if document["controllerPhase"].count(document["driverExecutable"]) != 1:
        raise ValueError("normal controller driver differs from the selected executable")
    for directory in document["runtimePath"].split(":"):
        if not re.fullmatch(STORE_FILE, directory) or Path(directory).name != "bin":
            raise ValueError("controller PATH contains a non-store tool directory")
    return selected


def read_regular(path, maximum):
    """Capture bounded regular input bytes without following a final symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("controller input type or size differs")
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        if len(body) != before.st_size or any(getattr(before, field) != getattr(after, field)
                for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
            raise ValueError("controller input changed during capture")
    return body


def write_new(path, body, mode=0o400):
    """Persist a new frozen input or receipt without replacing retained evidence."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())


def encoded(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def store_root(path):
    return "/".join(path.split("/")[:4])


def prepare(inputs_file, directory):
    """Freeze realized inputs and their registered immutable NAR closure."""
    raw = read_regular(inputs_file, 1048576)
    inputs = closed_json(raw)
    selected = captured_inputs(inputs)
    bodies = {label: read_regular(path, maximum) for label, path, maximum in (
        ("manifest", selected["manifest"], 1048576),
        ("test", selected["test"], 4 * 1024 * 1024),
        ("driver", inputs["driverExecutable"], 16 * 1024 * 1024),
        ("controller", Path(__file__).resolve(), 1048576),
    )}
    roots = sorted({inputs["source"], *(store_root(path) for path in selected.values()),
        store_root(inputs["driverExecutable"]), store_root(inputs["nixExecutable"]),
        *(store_root(path) for path in inputs["runtimePath"].split(":"))})
    arguments = [inputs["nixExecutable"], "path-info", "--json", "--recursive", *roots]
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                            check=False, timeout=180)
    if result.returncode != 0 or len(result.stdout) > 64 * 1024 * 1024:
        raise ValueError("controller prerequisites are not completely realized")
    closure = closed_json(result.stdout)
    # Nix's registered NAR identities cover image/kernel/initrd and helper
    # references carried by the exact generated manifest and test script.
    if not closure:
        raise ValueError("controller closure inventory is empty")
    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700)
    files = {"inputs.json": raw, "closure.json": result.stdout,
        "manifest.json": bodies["manifest"], "test.py": bodies["test"],
        "controller.py": bodies["controller"]}
    receipt = {"version": 1, "inputsSha256": hashlib.sha256(raw).hexdigest(),
        "source": inputs["source"], "testDerivation": inputs["testDerivation"],
        "driverExecutable": inputs["driverExecutable"],
        "driverSha256": hashlib.sha256(bodies["driver"]).hexdigest(),
        "files": {name: {"sha256": hashlib.sha256(body).hexdigest(), "byteSize": len(body)}
            for name, body in files.items()},
        "scope": "registered immutable input closure; no VM launch or qualification"}
    for name, body in files.items():
        write_new(directory / name, body)
    write_new(directory / "bundle.json", encoded(receipt))
    directory.chmod(0o500)
    return receipt


def run(directory, run_directory):
    """Launch the frozen ordinary driver in a new owner-private working root."""
    directory = Path(directory).absolute()
    receipt = closed_json(read_regular(directory / "bundle.json", 1048576))
    for name, expected in receipt["files"].items():
        body = read_regular(directory / name, 64 * 1024 * 1024)
        if len(body) != expected["byteSize"] or hashlib.sha256(body).hexdigest() != expected["sha256"]:
            raise ValueError("frozen controller input differs")
    current = read_regular(Path(__file__).resolve(), 1048576)
    if hashlib.sha256(current).hexdigest() != receipt["files"]["controller.py"]["sha256"]:
        raise ValueError("run the exact frozen controller source")
    inputs = closed_json(read_regular(directory / "inputs.json", 1048576))
    captured_inputs(inputs)
    driver = read_regular(inputs["driverExecutable"], 16 * 1024 * 1024)
    if hashlib.sha256(driver).hexdigest() != receipt["driverSha256"]:
        raise ValueError("immutable driver identity differs")
    root = Path(run_directory).absolute()
    root.mkdir(mode=0o700)
    environment = dict(os.environ)
    for name in ("LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME"):
        environment.pop(name, None)
    environment.update(TMPDIR=str(root), PATH=inputs["runtimePath"],
        PYTHONDONTWRITEBYTECODE="1", LC_ALL="C")
    arguments = [inputs["driverExecutable"], "--manifest", str(directory / "manifest.json"),
        "--test", str(directory / "test.py"), "-v"]
    launch = {"version": 1, "bundleSha256": hashlib.sha256(encoded(receipt)).hexdigest(),
        "arguments": arguments, "source": inputs["source"],
        "controllerPid": os.getpid(), "ownerUid": os.geteuid(),
        "namespace": os.readlink("/proc/self/ns/pid"),
        "controllerStartTicks": Path("/proc/self/stat").read_text().rpartition(") ")[2].split()[19],
        "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "actual normal fleet execution; outcome and acceptance remain separate"}
    write_new(root / "launch.json", encoded(launch), 0o600)
    with (root / "driver.log").open("xb") as log:
        os.chmod(root / "driver.log", 0o600)
        process = subprocess.Popen(arguments, cwd=root, env=environment,
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        write_new(root / "driver-process.json", encoded({"pid": process.pid,
            "ownerUid": os.geteuid(), "arguments": arguments,
            "startTicks": Path(f"/proc/{process.pid}/stat").read_text().rpartition(") ")[2].split()[19]}), 0o600)
        exit_code = process.wait()
    outcome = {"version": 1, "exitCode": exit_code,
        "finishedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "driver outcome only; retained gate measurements determine qualification"}
    write_new(root / "outcome.json", encoded(outcome), 0o600)
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser("prepare")
    preparation.add_argument("--inputs", required=True)
    preparation.add_argument("--directory", required=True)
    execution = commands.add_parser("run")
    execution.add_argument("--directory", required=True)
    execution.add_argument("--run-directory", required=True)
    arguments = parser.parse_args()
    result = (prepare(arguments.inputs, arguments.directory) if arguments.command == "prepare"
        else run(arguments.directory, arguments.run_directory))
    print(json.dumps(result, sort_keys=True))
    return result.get("exitCode", 0)


if __name__ == "__main__":
    raise SystemExit(main())
