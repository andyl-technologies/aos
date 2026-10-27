"""Compares the installed Hub command surface and complete migration dump."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def qualify(packages):
    """Runs both executables without external runtime commands in PATH."""
    probes = {
        "aos-hub": [
            (["--help"], 0), (["--version"], 0), (["--aos-invalid-option"], 2),
            (["schema", "dump"], 0), (["schema", "--help"], 0),
            (["serve", "--help"], 0), (["index", "--help"], 0),
            (["init", "--help"], 0), (["reset-root", "--help"], 0),
            (["worker", "--help"], 0), (["--target", "unknown", "init"], 1),
        ],
        "aos-hub-egress": [
            (["--help"], 0), (["--version"], 0),
            (["--aos-invalid-option"], 2), ([], 2),
        ],
    }
    if set(packages) != {"ordinary", "bazel"}:
        raise ValueError("installed Hub commands require both package roots")
    records = {}
    for driver, outputs in packages.items():
        binaries = Path(outputs["out"]) / "bin"
        if sorted(path.name for path in binaries.iterdir()) != sorted(probes):
            raise ValueError("installed Hub executable set differs")
        records[driver] = {}
        with tempfile.TemporaryDirectory(prefix="hub-installed-commands-") as temporary:
            environment = {"HOME": temporary, "PATH": "/no-external-runtime-tools", "TZ": "UTC"}
            for name, cases in probes.items():
                records[driver][name] = []
                for arguments, expected in cases:
                    result = subprocess.run(
                        [str(binaries / name), *arguments],
                        env=environment, capture_output=True, timeout=30,
                    )
                    if result.returncode != expected:
                        raise ValueError(f"installed {name} {arguments} returned {result.returncode}: {result.stderr!r}")
                    if expected == 0 and (not result.stdout or result.stderr):
                        raise ValueError("installed Hub command omitted its successful output")
                    if expected != 0 and (result.stdout or not result.stderr):
                        raise ValueError("installed Hub command changed its failure output contract")
                    record = {
                        "arguments": arguments, "status": result.returncode,
                        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                    }
                    if name == "aos-hub" and arguments == ["schema", "dump"]:
                        statements = json.loads(result.stdout)
                        if not isinstance(statements, list) or not statements or any(not isinstance(item, str) or not item.strip() for item in statements):
                            raise ValueError("installed Hub omitted its complete migration statement array")
                        record["migration_statements"] = len(statements)
                    records[driver][name].append(record)
            if any(Path(temporary).iterdir()):
                raise ValueError("installed Hub command inspection or rejection created home state")
    if records["ordinary"] != records["bazel"]:
        raise ValueError("installed Hub command status, output or migration dump differs")
    return records


if __name__ == "__main__":
    import sys

    packages = json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps(qualify(packages), indent=2, sort_keys=True))
