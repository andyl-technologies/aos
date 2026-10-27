"""Retains successful Bazel test attempts and their per-case logs/XML in Nix."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
from urllib.parse import unquote, urlparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=True)
    results = []
    for line in options.events.read_text().splitlines():
        event = json.loads(line)
        if "testResult" not in event.get("id", {}):
            continue
        identity = event["id"]["testResult"]
        result = event["testResult"]
        identifier = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        destination = options.output / identifier
        destination.mkdir()
        outputs = {}
        for item in result.get("testActionOutput", []):
            if item["name"] not in {"test.log", "test.xml"}:
                continue
            uri = urlparse(item["uri"])
            if uri.scheme != "file" or uri.netloc:
                raise ValueError("test export requires local log and XML outputs")
            source = Path(unquote(uri.path))
            shutil.copyfile(source, destination / item["name"])
            outputs[item["name"]] = f"{identifier}/{item['name']}"
        results.append({
            "identity": identity, "status": result["status"],
            "cached_locally": result.get("cachedLocally", False),
            "duration": result.get("testAttemptDuration", ""), "outputs": outputs,
        })
    (options.output / "index.json").write_text(json.dumps({"schema_version": 1, "results": results}, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
