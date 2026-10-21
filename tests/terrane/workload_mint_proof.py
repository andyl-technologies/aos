"""Checks both AUTH-3 issuer prerequisites against the owning gate's source."""

import json
import os
from pathlib import Path
import sys

from gcp_instance_proof import CASES as INSTANCE_CASES
from native_sdk_test_image import source_hashes
from workload_issuer_proof import CASES as STATIC_CASES


def require(condition, message):
    """Refuses missing, mismatched or incomplete issuer evidence."""
    if not condition:
        raise SystemExit(message)


def review(proof, source, inputs, target, cases):
    """Requires the complete native issuer inventory from identical source."""
    require((proof / "result").read_text().strip() == "PASS", "issuer prerequisite failed")
    evidence = json.loads((proof / "source-review.json").read_text())
    require(evidence["source"] == str(source) and evidence["input_sha256"] == inputs,
            "issuer prerequisite source differs from the owning gate")
    require(evidence["executed_cases"] == cases, "issuer prerequisite inventory differs")

    artifact = evidence["artifact"]
    rows = [json.loads(line) for line in (proof / "build.jsonl").read_text().splitlines()]
    require(rows.count(artifact) == 1 and artifact["target"]["name"] == target
            and artifact["target"]["kind"] == ["test"]
            and artifact["features"] == ["default", "send", "std", "tokio"]
            and artifact["profile"]["test"] is True,
            "issuer prerequisite does not name its native Cargo test artifact")
    inventory = [line.removesuffix(": test")
                 for line in (proof / "inventory.log").read_text().splitlines()
                 if line.endswith(": test")]
    require(len(inventory) == len(set(inventory)) == len(cases)
            and set(inventory) == set(cases), "issuer prerequisite inventory is incomplete")
    for case in cases:
        lines = (proof / (case + ".log")).read_text().splitlines()
        require(lines.count("test " + case + " ... ok") == 1
                and sum(line.startswith("test result:") for line in lines) == 1
                and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                        for line in lines) == 1, "issuer prerequisite case did not pass: " + case)

    return {"proof": str(proof), "target": target, "executed_cases": cases,
            "executable_sha256": evidence["executable_sha256"]}


def main():
    """Combines actual issuance evidence without claiming service deployment."""
    source = Path(os.environ["src"])
    inputs = source_hashes(Path.cwd(), source)
    static, instance = map(Path, sys.argv[1:])
    prerequisites = [
        review(static, source, inputs, "workload_issuer", STATIC_CASES),
        review(instance, source, inputs, "gcp_instance_issuer", INSTANCE_CASES),
    ]
    output = Path(os.environ["out"])
    (output / "source-review.json").write_text(json.dumps({
        "source": str(source), "input_sha256": inputs, "prerequisites": prerequisites,
        "requirements": ["AUTH-3"],
        "scope": "Configured workload issuance only; no deployed CI service or guard-enforcement claim",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
