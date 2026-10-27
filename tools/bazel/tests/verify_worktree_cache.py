"""Checks worktree cache topology without treating recycled inode IDs as sharing."""

import argparse
from itertools import combinations
import json
from pathlib import Path
import re


def validate_metrics(metrics):
    """Checks cache selection, fresh servers and isolation during measured overlap."""
    if set(metrics) != {"producer", "consumer", "uncached"}:
        raise ValueError("worktree proof requires producer, consumer and uncached metrics")

    namespaces = ["mnt", "net", "pid", "user"]
    for role, item in metrics.items():
        for field in ["started_unix_ns", "finished_unix_ns", "output_base_inode"]:
            if type(item[field]) is not int or item[field] <= 0:
                raise ValueError("invalid worktree metric: " + role + ": " + field)
        if item["started_unix_ns"] >= item["finished_unix_ns"]:
            raise ValueError("invalid worktree measurement interval: " + role)
        if item["server_before"] is not None:
            raise ValueError("worktree build reused a running Bazel server: " + role)
        for namespace in namespaces:
            if re.fullmatch(namespace + r":\[[1-9][0-9]*\]", item["namespaces"][namespace]) is None:
                raise ValueError("missing worktree namespace identity: " + role + ": " + namespace)

    producer_cache = metrics["producer"]["disk_cache"]
    if not producer_cache or producer_cache != metrics["consumer"]["disk_cache"]:
        raise ValueError("producer and consumer did not share the selected disk cache")
    if metrics["uncached"]["disk_cache"] is not None:
        raise ValueError("uncached worktree build enabled a disk cache")
    if metrics["producer"]["finished_unix_ns"] > metrics["consumer"]["started_unix_ns"]:
        raise ValueError("consumer started before the producer finished")

    overlapping = []
    for (left_role, left), (right_role, right) in combinations(metrics.items(), 2):
        start = max(left["started_unix_ns"], right["started_unix_ns"])
        finish = min(left["finished_unix_ns"], right["finished_unix_ns"])
        if start >= finish:
            continue

        # Linux frees namespace inode IDs for reuse after namespace destruction.
        # Equality is evidence of sharing only while both measured builds live.
        # See include/linux/proc_ns.h: ns_alloc_inum() and ns_free_inum().
        for namespace in namespaces:
            if left["namespaces"][namespace] == right["namespaces"][namespace]:
                raise ValueError("overlapping worktree builds shared a namespace: " + namespace)
        if left["output_base_inode"] == right["output_base_inode"]:
            raise ValueError("overlapping worktree builds shared an output directory")
        overlapping.append({"roles": [left_role, right_role], "overlap_ns": finish - start})

    return {
        "overlapping_pairs": overlapping,
        "identity_comparison_scope": "Measured overlapping lifetimes only; sequential namespace and directory inode IDs may be recycled.",
        "limits": [
            "Raw inode and namespace identifiers remain in metrics; distinct IDs are not required or claimed for nonoverlapping builds.",
            "These topology checks supplement the separately verified action reuse, artifact equality and Nix derivation provenance.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    options = parser.parse_args()
    evidence = json.loads(options.evidence.read_text())
    metrics = {
        role: json.loads((Path(build) / "evidence/metrics.json").read_text())
        for role, build in evidence["builds"].items()
    }
    evidence["topology"] = validate_metrics(metrics)
    evidence["metrics"] = metrics
    options.evidence.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
