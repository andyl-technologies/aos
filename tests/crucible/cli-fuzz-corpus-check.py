# SPDX-License-Identifier: Apache-2.0
"""Inspect the real CLI fixture's retained corpus and second-process reports.

This helper records addressed metadata. The production CLI authenticates all
descriptor, reproduction, choice-closure and coverage bytes before execution.
"""

import json
import pathlib
import re
import sys


def read_json(path, limit):
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{path}: fixture input exceeds {limit} bytes")
    return json.loads(data)


def address(value):
    data = value["bytes"]
    if len(data) != 32 or any(type(byte) is not int or not 0 <= byte <= 255 for byte in data):
        raise ValueError("expected a 32-byte content address")
    return bytes(data).hex()


def snapshot(corpus, output):
    index = read_json(corpus / "live-fuzz-corpus.json", 8 * 1024 * 1024)
    keys = [address(entry) for entry in index["entries"]]
    if index["schema"] != 1 or not 0 < len(keys) <= 64 or keys != sorted(set(keys)):
        raise ValueError("expected a nonempty bounded current-format fixture index")

    entries = []
    for key in keys:
        relative = f"{key[:2]}/{key}"
        descriptor = read_json(corpus / relative, 1024 * 1024)
        if (
            descriptor["schema"] != 1
            or not descriptor["coverage_ids"]
            or type(descriptor["resumable_choice"]) is not bool
        ):
            raise ValueError("expected a retained current-format coverage descriptor")
        entries.append({
            "descriptor": key,
            "artifact": address(descriptor["artifact"]),
            "coverage_fingerprint": address(descriptor["coverage_fingerprint"]),
            "coverage_count": len(descriptor["coverage_ids"]),
            "resumable_choice": descriptor["resumable_choice"],
        })

    output.write_text(json.dumps({"entries": entries}, sort_keys=True) + "\n")
    print(f"{keys[0][:2]}/{keys[0]}")


def one_row(rows, kind):
    selected = [row["summary"] for row in rows if row["kind"] == kind]
    if len(selected) != 1:
        raise ValueError(f"expected one {kind}, found {len(selected)}")
    return selected[0]


def summary_field(summary, name):
    values = re.findall(rf"(?:^|\s){re.escape(name)}=([^\s]+)", summary)
    if len(values) != 1:
        raise ValueError(f"expected one public {name} field")
    return values[0]


def check_reopen(before, report):
    entries = read_json(before, 1024 * 1024)["entries"]
    with report.open("rb") as source:
        data = source.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("second-process JSONL exceeds the fixture bound")
    rows = [json.loads(line) for line in data.splitlines()]

    execution = one_row(rows, "fuzz_campaign_execution")
    if summary_field(execution, "backend") != "live":
        raise ValueError("second process did not report the live campaign backend")
    parent = summary_field(execution, "parent")
    eligible = {entry["artifact"] for entry in entries if entry["resumable_choice"] is True}
    if parent != "seed" and parent not in eligible:
        raise ValueError("second process selected a parent absent from the retained resumable corpus")
    progress = one_row(rows, "coverage_guided_fuzz_run")
    if int(summary_field(progress, "replay_oracle_validations")) < len(entries):
        raise ValueError("second process did not report validation of the retained entries")
    if int(summary_field(progress, "iterations")) != 1:
        raise ValueError("second process did not complete exactly one fuzz iteration")
    if int(summary_field(one_row(rows, "fuzz_coverage_feedback"), "blocks")) <= 0:
        raise ValueError("second process did not report real coverage feedback")
    final = one_row(rows, "final_outcome")
    for name, expected in (("subcommand", "fuzz"), ("status", "passed"), ("exit_code", "0")):
        if summary_field(final, name) != expected:
            raise ValueError("second process did not report successful fuzz completion")

    print(f"durable_fuzz_corpus_reopened entries={len(entries)} parent={parent} "
          f"compatible_resumable_entries={len(eligible)}")


def main():
    operation, first, second = sys.argv[1:]
    if operation == "snapshot":
        snapshot(pathlib.Path(first), pathlib.Path(second))
    elif operation == "check-reopen":
        check_reopen(pathlib.Path(first), pathlib.Path(second))
    else:
        raise ValueError(f"unknown fixture operation: {operation}")


if __name__ == "__main__":
    main()
