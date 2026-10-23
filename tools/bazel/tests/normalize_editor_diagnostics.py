"""Attributes analyzer-generated expressions to their enclosing source bodies.

The pinned analyzer's verbose CSV output precedes each body with its original
file and byte range. Synthetic expressions have no finer source range; retaining
the body range lets scoped comparisons check their ownership and multiplicity.
The complete analyzer output remains a separate qualification artifact.
"""

import argparse
import csv
from pathlib import Path
import re


BODY = re.compile(r"^processing: .+ \((.+) (\d+)\.\.(\d+)\)$")


def normalize(source, destination, analysis_log=None):
    """Retains every CSV diagnostic and requires a source body for synthetic ones."""
    context = None
    count = 0
    kinds = {"type": 0, "mismatch": 0}
    with source.open(newline="") as stream, destination.open("w", newline="") as output:
        writer = csv.writer(output)
        for row in csv.reader(stream):
            message = ",".join(row)
            if message.startswith("processing: "):
                context = BODY.fullmatch(message)
                continue

            if len(row) < 4 or row[3] not in {"type", "mismatch"}:
                if row and row[0] == "synthetic":
                    raise ValueError("malformed synthetic analyzer diagnostic")
                continue

            if len(row) != (5 if row[3] == "type" else 6):
                raise ValueError("malformed analyzer CSV diagnostic")
            kinds[row[3]] += 1
            if row[0] == "synthetic":
                if context is None:
                    raise ValueError("synthetic analyzer diagnostic lacks its source body")
                path, start, end = context.groups()
                if "/crates/" not in path or int(start) > int(end):
                    raise ValueError("synthetic analyzer source body is outside first-party sources")
                row[:3] = [path, "body-byte:" + start, "body-byte:" + end]
                row[3] = "synthetic-" + row[3]

            writer.writerow(row)
            count += 1

    if analysis_log is not None:
        expected = {"type": 0, "mismatch": 0}
        log = analysis_log.read_text()
        for category in ["exprs", "pats"]:
            statistics = re.findall(
                rf"{category}: \d+, \?\?ty: (\d+) \(\d+%\), \?ty: (\d+) \(\d+%\), !ty: (\d+)", log,
            )
            if len(statistics) != 1:
                raise ValueError("missing unique analyzer diagnostic statistics")
            unknown, partial, mismatches = map(int, statistics[0])
            expected["type"] += unknown + partial
            expected["mismatch"] += mismatches
        if kinds != expected:
            raise ValueError(f"normalized analyzer diagnostics differ from statistics: {kinds} != {expected}")

    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--analysis-log", type=Path, required=True)
    options = parser.parse_args()
    normalize(options.input, options.output, options.analysis_log)
