"""Selects loaded definitions from the configured aspect's first-party targets."""

import argparse
import json
from pathlib import Path

from export_inventory import reports_from_events


def query(events):
    """Avoids unconfigured dependency walks into unused implicit toolchains."""
    labels = {
        report["label"] for report in reports_from_events(events)
        if not report.get("external", False)
    }
    if not labels:
        raise ValueError("configured inventory contains no first-party targets")
    return "buildfiles(set(" + " ".join(sorted(labels)) + "))\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    events = [json.loads(line) for line in options.events.read_text().splitlines() if line]
    options.output.write_text(query(events))
