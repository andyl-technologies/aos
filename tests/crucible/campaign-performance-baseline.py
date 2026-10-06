# SPDX-License-Identifier: Apache-2.0
"""Validate a reviewable v2 paired comparison without approving its baseline.

Every member must retain its actual VM output, semantic work, host and source
artifacts. The output is the authenticated candidate manifest for review;
publication still requires a separately reviewed hash and decision plan.
"""

import argparse
import json
from pathlib import Path
import runpy
import sys

REFERENCE_PROFILE = Path(__file__).parent / "fixtures/campaign-performance-reference-host-v1.env"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("comparison", type=Path)
    parser.add_argument("decision_plan", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    validator = runpy.run_path(str(Path(__file__).with_name("campaign-performance-comparison.py")))
    try:
        decision = validator["compare"](args.comparison, args.decision_plan, REFERENCE_PROFILE)
        args.report.write_text(json.dumps(decision, sort_keys=True, indent=2) + "\n")
        if validator["decision_exit_code"](decision) != 0:
            raise ValueError(f"paired no-regression decision is {decision['decision']}")
        sys.stdout.buffer.write(validator["bounded_read"](args.comparison))
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        parser.exit(1, f"campaign performance candidate: {error}\n")


if __name__ == "__main__":
    main()
