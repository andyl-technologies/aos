"""Derives one fixed, non-distributable RAM notification adversary.

The signed precursor already owns the token-specific independent oracle.
Only the RAM client's range notification after the first accepted horizon
is omitted; no runtime switch or ordinary artifact is modified.
"""

import argparse
import hashlib
import json
from pathlib import Path

NATIVE_COMMIT = "0e5751df73fdbf48b1d7f37b4a8c6eed6748a6c5"
PHYSICAL_SHA256 = "4f2f7a9d720e141ad8b3f3a1cb9e155ffa6f2c4d1cbb7365bc0f0b3b748fbbd1"
PAGED_SHA256 = "735a3a321b50d4d79bca09ec2eb6f0475110db5409271131ddc74cf2779868b0"
FIRST = 700_000
HEADER = '#include "exec/page-vary.h"\n'
HEADER_WITH_CLOCK = HEADER + '#include "exec/icount.h"\n'
ANCHOR = """    if ((mask & (1 << DIRTY_MEMORY_CRUCIBLE_CHECKPOINT)) &&
        (global_dirty_tracking & GLOBAL_DIRTY_CRUCIBLE_CHECKPOINT)) {
"""
OMISSION = """    /* Fixed diagnostic only: earlier real writes establish the baseline.
     * Preserve every other client's obligation and both original horizons. */
    if (icount_get_raw_observed() >= 700000) {
        mask &= ~(1 << DIRTY_MEMORY_CRUCIBLE_RAM);
    }

"""


def digest(source):
    return hashlib.sha256(source).hexdigest()


def transform(source):
    if digest(source) != PHYSICAL_SHA256:
        raise ValueError("physical source differs from the exact signed precursor")
    text = source.decode("utf-8")
    if text.count(HEADER) != 1 or text.count(ANCHOR) != 1:
        raise ValueError("notification/header anchors are not unique")
    changed = text.replace(HEADER, HEADER_WITH_CLOCK, 1)
    changed = changed.replace(ANCHOR, OMISSION + ANCHOR, 1)
    reconstructed = changed.replace(OMISSION, "", 1)
    reconstructed = reconstructed.replace(HEADER_WITH_CLOCK, HEADER, 1)
    if reconstructed.encode("utf-8") != source:
        raise ValueError("fixed omission does not reconstruct the complete precursor")
    return changed.encode("utf-8")


def verify_paged(source):
    if digest(source) != PAGED_SHA256:
        raise ValueError("paged source differs from the exact signed precursor")
    text = source.decode("utf-8")
    start = text.index("void qemu_crucible_ram_diagnostic_paused_owner(void)")
    end = text.index("\nstatic void hash_u32", start)
    text = text[start:end]
    required = [
        "qemu_plugin_crucible_ram_root_observer_v2 observer;",
        "0, result->token, incremental, &incremental_bytes,",
        "&result->capture_close);",
        "result->capture_close.attempted != 1",
        "0, result->token, complete, &complete_bytes);",
        "qemu_crucible_ram_diagnostic_fail(result->first_status);",
        "result->release_status = qemu_plugin_crucible_ram_physical_end_v1(",
    ]
    if any(text.count(expression) != 1 for expression in required):
        raise ValueError("stopped-owner comparison contract differs")
    contain = text.index(required[5])
    release = text.index(required[6])
    if contain >= release:
        raise ValueError("comparison refusal is not contained before owner release")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--physical-source", type=Path, required=True)
    parser.add_argument("--paged-source", type=Path, required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--role", choices=["oracle-positive", "notification-adversary"], required=True)
    args = parser.parse_args()

    physical = args.physical_source.read_bytes()
    paged = args.paged_source.read_bytes()
    verify_paged(paged)
    adversary = transform(physical)
    output = adversary if args.role == "notification-adversary" else physical
    args.output_file.write_bytes(output)
    args.manifest.write_text(json.dumps({
        "role": args.role,
        "native_commit": NATIVE_COMMIT,
        "physical_before_sha256": digest(physical),
        "physical_after_sha256": digest(output),
        "paged_unchanged_sha256": digest(paged),
        "omission_from_raw_icount": FIRST if args.role == "notification-adversary" else None,
        "full_precursor_reconstructed": True,
        "same_physical_token_candidate_full_read": True,
        "capture_closes_without_acknowledgement": True,
        "runtime_integrity_switch": False,
        "deployed_execution_qualified": False,
        "complete_16k_stack_and_original_payer_qualified": False,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
