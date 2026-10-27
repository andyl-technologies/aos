# SPDX-License-Identifier: GPL-2.0-only
"""Retain selected block-wait and time-advance bodies for the joined unit."""

import argparse
import hashlib
import json
from pathlib import Path
import re


FUNCTIONS = {
    "block/crucible-shmem.c": (
        "qemu_plugin_register_blk_cb",
        "qemu_plugin_register_blk_wait_cb",
        "crucible_blk_callbacks_ready",
        "crucible_shmem_wake",
        "crucible_shmem_wait_one_poll",
        "crucible_shmem_poll_until_ready",
    ),
    "plugins/api-system.c": (
        "qemu_plugin_wake_notifier_add",
        "qemu_plugin_wake_notifier_remove",
        "qemu_plugin_register_time_advance_cb",
        "qemu_plugin_time_advance_arm_on_cpu",
        "qemu_plugin_time_advance_run_on_rr",
        "qemu_plugin_time_advance_service_timers_on_cpu",
        "qemu_plugin_advance_time_bh",
        "qemu_plugin_time_advance_claim_timer_barrier",
        "qemu_plugin_time_advance_barrier_bh",
        "qemu_plugin_time_advance_complete_bh",
        "qemu_plugin_time_advance_is_pending",
        "qemu_plugin_time_advance_settle_at_rr_idle",
        "qemu_plugin_advance_time_ticks",
        "qemu_plugin_wake_fd_read",
        "qemu_plugin_clock_deadline_ps",
        "qemu_plugin_crucible_arm_virtual_timer_witness",
        "qemu_plugin_crucible_query_virtual_timer_witness",
        "qemu_plugin_crucible_virtual_timer_witness_begin",
        "qemu_plugin_crucible_virtual_timer_witness_complete",
    ),
    "accel/tcg/tcg-accel-ops-rr.c": (
        "rr_crucible_sim_skip_second_events_pass",
        "rr_crucible_sim_vcpu_is_halted",
        "rr_crucible_sim_all_vcpus_halted",
        "rr_crucible_sim_stop_or_unplug_pending",
        "rr_crucible_sim_sync_vcpu_halt_callbacks",
        "rr_wait_io_event",
    ),
}


def function(source, name):
    """Copy a definition with its original declaration and body."""
    declaration = re.search(
        rf"(?m)^(?:static[ \t]+)?[A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*)*[ \t*\n]+{re.escape(name)}\s*\([^;{{]*\)\s*\{{",
        source,
    )
    if declaration is None:
        raise ValueError(f"missing selected definition: {name}")
    # Tokens keep braces inside comments and literals out of the nesting count.
    tokens = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    depth = 1
    for token in tokens.finditer(source, declaration.end()):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return source[declaration.start():token.end()] + "\n"
    raise ValueError(f"unterminated selected definition: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    definitions = []
    bindings = []
    for relative, names in FUNCTIONS.items():
        path = args.source / relative
        data = path.read_bytes()
        text = data.decode()
        for name in names:
            body = function(text, name)
            # The unit includes the complete block backend. API/RR bodies have
            # broad system dependencies, so only the selected definitions join it.
            if relative != "block/crucible-shmem.c":
                definitions.append(body)
            bindings.append({
                "path": relative,
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "function": name,
                "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            })
    declarations = [body[:body.index("{")].rstrip() + ";" for body in definitions]
    args.output.write_text("\n".join(declarations + definitions))
    args.output.with_suffix(".json").write_text(json.dumps(bindings, indent=2) + "\n")


if __name__ == "__main__":
    main()
