# SPDX-License-Identifier: MIT
"""Runs one bounded ARM Linux PID1 diagnostic through real PL011 publications.

The existing ARM model owns firmware, DTB, GIC and timer construction. This
check grants no common-node Ready, capture, device-parity or timing authority.
"""

import importlib.util
from pathlib import Path
import sys

import m5


specification = importlib.util.spec_from_file_location(
    "crucible_linux_boot_observation", Path(__file__).with_name("linux-native-boot-common.py"))
common = importlib.util.module_from_spec(specification)
specification.loader.exec_module(common)
load = common.load
read_document = common.read_document
DEFAULT_HORIZON_SECONDS = "3"
MAX_EVENTS = common.MAX_EVENTS
EVENT_BATCH = common.EVENT_BATCH
REQUIRED_LINES = common.REQUIRED_LINES
MAX_TRANSCRIPT_BYTES = common.MAX_TRANSCRIPT_BYTES


def horizon_tick(seconds):
    return common.horizon_tick(seconds, ("3",))


def main():
    if len(sys.argv) not in (6, 7):
        raise ValueError("expected installed-helper manifest prepared-data transcript receipt [horizon-seconds]")
    helper_path, manifest_path, prepared_path, transcript_path, receipt_path = sys.argv[1:6]
    horizon_seconds = sys.argv[6] if len(sys.argv) == 7 else DEFAULT_HORIZON_SECONDS
    maximum_tick = horizon_tick(horizon_seconds)
    bundle = load("crucible_arm_boot_asset_verifier", Path(helper_path))
    document = read_document(manifest_path)
    bundle.verify_data(document)
    prepared = read_document(prepared_path)
    bundle.closed(prepared, {"schema", "resource_root", "model", "argv", "qualification"})
    if (prepared["schema"] != "crucible.gem5.arm-linux-prepared-data.v1"
            or prepared["qualification"] != document["qualification"]):
        raise ValueError("prepared native boot data has a foreign edition or qualification")
    artifacts = document["artifacts"]
    native = Path(artifacts["native_executable"]["path"])
    if Path("/proc/self/exe").resolve(strict=True) != native:
        raise ValueError("running simulator differs from the selected native executable")
    if Path(m5.options.outdir).resolve() != Path(prepared["resource_root"]):
        raise ValueError("native output directory differs from the original prepared root")
    if prepared["argv"] != [str(native), "--listener-mode=off",
            "--outdir=" + prepared["resource_root"], artifacts["entrypoint"]["path"]]:
        raise ValueError("prepared native boot command differs from its fixed installed model")

    adapter = load("crucible_fixed_arm_boot_model", Path(artifacts["model"]["path"]))
    model = adapter.ArmLinuxModel({"guest_isa": "aarch64", "executable": "",
                                  "model": prepared["model"]}, Path(prepared["resource_root"]))
    root = model.realize()
    console = common.Console(transcript_path, m5.curTick, "system.terminal", maximum_tick)
    processed = 0
    try:
        while processed < MAX_EVENTS:
            requested = min(EVENT_BATCH, MAX_EVENTS - processed)
            step = m5.simulateUntilBoundary(maximum_tick, requested)
            if not 0 <= step.processedEvents <= requested:
                raise ValueError("native callback count exceeds its requested finite batch")
            processed += step.processedEvents
            for publication in model.publications():
                identifier = console.consume(publication)
                model.acknowledge(identifier)
            if len(console.required) == len(REQUIRED_LINES):
                break
            if step.exitEvent is not None:
                raise ValueError("native guest exited before both PID1 boot lines: "
                                 + step.exitEvent.getCause())
            if not step.processedEvents:
                # Report the returned native boundary without advancing its queue.
                next_tick = step.nextTick if step.hasNextEvent else None
                raise ValueError(
                    "native guest exhausted its tick horizon or event queue: "
                    f"current_tick={step.currentTick}, has_next_event={step.hasNextEvent}, "
                    f"next_tick={next_tick}, exclusive_tick={maximum_tick}, "
                    f"processed_events={processed}, requested_events={requested}"
                )
        else:
            raise ValueError("native guest exhausted its original callback allowance")
    finally:
        console.stream.close()

    receipt = {
        "schema": "crucible.gem5.arm-linux-pid1-boot-check.v1",
        "model_id": "arm-linux-vexpress-atomic-functional-v1",
        "tick": str(m5.curTick()),
        "processed_events": processed,
        "limits": {"maximum_tick": str(maximum_tick), "maximum_events": MAX_EVENTS,
                   "maximum_transcript_bytes": MAX_TRANSCRIPT_BYTES},
        "required_lines": [line.decode("ascii") for line in REQUIRED_LINES],
        "console": console.summary(),
        "installed_artifacts": artifacts,
        "configuration_binding": document["configuration"]["binding"],
        "common_node_ready_qualified": False,
        "capture_qualified": False,
        "restored_continuation_qualified": False,
        "device_parity_qualified": False,
        "cpu_timing_qualified": False,
    }
    # Keep the actual instantiated graph alive through the final native readback.
    if root.system.terminal is not model.terminal:
        raise ValueError("native boot terminal left its original ARM owner")
    bundle.write_document(receipt, Path(receipt_path))


if __name__ == "__m5_main__":
    main()
