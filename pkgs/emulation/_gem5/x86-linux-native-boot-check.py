# SPDX-License-Identifier: MIT
"""Boots the fixed x86 guest and consumes its real native UART publications.

This is an installed guest boot check. It constructs no common-node capability,
source-cut permit, capture certificate or restored continuation. The installed
asset checker and native model perform their ordinary checks before callbacks.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import m5


MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 256 * 1024
MAX_EVENTS = 500_000_000
DEFAULT_HORIZON_SECONDS = "2"
EVENT_BATCH = 128
TICKS_PER_SECOND = 1_000_000_000_000
REQUIRED_LINES = (b"GEM5_LINUX_INIT_READY", b"GEM5_LINUX_PROBE_COMPLETE")
FAILURE_TEXT = (b"GEM5_DEVICE_FAILURE", b"GEM5_LINUX_PROBE_FAILED", b"Kernel panic")


def horizon_tick(seconds):
    """Selects one finite diagnostic case at the fixed native 1 THz clock."""
    if type(seconds) is not str or seconds not in ("2", "4"):
        raise ValueError("native boot horizon must select the two- or four-second case")
    return int(seconds) * TICKS_PER_SECOND


def load(name, source):
    """Loads one fixed installed helper without replacing a prior module."""
    if name in sys.modules:
        raise ValueError("native boot helper name was already loaded")
    specification = importlib.util.spec_from_file_location(name, source)
    if specification is None or specification.loader is None:
        raise ValueError("installed native boot helper is not loadable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def read_document(path):
    """Bounds the source-installed or prepared data document before parsing."""
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_DOCUMENT_BYTES + 1)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("native boot document exceeds its finite extent")
    document = json.loads(data)
    if type(document) is not dict:
        raise ValueError("native boot document is not an object")
    return document


class Console:
    """Retains the bounded raw UART transcript and its original birth digest."""

    def __init__(self, path, horizon_seconds=DEFAULT_HORIZON_SECONDS):
        self.maximum_tick = horizon_tick(horizon_seconds)
        self.stream = Path(path).open("xb")
        self.byte_hash = hashlib.sha256()
        self.birth_hash = hashlib.sha256()
        self.bytes = 0
        self.last_identifier = 0
        self.first_birth = None
        self.last_birth = None
        self.line = bytearray()
        self.required = set()

    def consume(self, publication):
        """Checks and retains a publication before its native FIFO ACK."""
        if (type(publication) is not dict or set(publication) != {
                "output_id", "tick", "event_ordinal", "tick_ordinal",
                "causal_parent", "facet", "terminal", "payload"}):
            raise ValueError("native boot UART publication fields differ")
        if (publication["facet"] != "serial"
                or publication["terminal"] != "system.pc.com_1.device"
                or publication["causal_parent"] != "17"):
            raise ValueError("native boot UART owner or causal parent differs")
        numeric = []
        for name in ("output_id", "tick", "event_ordinal", "tick_ordinal"):
            value = publication[name]
            if (type(value) is not str or not value.isascii() or not value.isdecimal()
                    or len(value) > 20 or str(int(value)) != value
                    or int(value) >= 1 << 64):
                raise ValueError("native boot UART birth is not a canonical u64")
            numeric.append(int(value))
        identifier, tick, ordinal, tie = numeric
        if (identifier != self.last_identifier + 1 or not ordinal or not tie
                or tick > m5.curTick() or tick >= self.maximum_tick):
            raise ValueError("native boot UART birth or FIFO order differs")
        payload = publication["payload"]
        if (type(payload) is not list or len(payload) != 1
                or type(payload[0]) is not int or not 0 <= payload[0] <= 255):
            raise ValueError("native boot UART publication is not one byte")
        if self.bytes == MAX_TRANSCRIPT_BYTES:
            raise ValueError("native boot UART transcript exhausted its finite credit")

        data = bytes(payload)
        self.stream.write(data)
        self.byte_hash.update(data)
        encoded_birth = json.dumps(publication, sort_keys=True, separators=(",", ":")).encode()
        self.birth_hash.update(len(encoded_birth).to_bytes(8, "big"))
        self.birth_hash.update(encoded_birth)
        self.bytes += 1
        self.last_identifier = identifier
        self.first_birth = self.first_birth or publication
        self.last_birth = publication

        if data == b"\n":
            line = bytes(self.line).removesuffix(b"\r")
            if line in REQUIRED_LINES:
                self.required.add(line)
            self.line.clear()
        else:
            self.line.extend(data)
            if len(self.line) > 4096:
                raise ValueError("native boot console line exceeds its finite extent")
        if any(marker in self.line for marker in FAILURE_TEXT):
            raise ValueError("actual guest console reported a boot or PID1 failure")
        return identifier

    def summary(self):
        return {
            "bytes": self.bytes,
            "sha256": self.byte_hash.hexdigest(),
            "birth_sha256": self.birth_hash.hexdigest(),
            "first_birth": self.first_birth,
            "last_birth": self.last_birth,
        }


def main():
    if len(sys.argv) not in (6, 7):
        raise ValueError("expected installed-helper manifest prepared-data transcript receipt [horizon-seconds]")
    helper_path, manifest_path, prepared_path, transcript_path, receipt_path = sys.argv[1:6]
    horizon_seconds = sys.argv[6] if len(sys.argv) == 7 else DEFAULT_HORIZON_SECONDS
    maximum_tick = horizon_tick(horizon_seconds)
    bundle = load("crucible_x86_boot_asset_verifier", Path(helper_path))
    document = read_document(manifest_path)
    bundle.verify_data(document)
    prepared = read_document(prepared_path)
    bundle.closed(prepared, {"schema", "resource_root", "model", "argv", "qualification"})
    if (prepared["schema"] != "crucible.gem5.x86-linux-prepared-data.v1"
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

    adapter = load("crucible_fixed_x86_boot_model", Path(artifacts["model"]["path"]))
    model = adapter.X86LinuxModel({"guest_isa": "x86_64", "executable": "",
                                  "model": prepared["model"]}, Path(prepared["resource_root"]))
    root = model.realize()
    console = Console(transcript_path, horizon_seconds)
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
        "schema": "crucible.gem5.x86-linux-pid1-boot-check.v1",
        "model_id": "x86-linux-pc-atomic-functional-v1",
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
    if root.system.pc.com_1.device is not model.terminal:
        raise ValueError("native boot terminal left its original PC owner")
    bundle.write_document(receipt, Path(receipt_path))


if __name__ == "__m5_main__":
    main()
