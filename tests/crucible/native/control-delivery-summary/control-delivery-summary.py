# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile actual bounded diagnostic and cancellation bodies with named providers.

No full QEMU translation unit, native worker, callback admission or physical
failure is authenticated. BQL is a real mutex with explicit thread custody;
CPU/runstate, trace endpoint and final write failures are providers.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shlex
import subprocess

CASES = ("default", "invalid", "not-sim", "pre-cancel", "foreign",
         "fixed-cache", "width", "fork", "pipe", "readonly", "closed",
         "interrupted-write", "short-write")
PREFIX = b"CRUCIBLE-NATIVE-CONTROL-SUMMARY-V1 "


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu-source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    extractor = here.parent / "block-wait-completion-bodies.py"
    function = runpy.run_path(str(extractor))["function"]
    api = args.qemu_source / "plugins/api-system.c"
    leaf = args.qemu_source / "accel/tcg/crucible-control-delivery-summary.c"
    names = ("qemu_plugin_trace_control_delivery",
             "qemu_plugin_crucible_rr_control_boundary_cancel")
    bodies = [function(api.read_text(), name) for name in names]
    (output / "control-delivery-summary-cancel.inc").write_text("\n".join(bodies))
    (output / "control-delivery-summary-native.inc").write_bytes(leaf.read_bytes())
    bindings = {
        "sources": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                    for path in (api, leaf, here / "control-delivery-summary.c", extractor)],
        "selected_bodies": [{"name": name, "sha256": hashlib.sha256(body.encode()).hexdigest()}
                            for name, body in zip(names, bodies, strict=True)],
        "limits": ["CPU/runstate are explicit providers",
                   "RR trace endpoint provider invokes actual cache helper",
                   "Cancellation prestate is constructed, not a native claim",
                   "No guest, full native loop or physical3998 cause proof"],
    }
    (output / "source-bindings.json").write_text(json.dumps(bindings, indent=2) + "\n")
    command = [os.environ["CC"], *shlex.split(os.environ.get("CFLAGS", "")),
               "-I" + str(output), str(here / "control-delivery-summary.c"),
               "-o", str(output / "controls"),
               *shlex.split(os.environ.get("LDFLAGS", ""))]
    (output / "compile-command.json").write_text(json.dumps(command, indent=2) + "\n")
    subprocess.run(command, check=True)
    for case in CASES:
        environment = os.environ.copy()
        environment.pop("CRUCIBLE_NATIVE_CONTROL_DELIVERY_SUMMARY", None)
        if case == "invalid":
            environment["CRUCIBLE_NATIVE_CONTROL_DELIVERY_SUMMARY"] = "01"
        elif case != "default":
            environment["CRUCIBLE_NATIVE_CONTROL_DELIVERY_SUMMARY"] = "1"
        with (output / f"{case}.stdout").open("wb") as stdout, \
             (output / f"{case}.stderr").open("wb") as stderr:
            # This independent parent owns the child; timeout kills and reaps it.
            subprocess.run([str(output / "controls"), case], env=environment,
                           stdout=stdout, stderr=stderr, check=True, timeout=10)
        stdout = (output / f"{case}.stdout").read_bytes()
        stderr = (output / f"{case}.stderr").read_bytes()
        assert stdout == f"CONTROL_SUMMARY_PASS case={case}\n".encode()
        if case in ("default", "invalid", "not-sim", "pipe", "readonly",
                    "closed", "interrupted-write"):
            assert stderr == b"", case
        elif case == "short-write":
            assert stderr == PREFIX[:2]
        else:
            rows = stderr.splitlines(keepends=True)
            assert all(row.startswith(PREFIX) and row.endswith(b"\n") and
                       len(row) <= 512 for row in rows), case
            assert len(stderr) <= (2 if case == "fork" else 1) * 6656
            assert sum(b"kind=current phase=cancel " in row for row in rows) == (
                2 if case == "fork" else 1)
            if case == "fixed-cache":
                assert len(rows) == 13
                assert b"sample=12000 request=3302 ack=1 complete=1 " in rows[0]
                assert all(b"request=18446744073709551615 " in row for row in rows[1:])
            elif case in ("pre-cancel", "foreign", "fork"):
                assert b"request=3302 ack=1 complete=1 rr_token=0x9 token=0x9 deferred=1 " in rows[0]
            if case == "fork":
                pids = {row.split(b" pid=", 1)[1].split(b" ", 1)[0] for row in rows}
                assert len(pids) == 2
        print(stdout.decode(), end="")


if __name__ == "__main__":
    main()
