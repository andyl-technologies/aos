# SPDX-License-Identifier: Apache-2.0
"""Check trial provenance and native-witness admission without launching a VM."""

import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--runner", type=Path, required=True)
parser.add_argument("--oracle", type=Path, required=True)
arguments = parser.parse_args()
spec = importlib.util.spec_from_file_location("serial_runner", arguments.runner)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def sample(command):
    """Provide explicit synthetic evidence satisfying the public boundary oracle."""
    payload = bytearray(40)
    payload[:12] = b"CRUCSPQ2\x02\x00\x28\x00"
    payload[32:40] = (100).to_bytes(8, "little")
    value = {
        "mode": command[1], "milestone": runner.MILESTONE, "milestone_count": 1,
        "qemu": command[2], "plugin": None if command[3] == "-" else command[3],
        "cpu": int(command[7]),
        "seconds": 5.0, "startup_seconds": 0.1, "boot_seconds": 4.9,
        "raw_icount": 101, "logical_tick": 750, "idle_wake_tick": 750,
        "status": {"status": "paused"}, "ram_bytes": 256 * 1024 * 1024,
        "registers": "synthetic", "ram_sha256": "00" * 32,
        "serial_sha256": "00" * 32, "device_projection_manifest": {"synthetic": True},
        "markers": [{"kind": 0xFF06, "logical_tick": 700, "payload_hex": payload.hex()}],
        "advances": [20_000_000_000_000],
        "timer_witness": {"generation": 1, "completed": 1, "reserved": 0,
                          "armed_raw_icount": 50, "fired_raw_icount": 50,
                          "deadline_ps": 500, "fired_expire_ps": 500,
                          "fired_virtual_ps": 504, "deadline_tick": 500},
        "coverage": "off", "fingerprint": "off", "whitebox": "on", "ram_mib": 256,
        "kernel": command[4], "initrd": command[5],
    }
    if command[1] == "sim":
        value.update(
            schema="crucible.managed-tcg-performance.v1", workload="linux",
            managed_owner=True, accepted_assignment=True, native_cleanup=True,
            fingerprint_requests_after_measurement=True, component_failures=0,
            serial_receipt_roi_seconds=None,
            ram_prefix_hex="00" * 8, record_hex="00" * 16, sim_saved_registers_hex="00" * 8,
            request={"sequence": 2, "selectable_id": "flight.ready", "instance_key": "boot",
                     "raw_icount": 100, "logical_tick": 700},
            canonical_execution_fingerprint="11" * 32,
            canonical_ram_blake3="22" * 32,
            canonical_register_blake3="33" * 32,
            canonical_device_blake3="44" * 32,
            serial_hex=b"\nCRUCIBLE_TCG_BOOT_READY_V1\n".hex(),
        )
    return value



class TrialAdmission(unittest.TestCase):
    def invoke(self, rows, rounds, execute, continue_failed=False):
        temporary = tempfile.TemporaryDirectory(prefix="serial-runner-test-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        kernel = root / "kernel"
        initrd = root / "initrd"
        kernel.write_bytes(b"synthetic kernel")
        initrd.write_bytes(b"synthetic initrd")
        output = root / "results"
        argv = ["runner", "--driver", sys.executable, "--oracle", str(arguments.oracle),
                "--kernel", str(kernel), "--initrd", str(initrd), "--output", str(output),
                "--cpu", "96", "--host-cpu", "97", "--rounds", str(rounds)]
        for label, mode in rows:
            argv += ["--row", label, mode, sys.executable, sys.executable if mode == "sim" else "-"]
        if continue_failed:
            argv.append("--continue-failed")
        patches = (mock.patch.object(sys, "argv", argv),
                   mock.patch.object(runner.subprocess, "run", side_effect=execute),
                   mock.patch.object(runner.os, "sched_setaffinity"))
        with patches[0], patches[1] as launches, patches[2], contextlib.redirect_stdout(io.StringIO()):
            try:
                runner.main()
                error = None
            except (RuntimeError, AssertionError) as failure:
                error = failure
        return json.loads((output / "results.json").read_text()), error, launches.call_count

    def test_failed_launch_is_retained_and_not_retried(self):
        def fail(command, **_):
            return subprocess.CompletedProcess(command, 1, "", "serial milestone timeout after 300 seconds")
        result, error, count = self.invoke([("stock", "tcg"), ("sim", "sim")], 1, fail)
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(count, 1)
        self.assertEqual(result["attempts"][0]["censored_timeout_seconds"], 300)
        self.assertEqual(result["samples"], [])
        self.assertFalse(result["campaign_complete"])

    def test_scheduled_continuation_keeps_failures_outside_ready_mean(self):
        def execute(command, **_):
            if command[1] == "tcg":
                return subprocess.CompletedProcess(command, 1, "", "serial milestone timeout after 300 seconds")
            return subprocess.CompletedProcess(command, 0, json.dumps(sample(command)), "")
        result, error, count = self.invoke([("stock", "tcg"), ("sim", "sim")], 2, execute, True)
        self.assertIsNone(error)
        self.assertEqual(count, 4)
        self.assertTrue(result["campaign_complete"])
        self.assertEqual(result["distributions"]["stock"]["failed"], 2)
        self.assertIsNone(result["distributions"]["stock"]["seconds"])
        self.assertEqual(result["distributions"]["sim"]["seconds"]["mean"], 5.0)

    def test_native_witness_drift_aborts_even_when_failures_continue(self):
        calls = 0
        def execute(command, **_):
            nonlocal calls
            calls += 1
            value = sample(command)
            if calls == 2:
                value["canonical_ram_blake3"] = "55" * 32
            return subprocess.CompletedProcess(command, 0, json.dumps(value), "")
        result, error, count = self.invoke([("sim", "sim")], 3, execute, True)
        self.assertIsInstance(error, AssertionError)
        self.assertEqual(count, 2)
        self.assertEqual(result["attempts"][-1]["outcome"], "invalid_witness")
        self.assertFalse(result["campaign_complete"])

    def test_successful_mismatched_artifact_is_rejected(self):
        def execute(command, **_):
            value = sample(command)
            value["qemu"] = "a different synthetic artifact"
            return subprocess.CompletedProcess(command, 0, json.dumps(value), "")
        result, error, count = self.invoke([("sim", "sim")], 1, execute, True)
        self.assertIsInstance(error, AssertionError)
        self.assertEqual(count, 1)
        self.assertEqual(result["attempts"][-1]["outcome"], "invalid_witness")

    def test_unclassified_driver_error_never_continues(self):
        def execute(command, **_):
            return subprocess.CompletedProcess(command, 1, "", "new semantic or setup failure")
        result, error, count = self.invoke([("sim", "sim")], 2, execute, True)
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(count, 1)
        self.assertEqual(result["attempts"][-1]["outcome"], "unclassified_driver_error")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
