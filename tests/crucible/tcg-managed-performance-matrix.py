"""Run separately admitted native trials and compare their canonical boundaries.

The samples measure spawn through the authenticated stopped boundary. Canonical
RAM identity differs from the historical flat-memory SHA witness; admitted
register and memory windows retain the independent arithmetic checks. Every
repeat uses a fresh quota namespace.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def load_oracle(path):
    specification = importlib.util.spec_from_file_location("managed_oracle", path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--profile-json", type=Path)
    parser.add_argument("--bios", required=True)
    parser.add_argument("--rom", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--rom-oracle", type=Path, required=True)
    parser.add_argument("--workload", action="append", choices=("bios", "linux", "rom"), required=True)
    arguments = parser.parse_args()
    if len(set(arguments.workload)) != len(arguments.workload):
        raise ValueError("each workload must have one explicit repeated comparison")
    if arguments.baseline and not arguments.profile_json:
        raise ValueError("baseline comparison requires an explicit measurement profile")
    oracle = load_oracle(arguments.oracle)
    arithmetic = load_oracle(arguments.rom_oracle)
    manifest = json.loads(arguments.manifest.read_text())
    if arithmetic.reference_checksum(manifest["iterations"]) != manifest["checksum"]:
        raise AssertionError("finite ROM manifest differs from the independent arithmetic checksum")
    selector = "packaged_qemu_executor::tests::paging_native::performance::managed_tcg_performance_trial"
    qemu, plugin = (os.environ[key] for key in ("CRUCIBLE_PAGING_QEMU", "CRUCIBLE_PAGING_PLUGIN"))
    kernel, initrd = (os.environ[key] for key in ("CRUCIBLE_PAGING_KERNEL", "CRUCIBLE_TCG_INITRD"))
    trial_index = 0
    all_samples = []
    controls = []
    for workload in arguments.workload:
        expected = None
        for repeat in range(2):
            directory = f"/tmp/tcg-sample-{trial_index}"
            if workload == "bios":
                inputs = ["bios-driver", qemu, plugin, arguments.bios, "2400000", directory, "0"]
                ram_mib = 64
            elif workload == "linux":
                inputs = ["linux-driver", "sim", qemu, plugin, kernel, initrd, directory, "0", "256"]
                ram_mib = 256
            else:
                inputs = ["rom-driver", "sim", qemu, plugin, arguments.rom, directory, "0", str(arguments.manifest)]
                ram_mib = 64
            environment = dict(os.environ)
            environment.update(
                CRUCIBLE_TCG_TRIAL_INDEX=str(trial_index),
                CRUCIBLE_TCG_PERFORMANCE_WORKLOAD=workload,
                CRUCIBLE_TCG_PERFORMANCE_ARGUMENTS=json.dumps(inputs),
            )
            command = [arguments.runner, "--ignored", "--exact", selector, "--nocapture", "--test-threads=1"]
            completed = subprocess.run(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            print(completed.stdout, end="", flush=True)
            completed.check_returncode()
            if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in completed.stdout:
                raise AssertionError("the actual ignored native trial did not execute")
            encoded = [line.removeprefix("TCG_MANAGED_SAMPLE=") for line in completed.stdout.splitlines() if line.startswith("TCG_MANAGED_SAMPLE=")]
            if len(encoded) != 1:
                raise AssertionError("each native trial must publish exactly one measurement")
            sample = json.loads(encoded[0])
            witness = oracle.require_witness(sample, workload, ram_mib)
            controls = oracle.negative_controls(sample, workload, ram_mib)
            if workload == "bios" and sample["raw_icount"] != 2400000:
                raise AssertionError("BIOS trial did not stop at its independently authored horizon")
            if workload == "bios":
                oracle.require_bios_reference(sample, 2400000)
            if expected is None:
                expected = witness
            elif witness != expected:
                raise AssertionError(f"canonical stopped boundary changed across {workload} repeats")
            all_samples.append(dict(sample, trial_index=trial_index, repeat=repeat))
            trial_index += 1
    if arguments.profile_json:
        comparison = load_oracle(Path(__file__).with_name("managed-performance-comparison.py"))
        def digest(path):
            with open(path, "rb") as artifact:
                return hashlib.file_digest(artifact, "sha256").hexdigest()
        receipt = {
            "schema": comparison.SCHEMA,
            "profile": json.loads(arguments.profile_json.read_text()),
            "producer": {"qemu": digest(qemu), "plugin": digest(plugin)},
            "inputs": {name: digest(path) for name, path in {
                "kernel": kernel, "initrd": initrd, "bios": arguments.bios,
                "rom": arguments.rom, "manifest": arguments.manifest,
                "firmware": os.environ["CRUCIBLE_TCG_FIRMWARE"],
            }.items()},
            "timing_contract": "native-spawn-to-authenticated-stopped-boundary.v1",
            "samples": all_samples,
        }
        comparison.checked_groups(receipt)
        print("MANAGED_TCG_PERFORMANCE_RECEIPT=" + json.dumps(receipt, sort_keys=True))
        if arguments.baseline:
            baseline = json.loads(arguments.baseline.read_text())
            for previous in baseline["samples"]:
                oracle.require_witness(previous, previous["workload"], previous["ram_mib"])
            rows = comparison.compare_no_regression(baseline, receipt)
            print("MANAGED_TCG_PERFORMANCE_COMPARISON=" + json.dumps(rows, sort_keys=True))
            print("managed_tcg_regression_acceptance=PASS")
        else:
            print("managed_tcg_regression_acceptance=BLOCKED-missing-reviewed-baseline")
    else:
        print("managed_tcg_regression_acceptance=BLOCKED-missing-measurement-profile-and-baseline")
    print("managed_tcg_samples=" + str(len(all_samples)))
    print("managed_tcg_workloads=" + str(len(arguments.workload)))
    print("managed_tcg_repeated_canonical_boundaries=true")
    print("managed_tcg_original_owner_negative_controls=" + str(len(controls)))
    print("managed_tcg_native_cleanup=true")
    print("managed_tcg_portable_timing_threshold=false")
    print("managed_tcg_independent_arithmetic_oracles=true")
    print("MANAGED_TCG_PERFORMANCE_NATIVE_PASS")


if __name__ == "__main__":
    main()
