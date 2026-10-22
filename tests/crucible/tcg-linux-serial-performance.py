# SPDX-License-Identifier: Apache-2.0
"""Compare ordinary TCG and Sim through the same complete serial milestone.

All rows boot identical stock kernel and initramfs bytes. The primary interval
starts before QEMU spawn and ends at the socket receipt for ordinary controls and at the authenticated
native stop for managed Sim. These distinct endpoints are recorded per row. It includes emulator startup, QMP setup and boot;
protocol allocation and post-marker diagnostics are outside the interval.

Ordinary TCG without icount, ordinary TCG with 1 ns per instruction, and Sim
with 50 ps per instruction use different execution contracts. Their same-workload
boot latency comparison is not a measurement of equal-instruction overhead.
Sim's authenticated native stop, full RAM, registers and timer witness are
qualified separately after the common marker. Stock post-marker QMP stops are
not exact token coordinates. CPU accounting endpoints are recorded per row.

Build the new guest and driver with the AOS phase2.tcgLinuxSerialGuest and
phase2.tcgLinuxSerialPerformanceDriver targets using local builders. Pass each
row explicitly as --row LABEL MODE QEMU_BINARY PLUGIN_OR_DASH. Modes are tcg,
tcg-icount and sim; ordinary TCG takes '-' for the plugin. No plugins are loaded
in ordinary TCG rows, even when the emulator supports them. Repeated rounds
rotate row positions and then reverse the rotations. Every start, exit, stream,
raw result and failed attempt is retained; no failed trial is retried or replaced.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess


MILESTONE = "CRUCIBLE_TCG_BOOT_READY_V1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--row", nargs=4, action="append", required=True,
                        metavar=("LABEL", "MODE", "QEMU", "PLUGIN_OR_DASH"))
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--initrd", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--host-cpu", type=int, required=True)
    parser.add_argument("--ram-mib", type=int, default=256)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--continue-failed", action="store_true")
    parser.add_argument("--oracle", type=Path,
                        default=Path(__file__).with_name("tcg-linux-boot-performance.py"))
    args = parser.parse_args()
    if args.output.exists() or args.rounds < 1:
        raise ValueError("use a new output directory and positive round count")
    if os.environ.get("LD_PRELOAD") or os.environ.get("CPUPROFILE"):
        raise ValueError("unset profiling instrumentation for uninstrumented trials")

    spec = importlib.util.spec_from_file_location("readiness_oracle", args.oracle)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    rows = {}
    for label, mode, qemu, plugin in args.row:
        permitted = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        valid_label = label and all(character in permitted for character in label)
        if label in rows or not valid_label:
            raise ValueError("provide unique path-safe row labels")
        if mode not in ("tcg", "tcg-icount", "sim") or (plugin == "-") != (mode != "sim"):
            raise ValueError("Sim requires a plugin; ordinary TCG requires '-' for its plugin")
        binary = Path(qemu).resolve(strict=True)
        plugin_path = None if plugin == "-" else Path(plugin).resolve(strict=True)
        identity = binary.parent.parent / "share/aos/crucible/qemu-build-identity.env"
        rows[label] = {
            "mode": mode, "qemu": str(binary), "qemu_sha256": oracle.sha256(binary),
            "plugin": str(plugin_path) if plugin_path else None,
            "plugin_sha256": oracle.sha256(plugin_path) if plugin_path else None,
            "qemu_build_identity": identity.read_text() if identity.exists() else None,
            "execution_contract": {
                "tcg": "ordinary TCG, virtual time not assigned per retired instruction",
                "tcg-icount": "ordinary TCG, shift=0 assigns 1 ns per retired instruction",
                "sim": "Sim, fixed 50 ps per retired instruction, scheduler quantum 4096",
            }[mode],
        }
    labels = list(rows)
    driver = args.driver.resolve(strict=True)
    kernel = args.kernel.resolve(strict=True)
    initrd = args.initrd.resolve(strict=True)
    os.sched_setaffinity(0, {args.host_cpu})
    args.output.mkdir(parents=True)
    destination = args.output / "results.json"
    results = {
        "scope": __doc__, "rows": rows, "rounds": args.rounds,
        "platform": oracle.platform_metadata({args.cpu, args.host_cpu}),
        "driver": {"path": str(driver), "sha256": oracle.sha256(driver)},
        "runner": {"path": str(Path(__file__).resolve()), "sha256": oracle.sha256(Path(__file__))},
        "oracle": {"path": str(args.oracle), "sha256": oracle.sha256(args.oracle)},
        "guest": {"kernel": str(kernel), "kernel_sha256": oracle.sha256(kernel),
                  "initrd": str(initrd), "initrd_sha256": oracle.sha256(initrd)},
        "configuration": {
            "cpu": args.cpu, "host_cpu": args.host_cpu, "ram_mib": args.ram_mib,
            "machine": "pc-q35-9.2", "vcpus": 1, "cpu_model": "qemu64,-rdrand,-rdseed",
            "rtc": "2026-01-01T00:00:00,clock=vm", "seed": "0x0010c004",
            "kernel_cmdline": "console=ttyS0 reboot=k panic=1 quiet rdinit=/init",
            "serial": "socket receipt for ordinary controls; reconciled token at authenticated native stop for managed Sim",
            "trial_order": "rotate row positions, then reverse rotations; retain every attempt",
            "cache_policy": "ordinary local caches; no forced cache drop",
        },
        "attempts": [], "samples": [], "campaign_complete": False,
    }
    expected_sim = None
    managed = oracle.managed_oracle()
    sim_fields = managed.WITNESS_KEYS

    def save():
        results["distributions"] = {
            label: {
                "attempts": sum(a["label"] == label for a in results["attempts"]),
                "passed": sum(a["label"] == label and a["outcome"] == "passed" for a in results["attempts"]),
                "failed": sum(a["label"] == label and a["outcome"] == "failed" for a in results["attempts"]),
                "successful_ready_times_are_conditional": True,
                "seconds": oracle.distribution([s["seconds"] for s in results["samples"] if s["label"] == label])
                           if any(s["label"] == label for s in results["samples"]) else None,
            }
            for label in labels
        }
        destination.write_text(json.dumps(results, indent=2) + "\n")

    save()
    for round_index in range(args.rounds):
        for position, label in enumerate(oracle.trial_order(labels, round_index)):
            row = rows[label]
            directory = args.output / f"round-{round_index}-{position}-{label}"
            directory.mkdir()
            command = [str(driver), row["mode"], row["qemu"], row["plugin"] or "-",
                       str(kernel), str(initrd), str(directory), str(args.cpu), str(args.ram_mib)]
            attempt = {"label": label, "round": round_index, "position": position,
                       "command": command, "outcome": "started"}
            results["attempts"].append(attempt)
            save()
            trial_environment = dict(os.environ)
            trial_environment["CRUCIBLE_TCG_TRIAL_INDEX"] = str(round_index * len(labels) + position)
            completed = subprocess.run(command, text=True, capture_output=True, check=False,
                                       env=trial_environment)
            (directory / "stdout.log").write_text(completed.stdout)
            (directory / "stderr.log").write_text(completed.stderr)
            attempt["exit_status"] = completed.returncode
            if completed.returncode != 0:
                attempt["outcome"] = "failed"
                readiness_timeout = ("serial milestone timeout after 300 seconds" in completed.stderr
                                     or "Linux readiness timeout:" in completed.stderr)
                if readiness_timeout:
                    attempt["censored_timeout_seconds"] = 300
                save()
                print(json.dumps({"label": label, "round": round_index, "outcome": "failed", "exit_status": completed.returncode}), flush=True)
                semantic_failure = any(message in completed.stderr for message in (
                    "duplicate complete serial milestone", "expected one complete serial milestone",
                    "unexpected readiness", "unexpected authenticated readiness",
                    "guest ran beyond", "readiness moved", "stopped RAM capture changed",
                ))
                if semantic_failure:
                    attempt["outcome"] = "invalid_witness"
                    save()
                    raise AssertionError("driver rejected semantic milestone/native evidence")
                recognized_failure = readiness_timeout or any(message in completed.stderr for message in (
                    "QEMU exited before complete serial milestone",
                    "QEMU exited before authenticated readiness",
                ))
                if not recognized_failure:
                    attempt["outcome"] = "unclassified_driver_error"
                    save()
                    raise RuntimeError("driver error was not a recognized boot/readiness failure")
                if args.continue_failed:
                    continue
                raise RuntimeError(f"trial failed without retry: {label}; see retained stderr")
            try:
                sample = json.loads(completed.stdout)
                (directory / "result.json").write_text(json.dumps(sample, indent=2) + "\n")
                if sample["milestone"] != MILESTONE or sample["milestone_count"] != 1 or sample["mode"] != row["mode"]:
                    raise AssertionError("shared complete serial milestone was not proved")
                expected_artifacts = {
                    "qemu": row["qemu"], "plugin": row["plugin"],
                    "kernel": str(kernel), "initrd": str(initrd),
                    "ram_mib": args.ram_mib, "cpu": args.cpu,
                }
                if any(sample[key] != value for key, value in expected_artifacts.items()):
                    raise AssertionError("successful sample does not identify its declared row artifacts")
                if not 0 <= sample["startup_seconds"] <= sample["seconds"]:
                    raise AssertionError("serial milestone timing precedes guest startup")
                if row["mode"] == "sim":
                    managed.require_witness(sample, "linux", args.ram_mib)
                    witness = {key: sample[key] for key in sim_fields}
                    if expected_sim is None:
                        expected_sim = witness
                        results["sim_negative_controls"] = managed.negative_controls(sample, "linux", args.ram_mib)
                    elif witness != expected_sim:
                        raise AssertionError("same-fixture Sim native witness changed")
            except (AssertionError, KeyError, ValueError) as error:
                attempt.update(outcome="invalid_witness", error=str(error))
                save()
                raise
            sample.update(label=label, round=round_index, position=position)
            results["samples"].append(sample)
            attempt["outcome"] = "passed"
            save()
            print(json.dumps({"label": label, "round": round_index, "seconds": sample["seconds"],
                              "native_stop_seconds": sample.get("native_stop_seconds"),
                              "post_marker_stopped_replay": sample.get("post_marker_stopped_replay")}), flush=True)
    results["campaign_complete"] = True
    results["sim_witness"] = expected_sim
    save()


if __name__ == "__main__":
    main()
