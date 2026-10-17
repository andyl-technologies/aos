"""Compare current admitted production plugins at authenticated Linux readiness.

Each Sim sample runs in the isolated quota/UFFD kernel under a real accepted
assignment. The primary interval begins at native spawn and ends at the exact
flight.ready stop. Canonical BLAKE scope roots and timer evidence are validated
separately after timing. Historical flat-memory hashes remain historical;
legacy fixture validators below are used only by their component tests.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import statistics
import subprocess


WITNESS_KEYS = (
    "raw_icount", "logical_tick", "idle_wake_tick", "registers",
    "ram_sha256", "ram_bytes", "serial_sha256", "markers", "advances", "status",
    "timer_witness", "device_projection_manifest",
)



def managed_oracle():
    path = Path(__file__).with_name("tcg-managed-performance-oracle.py")
    spec = importlib.util.spec_from_file_location("managed_performance_oracle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def labeled_paths(arguments):
    """Resolve explicitly paired local artifact labels."""
    result = {}
    for argument in arguments:
        label, path = argument.split("=", 1)
        allowed_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        valid_label = label and all(character in allowed_characters for character in label)
        if label in result or not valid_label:
            raise ValueError(f"invalid or duplicate artifact label {label}")
        result[label] = Path(path).resolve(strict=True)
    return result


def sha256(path):
    """Hash a frozen executable or guest artifact before running VMs."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def distribution(values):
    """Retain central tendency and spread without discarding raw samples."""
    return {
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0,
    }


def require_ready_witness(sample, ram_mib):
    """Independently verify the authenticated trap-to-stop protocol relation."""
    pending = [marker for marker in sample["markers"] if marker["kind"] == 0xFF06]
    if len(pending) != 1:
        raise AssertionError("expected exactly one authenticated pending selectable")
    marker = pending[0]
    payload = bytes.fromhex(marker["payload_hex"])
    # The public v2 transport carries raw retirement separately from the outer
    # marker's logical time. Reject version/layout drift instead of guessing.
    supported_layout = (
        len(payload) >= 40
        and payload[:8] == b"CRUCSPQ2"
        and payload[8:12] == b"\x02\x00\x28\x00"
    )
    if not supported_layout:
        raise AssertionError("unexpected selectable transport layout")
    request_raw = int.from_bytes(payload[32:40], "little")
    if sample["raw_icount"] != request_raw + 1:
        raise AssertionError("readiness did not stop after the doorbell instruction")
    if sample["logical_tick"] != marker["logical_tick"] + 50:
        raise AssertionError("readiness stopped at a different logical tick")
    if sample["idle_wake_tick"] != sample["logical_tick"] or sample["status"]["status"] != "paused":
        raise AssertionError("readiness boundary is not quiesced")
    if sample["ram_bytes"] != ram_mib * 1024 * 1024:
        raise AssertionError("the complete declared physical memory range was not captured")
    timer = sample["timer_witness"]
    if not timer or timer["generation"] < 1 or timer["completed"] != 1 or timer["reserved"] != 0:
        raise AssertionError("Linux boot did not publish a completed native timer witness")
    if not timer["armed_raw_icount"] == timer["fired_raw_icount"] <= sample["raw_icount"]:
        raise AssertionError("guest retirement changed during the witnessed timer jump")
    if not timer["deadline_ps"] == timer["fired_expire_ps"] <= timer["fired_virtual_ps"]:
        raise AssertionError("the native timer fired before its saved expiry")
    if timer["deadline_tick"] > sample["logical_tick"]:
        raise AssertionError("the witnessed timer lies after readiness")
    return {key: sample[key] for key in WITNESS_KEYS}


def readiness_negative_controls(sample, ram_mib):
    """Prove that malformed stopping and timer evidence is rejected."""
    mutations = {
        "raw_overshoot": lambda value: value.update(raw_icount=value["raw_icount"] + 1),
        "logical_overshoot": lambda value: value.update(logical_tick=value["logical_tick"] + 1),
        "native_running": lambda value: value["status"].update(status="running"),
        "partial_memory": lambda value: value.update(ram_bytes=value["ram_bytes"] - 1),
        "missing_request": lambda value: value.update(markers=[]),
        "incomplete_timer": lambda value: value["timer_witness"].update(completed=0),
        "timer_retired_instruction": lambda value: value["timer_witness"].update(
            fired_raw_icount=value["timer_witness"]["armed_raw_icount"] + 1
        ),
    }
    for name, mutate in mutations.items():
        invalid = copy.deepcopy(sample)
        mutate(invalid)
        try:
            require_ready_witness(invalid, ram_mib)
        except AssertionError:
            continue
        raise AssertionError(f"readiness negative control was accepted: {name}")
    return list(mutations)


def trial_order(labels, repeat):
    """Rotate every label through trial positions, then reverse the rotations."""
    if len(labels) == 2:
        return labels if repeat % 2 == 0 else list(reversed(labels))
    position = repeat % (2 * len(labels))
    basis = labels if position < len(labels) else list(reversed(labels))
    rotation = position % len(labels)
    return basis[rotation:] + basis[:rotation]


def platform_metadata(cpus):
    """Record the local host and available frequency policy without changing it."""
    cpuinfo = Path("/proc/cpuinfo").read_text()
    model = next(line.split(":", 1)[1].strip() for line in cpuinfo.splitlines()
                 if line.startswith("model name"))
    governors = {}
    for cpu in sorted(cpus):
        path = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
        governors[str(cpu)] = path.read_text().strip() if path.exists() else None
    return {
        "cpu_model": model,
        "logical_cpus": os.cpu_count(),
        "system": {
            "name": os.uname().sysname,
            "release": os.uname().release,
            "architecture": os.uname().machine,
        },
        "governors": governors,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--qemu", action="append", required=True)
    parser.add_argument("--plugin", action="append", required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--initrd", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--host-cpu", type=int)
    parser.add_argument("--ram-mib", type=int, default=256)
    parser.add_argument("--fingerprint", choices=["on"], default="on")
    parser.add_argument("--baseline-revision")
    parser.add_argument("--candidate-revision")
    args = parser.parse_args()
    if os.environ.get("CRUCIBLE_PERFORMANCE_PROGRESS"):
        raise ValueError("unset diagnostic progress logging for measured trials")
    qemu = labeled_paths(args.qemu)
    plugins = labeled_paths(args.plugin)
    if qemu.keys() != plugins.keys() or args.repetitions < 1:
        raise ValueError("provide matching QEMU/plugin labels and positive repetitions")
    if args.host_cpu is not None:
        os.sched_setaffinity(0, {args.host_cpu})
    args.output.mkdir(parents=True, exist_ok=True)
    kernel = args.kernel.resolve(strict=True)
    initrd = args.initrd.resolve(strict=True)
    driver = args.driver.resolve(strict=True)
    results = {
        "scope": __doc__, "baseline_revision": args.baseline_revision,
        "candidate_revision": args.candidate_revision, "cpu": args.cpu,
        "host_cpu": args.host_cpu, "repetitions": args.repetitions,
        "configuration": {
            "ram_mib": args.ram_mib, "vcpus": 1, "machine": "pc-q35-9.2",
            "accelerator": "sim,thread=single", "rr_switch_quantum": 4096,
            "cpu_model": "qemu64,-rdrand,-rdseed", "seed": "0x0010c004",
            "kernel_cmdline": "console=ttyS0 reboot=k panic=1 quiet rdinit=/init",
            "coverage": "off", "fingerprint": args.fingerprint, "whitebox": "on",
            "timer": "CLOCK_MONOTONIC via Rust Instant",
            "cpu_accounting": "QEMU /proc/PID/stat user+system ticks, including startup",
            "poll_interval_us": 100,
            "trial_order": "two labels alternate; other counts rotate then reverse",
            "cache_policy": "ordinary local caches; no forced cache drop",
        },
        "guest": {"kernel": str(kernel), "kernel_sha256": sha256(kernel),
                  "initrd": str(initrd), "initrd_sha256": sha256(initrd)},
        "driver": {"path": str(driver), "sha256": sha256(driver)},
        "artifacts": {
            label: {"qemu": str(binary), "qemu_sha256": sha256(binary),
                    "plugin": str(plugins[label]), "plugin_sha256": sha256(plugins[label]),
                    "qemu_build_identity": (binary.parent.parent / "share/aos/crucible/qemu-build-identity.env").read_text()}
            for label, binary in qemu.items()
        },
        "attempts": [], "samples": [],
        "platform": platform_metadata({args.cpu} | ({args.host_cpu} if args.host_cpu is not None else set())),
    }
    labels = list(qemu)
    expected = None
    for repeat in range(args.repetitions):
        order = trial_order(labels, repeat)
        for label in order:
            directory = args.output / f"linux-{repeat}-{label}"
            command = [str(driver), "--linux", str(qemu[label]), str(plugins[label]),
                       str(kernel), str(initrd), str(directory), str(args.cpu),
                       str(args.ram_mib), args.fingerprint]
            directory.mkdir(parents=True, exist_ok=True)
            attempt = {"label": label, "repeat": repeat, "command": command,
                       "outcome": "started"}
            results["attempts"].append(attempt)
            (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")

            trial_environment = dict(os.environ)
            trial_environment["CRUCIBLE_TCG_TRIAL_INDEX"] = str(repeat * len(labels) + labels.index(label))
            completed = subprocess.run(command, text=True, capture_output=True, check=False,
                                       env=trial_environment)
            (directory / "stdout.log").write_text(completed.stdout)
            (directory / "stderr.log").write_text(completed.stderr)
            attempt.update(exit_status=completed.returncode,
                           outcome="captured" if completed.returncode == 0 else "failed")
            (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
            if completed.returncode != 0:
                raise RuntimeError(f"Linux boot trial failed: {label}, repeat {repeat}, "
                                   f"exit {completed.returncode}; see {directory / 'stderr.log'}")

            try:
                sample = json.loads(completed.stdout)
                sample.update(label=label, repeat=repeat, command=command)
                (directory / "result.json").write_text(json.dumps(sample, indent=2) + "\n")
                witness = managed_oracle().require_witness(sample, "linux", args.ram_mib)
                if expected is None:
                    expected = witness
                    results["negative_controls"] = managed_oracle().negative_controls(sample, "linux", args.ram_mib)
                if witness != expected:
                    differences = [key for key in managed_oracle().WITNESS_KEYS if witness[key] != expected[key]]
                    raise AssertionError(f"Linux state witness changed: {label}, repeat {repeat}: {differences}")
            except (ValueError, KeyError, AssertionError) as error:
                attempt.update(outcome="invalid_witness", error=str(error))
                (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
                raise

            results["samples"].append(sample)
            attempt["outcome"] = "passed"
            (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
            print(json.dumps({"label": label, "repeat": repeat,
                              "seconds": sample["seconds"], "boot_seconds": sample["boot_seconds"],
                              "raw_icount": sample["raw_icount"]}), flush=True)
    results["deterministic"] = True
    results["witness"] = expected
    results["distributions"] = {
        label: {
            key: distribution([sample[key] for sample in results["samples"] if sample["label"] == label])
            for key in ("seconds", "boot_seconds", "startup_seconds")
        }
        for label in labels
    }
    results["comparisons"] = []
    for index, candidate in enumerate(labels[1:], start=1):
        baseline = labels[0]
        control = results["distributions"][baseline]["seconds"]["mean"]
        treatment = results["distributions"][candidate]["seconds"]["mean"]
        previous = labels[index - 1]
        previous_mean = results["distributions"][previous]["seconds"]["mean"]
        results["comparisons"].append({
            "baseline": baseline,
            "candidate": candidate,
            "launch_to_ready_reduction_percent": 100 * (control - treatment) / control,
            "speedup": control / treatment,
            "previous_stage": previous,
            "incremental_reduction_percent": 100 * (previous_mean - treatment) / previous_mean,
        })
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
