"""Measure the common shipped-CLI campaign workflow in one disposable VM.

Run with AOS-built Python and each revision's own campaign-process-flight,
CLI, QEMU and plugin. The manifest supplies two independently authored
deployments, a common kernel/root image, and the actual VM/storage description.
This compares public campaign completion, not modern durable attempt receipts.
It neither flushes host caches nor changes kernel permissions or quotas.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import statistics
import subprocess
import tomllib

SELECTOR = "public_default_run_executes_through_an_authenticated_campaign"
SCHEMA = "crucible.public-workflow-performance.v1"
TIMING = "shipped-cli-spawn-through-exit"
WORKLOAD = {
    "selector": SELECTOR, "architecture": "x86_64", "memory_mib": 128,
    "vcpus": 1, "cmdline": "console=ttyS0", "initrd": None,
    "ready_icount": 0, "seed": 0x1E6ACACA, "terminal_delay_ns": 2000000,
    "terminal_action": "Pass", "white_box": "Disabled",
}
ARTIFACT_ENV = {
    "cli": "CRUCIBLE_PROCESS_FLIGHT_BINARY",
    "qemu": "CRUCIBLE_FLIGHT_QEMU",
    "plugin": "CRUCIBLE_FLIGHT_PLUGIN",
}


def file_identity(value):
    """Identify the bytes actually consumed, with bounded hashing scratch."""
    path = Path(value).resolve(strict=True)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest()}


def positive_integer(value, name):
    """Refuse booleans and absent or nonpositive numerical contracts."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def native_limits(deployment):
    """Check the one-node initial launch partition, before inventory tightening.

    Version 3 charges source services separately from the native process. These
    constants follow known_ram_launch_requirements(128MiB, 1): one CAS slot,
    4MiB operation scratch plus 16KiB native staging. They do not assert that
    post-inventory native ceilings remain equal or that host service peaks are
    the same in the two revisions.
    """
    if deployment.get("schema") != "crucible.campaign-packaged-executor":
        raise ValueError("unexpected executor deployment schema")
    if deployment.get("maximum_slots") != 1 or deployment.get("worker_count") != 1:
        raise ValueError("common workflow requires one assignment and one worker")
    if deployment.get("qemu_profile") != "deterministic-tcg-v1":
        raise ValueError("common workflow requires deterministic TCG")
    version = deployment.get("version")
    if version == 2:
        resident = deployment["maximum_resident_bytes"]
        backing = deployment["maximum_disk_bytes"]
        cpu = deployment["maximum_vcpus"]
        quanta = deployment["maximum_execution_quanta"]
    elif version == 3:
        resources = deployment["assignment_resources"]
        limits = deployment["assignment_limits"]
        resident = (resources["resident_peak_bytes"]
                    - deployment["watcher_service_resident_bytes"]
                    - deployment["maximum_node_host_service_resident_bytes"]
                    - 4 * 1024 * 1024)
        backing = resources["backing_peak_bytes"] - (4 * 1024 * 1024 + 16384)
        # Actual QEMU topology contains one vCPU; authored aggregate CPU slots
        # additionally contain catalog/registry and retained Service owners.
        cpu = 1
        quanta = limits["execution_quanta"]
    else:
        raise ValueError("unsupported revision-specific deployment")
    result = {"resident_bytes": resident, "backing_bytes": backing,
              "cpu_slots": cpu, "task_slots": deployment["maximum_tasks"],
              "execution_quanta": quanta}
    for name, value in result.items():
        positive_integer(value, name)
    return result


def parse_sample(output):
    """Accept timing only after the original exact selector's assertions pass."""
    required = {
        "campaign_default_run": "true",
        "campaign_default_run_completed_campaigns": "1",
        "campaign_default_run_measurement": TIMING,
        "campaign_default_run_completion": "authenticated-public-campaign",
    }
    fields = {}
    for line in output.splitlines():
        if line.startswith("campaign_default_run") and "=" in line:
            name, value = line.split("=", 1)
            if name in fields:
                raise ValueError(f"duplicate measured field {name}")
            fields[name] = value
    if any(fields.get(name) != value for name, value in required.items()):
        raise ValueError("missing authenticated public campaign completion")
    if not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", output):
        raise ValueError("the original exact selector did not pass")
    result = {}
    for name in ("process_host_ns", "physical_quanta", "frontier_ticks"):
        result[name] = positive_integer(
            int(fields[f"campaign_default_run_{name}"]), name)
    return result


def compare(samples):
    """Reject increased median or maximum; keep individual samples visible."""
    durations = {name: [sample["process_host_ns"] for sample in samples
                        if sample["variant"] == name]
                 for name in ("baseline", "candidate")}
    if len(durations["baseline"]) < 2 or len(durations["baseline"]) != len(durations["candidate"]):
        raise ValueError("comparison requires equal repeated measurements")
    summaries = {name: {"median_ns": statistics.median(values),
                        "minimum_ns": min(values), "maximum_ns": max(values),
                        "sample_count": len(values)}
                 for name, values in durations.items()}
    passed = all(summaries["candidate"][field] <= summaries["baseline"][field]
                 for field in ("median_ns", "maximum_ns"))
    return {"samples": summaries, "no_regression": passed,
            "criterion": "candidate median and maximum <= baseline, no margin"}


def collect(manifest, output_root):
    """Run ABBA blocks sequentially under the same observed VM environment."""
    blocks = positive_integer(manifest["abba_blocks"], "abba_blocks")
    timeout = positive_integer(manifest["sample_timeout_seconds"], "sample_timeout_seconds")
    profile = manifest["profile"]
    experiment_id = manifest["experiment_id"]
    if not isinstance(experiment_id, str) or not experiment_id.strip():
        raise ValueError("experiment lacks its explicit run identity")
    for field in ("host", "storage"):
        if not isinstance(profile.get(field), str) or not profile[field].strip():
            raise ValueError(f"profile lacks its declared {field}")
    inputs = {name: file_identity(manifest["inputs"][name])
              for name in ("kernel", "root_image")}
    workload = {"authored": WORKLOAD,
                "kernel_sha256": inputs["kernel"]["sha256"],
                "root_image_sha256": inputs["root_image"]["sha256"]}
    workload_sha256 = hashlib.sha256(json.dumps(
        workload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    variants = {}
    partitions = {}
    original_namespaces = set()
    for name in ("baseline", "candidate"):
        supplied = manifest["variants"][name]
        if not re.fullmatch(r"[0-9a-f]{40}", supplied["source_commit"]):
            raise ValueError("variant lacks its pinned source commit")
        artifacts = {field: file_identity(supplied[field])
                     for field in (*ARTIFACT_ENV, "test_binary")}
        if len(supplied["deployments"]) != 2 * blocks:
            raise ValueError("each invocation needs its own authored deployment")
        deployments = []
        for path in supplied["deployments"]:
            identity = file_identity(path)
            deployment = tomllib.loads(Path(identity["path"]).read_text())
            partition = native_limits(deployment)
            if name in partitions and partitions[name] != partition:
                raise ValueError("a variant changes native limits between repeats")
            partitions[name] = partition
            for field in ("run_root", "operational_registry_root", "ram_catalog_root"):
                namespace = deployment.get(field)
                if namespace is not None:
                    if namespace in original_namespaces:
                        raise ValueError("repeat reuses a durable workflow namespace")
                    original_namespaces.add(namespace)
            deployments.append({"identity": identity, "body": deployment})
        variants[name] = {"source_commit": supplied["source_commit"],
                          "artifacts": artifacts, "deployments": deployments}
    if partitions["baseline"] != partitions["candidate"]:
        raise ValueError(f"initial native launch limits differ: {partitions}")

    output_root.mkdir(parents=True, exist_ok=False)
    observed = {"uname": list(os.uname()),
                "cpu_affinity": sorted(os.sched_getaffinity(0)),
                "inherited_nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
                "inherited_memlock": resource.getrlimit(resource.RLIMIT_MEMLOCK),
                "mountinfo": Path("/proc/self/mountinfo").read_text(),
                "host_cache": "uncontrolled; no host-cold claim"}
    samples = []
    invocation_counts = {"baseline": 0, "candidate": 0}
    for block in range(blocks):
        for name in ("baseline", "candidate", "candidate", "baseline"):
            variant = variants[name]
            environment = os.environ.copy()
            for field, variable in ARTIFACT_ENV.items():
                environment[variable] = variant["artifacts"][field]["path"]
            invocation = invocation_counts[name]
            deployment = variant["deployments"][invocation]["identity"]
            environment["CRUCIBLE_FLIGHT_DEPLOYMENT"] = deployment["path"]
            environment["CRUCIBLE_KERNEL"] = inputs["kernel"]["path"]
            environment["CRUCIBLE_ROOT_IMAGE"] = inputs["root_image"]["path"]
            command = [variant["artifacts"]["test_binary"]["path"], "--ignored",
                       "--exact", SELECTOR, "--nocapture", "--test-threads=1"]
            log = output_root / f"{len(samples):03d}-{name}.log"
            # On timeout/failure the original log remains. The disposable VM
            # harness must then contain/reap the failed flight before any reuse.
            with log.open("w") as destination:
                subprocess.run(command, env=environment, stdout=destination,
                               stderr=subprocess.STDOUT, timeout=timeout, check=True)
            sample = parse_sample(log.read_text())
            cgroup_events = Path(variant["deployments"][invocation]["body"]["cgroup_root"]).joinpath("cgroup.events").read_text()
            if "populated 0" not in cgroup_events.splitlines():
                raise ValueError("completed CLI left a populated native cgroup")
            sample.update(variant=name, block=block, invocation=invocation,
                          deployment_sha256=deployment["sha256"],
                          cgroup_events_after_exit=cgroup_events, log=str(log))
            samples.append(sample)
            invocation_counts[name] += 1
            if len({(row["physical_quanta"], row["frontier_ticks"]) for row in samples}) != 1:
                raise ValueError("completed workloads disagree on guest work or frontier")
    comparison = compare(samples)
    report = {"schema": SCHEMA, "timing_contract": TIMING,
              "experiment_id": experiment_id,
              "profile": profile, "observed_environment": observed,
              "inputs": inputs, "variants": variants, "workload": workload,
              "workload_sha256": workload_sha256,
              "initial_native_limits": partitions["baseline"], "samples": samples,
              "comparison": comparison,
              "scope": "common public campaign workflow; no modern attempt receipt coercion",
              "excluded": ["host-cold cache", "phase-specific timing",
                           "full throughput matrix", "post-inventory grant parity"]}
    (output_root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if not comparison["no_regression"]:
        raise AssertionError("public workflow performance regressed; see report.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    collect(json.loads(arguments.manifest.read_text()), arguments.output)


if __name__ == "__main__":
    main()
