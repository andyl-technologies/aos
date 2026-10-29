"""Execute complete scale waves on the selected Worker VM's real loopback ports.

A private stop request lets the Fleet controller signal the exact Native issuer
through its existing machine agent. The handshake neither supplies an issuer
reply nor changes admission, time or provider permission. Missing acknowledgment
terminates this fixture as unknown; it never repeats an original owner request.
"""

import asyncio
import hashlib
import json
import os
import math
import secrets
from pathlib import Path
import sys
import stat
import time


def _scale_runtime_json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


async def execute_scale_runtime(selected, process, workload):
    root = Path(selected["root"])
    current = process["scale_process_identity"](os.getpid())
    original = {"version": 1, "runId": selected["run_id"], "sourceDigest": selected["source_digest"],
        "issuerPid": selected["issuer"]["pid"], "issuerStartTicks": selected["issuer"]["startTicks"],
        "workloadPid": current["pid"], "workloadStartTicks": current["startTicks"]}

    async def stop_issuer():
        request = {**original, "requestedUnixNs": time.time_ns()}
        process["scale_write_private"](root / "stop-request.json", request)
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            path = root / "stop-acknowledgment.json"
            if path.exists():
                reply = json.loads(process["scale_private_bytes"](path, 65536))
                if reply["original"] != request or reply["terminal"]["pid"] != original["issuerPid"] or reply["terminal"]["startTicks"] != original["issuerStartTicks"] or reply["terminal"]["exitCode"] != 0:
                    raise ValueError("Native stop acknowledgment belongs to another original or failed process")
                return reply["terminal"]
            await asyncio.sleep(0.05)
        raise ValueError("actual scoped issuer stop has no acknowledgment; no retry or guessed drain")

    arguments = {name: selected[name] for name in ("run_id", "source_digest", "workers", "cohort_digests")}
    arguments["key"] = process["scale_private_bytes"](selected["keyFile"], 65536)
    arguments.update(output_root=str(root / "waves"), stop_issuer=stop_issuer)
    owner_waits, cpu_waves = [], []
    actual_wave = workload["run_scale_wave"]

    async def sample_cpu(wave, phase, offered_digest):
        sequence = len(cpu_waves) * 2 + (phase == "end")
        if sequence >= 32:
            raise ValueError("CPU handshake count exceeds its fixed bound")
        request = {**original, "sequence": sequence, "phase": phase, "wave": wave,
            "waveOriginalsSha256": offered_digest, "issuerProcessSha256": selected["issuerProcessSha256"],
            "nonce": secrets.token_hex(16), "requestedUnixNs": time.time_ns()}
        process["scale_publish_private"](root / f"cpu-request-{sequence:02}.json", request)
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            path = root / f"cpu-ack-{sequence:02}.json"
            if path.exists():
                reply = json.loads(process["scale_private_bytes"](path, 65536))
                if set(reply) != {"original", "sample"} or reply["original"] != request:
                    raise ValueError("CPU acknowledgment substituted an original wave or process")
                return reply
            await asyncio.sleep(0.05)
        # A missing endpoint never retries, infers ticks or supplies a budget.
        return {"original": request, "sample": {"outcome": "unknown", "reason": "acknowledgment_absent"}}

    async def measured_wave(calls, key):
        if len(calls) != 4224 or len({row["original"]["nonce"] for row in calls}) != 4224:
            raise ValueError("CPU interval requires the complete offered wave")
        names = {row["wave"] for row in calls}
        if len(names) != 1:
            raise ValueError("CPU interval mixes offered waves")
        wave = next(iter(names))
        offered = [{"original": row["original"], "isolateLabel": row["worker"]["isolateLabel"],
            "offeredIndex": row["offeredIndex"], "wave": row["wave"]} for row in calls]
        digest = hashlib.sha256(_scale_runtime_json(offered)).hexdigest()
        start = await sample_cpu(wave, "start", digest)
        # Handshake time is excluded from the denominator. Its CPU can only
        # increase the conservative numerator, never dilute the offered load.
        resolution = math.ceil(time.get_clock_info('monotonic').resolution * 1_000_000_000)
        utc_start, mono_start = time.time_ns(), time.monotonic_ns()
        try:
            return await actual_wave(calls, key)
        finally:
            mono_end, utc_end = time.monotonic_ns(), time.time_ns()
            end = await sample_cpu(wave, "end", digest)
            cpu_waves.append({"wave": wave, "waveOriginalsSha256": digest, "start": start, "end": end,
                "workloadProcess": current, "startedUnixNs": utc_start, "completedUnixNs": utc_end,
                "monotonicStartNs": mono_start, "monotonicEndNs": mono_end,
                "monotonicResolutionNs": resolution})

    workload["run_scale_wave"] = measured_wave

    async def wait_for_owners(target):
        receipt = await wait_scale_owner_windows(selected, process, workload, target)
        owner_waits.append(receipt)

    if selected["capped"]:
        result = await workload["run_scale_cap"](**arguments)
    else:
        result = await workload["run_scale_profile"](**arguments, maximum_lifetime=selected["maximum_lifetime"],
            wait_until=wait_for_owners)
    result["actualOwnerWaits"] = owner_waits
    result["loadedCpuWaves"] = cpu_waves
    process["scale_write_private"](root / "result.json", result)


async def wait_scale_owner_windows(selected, process, workload, target):
    """Wait for actual token and immutable owner horizons, retaining their source."""
    contexts = [{"runId": selected["run_id"], "sourceDigest": selected["source_digest"],
        "isolateLabel": row["isolateLabel"], "configurationDigest": row["configurationDigest"],
        "cohortDigests": selected["cohort_digests"]} for row in selected["workers"]]
    source = selected["sources"]["joins"]
    body = process["scale_private_bytes"](source["path"], 128 * 1024)
    if hashlib.sha256(body).hexdigest() != source["sha256"]:
        raise ValueError("selected actual dispatch join source changed")
    namespace = {"__name__": "aos_scale_wait_joins"}
    exec(compile(body, source["path"], "exec"), namespace)
    collector_source = selected["sources"]["collector"]
    body = process["scale_private_bytes"](collector_source["path"], 128 * 1024)
    if hashlib.sha256(body).hexdigest() != collector_source["sha256"]:
        raise ValueError("selected collector source changed")
    collector = {"__name__": "aos_scale_wait_collector"}
    exec(compile(body, collector_source["path"], "exec"), collector)
    namespace.update({name: collector[name] for name in ("_closed_object", "_digest", "_unsigned")})
    texts, snapshots = [], []
    for owner in selected["workerProcesses"]:
        actual = process["scale_process_identity"](owner["pid"])
        if any(actual[name] != owner[name] for name in actual):
            raise ValueError("actual dispatch-log owner lifetime changed")
        path = Path(owner["logFile"])
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source_file:
            before = os.fstat(source_file.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 256 * 1024 * 1024):
                raise ValueError("actual current dispatch log exceeds bound")
            raw = source_file.read(before.st_size)
            source_file.seek(0)
            confirmed = source_file.read(before.st_size)
            after = os.fstat(source_file.fileno())
        current_file = path.stat(follow_symlinks=False)
        if raw != confirmed or len(raw) != before.st_size or any((row.st_dev, row.st_ino) != (before.st_dev, before.st_ino)
                for row in (after, current_file)) or not raw.endswith(b"\n"):
            raise ValueError("actual current dispatch prefix is incomplete or substituted")
        texts.append(raw.decode())
        snapshots.append({"file": str(path), "device": before.st_dev, "inode": before.st_ino,
            "prefixBytes": len(raw), "prefixSha256": hashlib.sha256(raw).hexdigest(),
            "pid": owner["pid"], "startTicks": owner["startTicks"]})
        if process["scale_process_identity"](owner["pid"]) != actual:
            raise ValueError("actual dispatch-log owner changed during prefix observation")
    events = namespace["scale_dispatch_events"]("\n".join(texts), contexts)
    identities = {(row["isolateLabel"], row["cohortDigest"]) for row in events}
    required = {(row["isolateLabel"], cohort) for row in selected["workers"] for cohort in selected["cohort_digests"]}
    if identities != required:
        raise ValueError("actual immutable owner coverage is incomplete; no estimated replacement boundary")
    latest = {}
    for event in events:
        identity = (event["isolateLabel"], event["cohortDigest"])
        old = latest.get(identity)
        if old is not None and event["issuedAt"] < old["expiresAt"]:
            raise ValueError("a new issuer original overlaps the retained owner window")
        latest[identity] = event
    boundary = max(target, max(row["expiresAt"] for row in latest.values()) + 1)
    started_ns = time.time_ns()
    await workload["wait_actual_utc"](boundary)
    receipt = {"requestedActualTokenBoundary": target, "actualOwnerBoundary": boundary,
        "ownerOriginals": list(latest.values()), "logSnapshots": snapshots,
        "startedUnixNs": started_ns, "completedUnixNs": time.time_ns(),
        "scope": "actual immutable issuer owner windows; no owner retry or clock qualification"}
    name = "wait-" + os.urandom(16).hex() + ".json"
    process["scale_write_private"](Path(selected["root"]) / name, receipt)
    return receipt


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise ValueError("expected one explicit private scale runtime configuration")
    # The supervisor independently pins this file and all source files before
    # spawn. They are read again here before running actual transport originals.
    selection_path = Path(sys.argv[1])
    raw = selection_path.read_bytes()
    if len(raw) > 65536:
        raise ValueError("scale runtime configuration exceeds its bound")
    selected = json.loads(raw)
    namespaces = {}
    for name in ("process", "workload"):
        reference = selected["sources"][name]
        body = Path(reference["path"]).read_bytes()
        if len(body) > 128 * 1024 or hashlib.sha256(body).hexdigest() != reference["sha256"]:
            raise ValueError("selected runtime fixture source changed")
        namespace = {"__name__": "aos_scale_guest_" + name, "__file__": reference["path"]}
        exec(compile(body, reference["path"], "exec"), namespace)
        namespaces[name] = namespace
    process = namespaces["process"]
    if process["scale_private_bytes"](selection_path, 65536) != raw:
        raise ValueError("private runtime configuration changed after source selection")
    asyncio.run(execute_scale_runtime(selected, process, namespaces["workload"]))
