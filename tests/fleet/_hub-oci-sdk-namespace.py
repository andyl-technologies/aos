"""Observe a selected local R2 SDK attachment through its live runner peer.

The receipt joins installed inputs and process lifetimes to a version-pinned
namespace readback. It performs no object SDK operation, authenticates no
acceptance artifact, and establishes no Hosted R2 or general Direct capability.
A separately reviewed positive namespace anchor remains mandatory.
"""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct


FIELDS = frozenset((
    "version", "observationScope", "observedAt", "runnerPid", "runnerStartTicks",
    "configurationSha256", "runnerSha256", "miniflareVersion", "miniflareModuleSha256",
    "miniflareEntryWorkerSha256", "miniflareBucketWorkerSha256", "shimSha256",
    "wasmSha256", "wasmByteSize", "sourceStorePath", "buildDerivedSourceDigest",
    "buildDerivedScriptVersion", "workerName", "bindingName", "namespaceId",
    "namespaceUniqueKey", "namespaceObjectId", "persistenceRoot", "workerdPid",
    "workerdStartTicks", "workerdExecutableSha256",
))


def closed_json(body):
    """Reject duplicate fields before selecting a closed observation shape."""
    def pairs(entries):
        result = {}
        for name, value in entries:
            if name in result:
                raise ValueError("duplicate observation field")
            result[name] = value
        return result

    return json.loads(body, object_pairs_hook=pairs)


def bounded_file(path, maximum):
    """Read an owned private regular selection without following a symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077):
            raise ValueError("selection custody differs")
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    if (len(body) > maximum or len(body) != before.st_size
            or any(getattr(before, field) != getattr(after, field)
                   for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
        raise ValueError("selection changed or exceeds its bound")
    return body


def hash_file(path, maximum, *, follow_link=False):
    """Stream stable installation bytes with bounded memory."""
    flags = os.O_RDONLY | os.O_NONBLOCK | (0 if follow_link else os.O_NOFOLLOW)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("installed file exceeds its bound")
        digest, count = hashlib.sha256(), 0
        while block := source.read(1024 * 1024):
            count += len(block)
            if count > maximum:
                raise ValueError("installed file grew beyond its bound")
            digest.update(block)
        after = os.fstat(source.fileno())
    if (count != before.st_size or any(getattr(before, field) != getattr(after, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
        raise ValueError("installed file changed")
    return digest.hexdigest(), str(count)


def process_identity(pid, executable):
    """Bind one live owned process to its exact selected executable."""
    directory = Path("/proc") / str(pid)
    with (directory / "stat").open("rb") as source:
        raw = source.read(8193)
    if len(raw) > 8192:
        raise ValueError("process stat exceeds its bound")
    fields = raw.decode().rpartition(") ")[2].split()
    actual_executable = (directory / "exe").resolve(strict=True)
    if (len(fields) < 20 or fields[0] == "Z" or directory.stat().st_uid != os.getuid()
            or actual_executable != executable.resolve(strict=True)):
        raise ValueError("process executable or owner differs")
    return {"pid": pid, "startTicks": fields[19], "parentPid": int(fields[1]),
            "ownerUid": directory.stat().st_uid, "executable": str(actual_executable)}


def validate_readback(actual, selected, identity, runner, workerd, observed_files):
    """Check the exact closed schema and all independently selected joins."""
    if not isinstance(actual, dict) or set(actual) != FIELDS:
        raise ValueError("namespace readback fields differ")
    if (type(actual["version"]) is not int or actual["version"] != 1
            or actual["observationScope"] != "oci_sdk_emulator_namespace_readback"
            or actual["miniflareVersion"] != "5.20260801.0-alpha"
            or actual["bindingName"] != "REGISTRY_BUCKET"
            or actual["namespaceUniqueKey"] != "miniflare-R2BucketObject"):
        raise ValueError("namespace readback purpose differs")
    for name, value in actual.items():
        if name.endswith("Sha256") and (not isinstance(value, str)
                or not re.fullmatch(r"[0-9a-f]{64}", value)):
            raise ValueError("namespace digest spelling differs")
    for name in ("namespaceObjectId", "buildDerivedSourceDigest"):
        if not isinstance(actual[name], str) or not re.fullmatch(r"[0-9a-f]{64}", actual[name]):
            raise ValueError("namespace identity spelling differs")
    for name in ("workerName", "namespaceId"):
        if not isinstance(actual[name], str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", actual[name]):
            raise ValueError("namespace name exceeds its bound")
    for name in ("runnerStartTicks", "workerdStartTicks", "wasmByteSize"):
        if not isinstance(actual[name], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", actual[name]):
            raise ValueError("namespace count spelling differs")
    for name in ("runnerPid", "workerdPid"):
        if type(actual[name]) is not int or not 0 < actual[name] < 2**31:
            raise ValueError("namespace process spelling differs")
    if not isinstance(actual["observedAt"], str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", actual["observedAt"]):
        raise ValueError("namespace completion spelling differs")
    observed_at = datetime.fromisoformat(actual["observedAt"])
    if observed_at.utcoffset() is None or observed_at.utcoffset().total_seconds() != 0:
        raise ValueError("namespace completion lacks an actual UTC observation")
    expected_source = hashlib.sha256(os.fsencode(selected["sourceStorePath"])).hexdigest()
    if (actual["sourceStorePath"] != selected["sourceStorePath"]
            or actual["buildDerivedSourceDigest"] != expected_source
            or actual["buildDerivedScriptVersion"] != "emulated-" + expected_source
            or identity != {"sourceDigest": expected_source, "scriptVersion": "emulated-" + expected_source}):
        raise ValueError("namespace source differs from independently selected Worker identity")
    configuration = closed_json(selected["configurationBytes"])
    bucket = configuration["r2Buckets"]["REGISTRY_BUCKET"]
    expected_namespace = bucket if isinstance(bucket, str) else bucket.get("id")
    if (not isinstance(bucket, str) and set(bucket) != {"id"}
            or actual["namespaceId"] != expected_namespace
            or actual["workerName"] != configuration["name"]
            or actual["persistenceRoot"] != str(Path(configuration["resourcePersistencePath"]) / "r2")
            or configuration["scriptPath"] != selected["shimFile"]):
        raise ValueError("namespace configuration differs")
    for prefix, pin in (("runner", runner), ("workerd", workerd)):
        if (actual[prefix + "Pid"] != pin["pid"]
                or actual[prefix + "StartTicks"] != pin["startTicks"]):
            raise ValueError("namespace process lifetime differs")
    if workerd["parentPid"] != runner["pid"]:
        raise ValueError("runtime is not the selected runner child")
    for name, digest in observed_files.items():
        if actual[name] != digest:
            raise ValueError("namespace installed bytes differ")
    return actual


def read_socket_reply(socket_file, runner):
    """Check the actual owner-private socket peer before a bounded readback."""
    socket_stat = socket_file.lstat()
    if (not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != os.getuid()
            or stat.S_IMODE(socket_stat.st_mode) != 0o600):
        raise ValueError("namespace socket custody differs")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(15)
        peer.connect(str(socket_file))
        pid, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != runner["pid"] or uid != runner["ownerUid"]:
            raise ValueError("namespace peer differs from selected runner")
        peer.sendall(b'{"version":1,"kind":"oci-sdk-namespace-readback"}')
        peer.shutdown(socket.SHUT_WR)
        response = bytearray()
        while block := peer.recv(4096):
            response.extend(block)
            if len(response) > 16384:
                raise ValueError("namespace reply exceeds its bound")
    return closed_json(response)


def observe(options):
    """Join an owner-private socket reply to actual process and artifact bytes."""
    configuration_bytes = bounded_file(options.configuration_file, 1024 * 1024)
    identity = closed_json(bounded_file(options.identity_file, 256 * 1024))
    configuration = closed_json(configuration_bytes)
    installed = configuration.get("ociSdkNamespaceObservation")
    if installed != {"sourceStorePath": str(options.source_store_path),
                     "wasmPath": str(options.wasm_file), "workerdPath": str(options.workerd_file)}:
        raise ValueError("runner installed observation inputs differ")
    runner = process_identity(options.runner_pid, options.node_file)
    if runner["startTicks"] != options.runner_start_ticks:
        raise ValueError("selected runner lifetime differs")
    with (Path("/proc") / str(options.runner_pid) / "cmdline").open("rb") as source:
        command = source.read(65537)
    expected_command = [str(options.node_file), str(options.runner_file),
                        str(options.miniflare_root), str(options.configuration_file)]
    if len(command) > 65536 or command.split(b"\x00")[:-1] != [os.fsencode(value) for value in expected_command]:
        raise ValueError("runner command differs from selected immutable inputs")
    actual = read_socket_reply(options.socket_file, runner)
    workerd = process_identity(actual["workerdPid"], options.workerd_file)
    observed_files = {"configurationSha256": hashlib.sha256(configuration_bytes).hexdigest()}
    for name, path, maximum in (
        ("runnerSha256", options.runner_file, 1024 * 1024),
        ("shimSha256", options.shim_file, 2 * 1024 * 1024),
        ("wasmSha256", options.wasm_file, 64 * 1024 * 1024),
        ("workerdExecutableSha256", Path("/proc") / str(workerd["pid"]) / "exe", 512 * 1024 * 1024),
    ):
        digest, size = hash_file(path, maximum, follow_link=name == "workerdExecutableSha256")
        observed_files[name] = digest
        if name == "wasmSha256":
            observed_files["wasmByteSize"] = size
    expected_runtime_sha = hash_file(options.workerd_file,
        512 * 1024 * 1024, follow_link=True)[0]
    if observed_files["workerdExecutableSha256"] != expected_runtime_sha:
        raise ValueError("live runtime bytes differ from selected installation")
    module_root = options.miniflare_root / "lib/node_modules/wrangler/node_modules/miniflare/dist/src"
    for name, relative in (("miniflareModuleSha256", "index.js"),
            ("miniflareEntryWorkerSha256", "workers/shared/object-entry.worker.js"),
            ("miniflareBucketWorkerSha256", "workers/r2/bucket.worker.js")):
        observed_files[name] = hash_file(module_root / relative, 8 * 1024 * 1024)[0]
    selected = {"configurationBytes": configuration_bytes, "sourceStorePath": str(options.source_store_path),
                "shimFile": str(options.shim_file)}
    validate_readback(actual, selected, identity, runner, workerd, observed_files)
    if (runner != process_identity(options.runner_pid, options.node_file)
            or workerd != process_identity(workerd["pid"], options.workerd_file)
            or bounded_file(options.configuration_file, 1024 * 1024) != configuration_bytes):
        raise ValueError("namespace inputs changed during independent observation")
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-pid", type=int, required=True)
    parser.add_argument("--runner-start-ticks", required=True)
    for name in ("socket-file", "node-file", "runner-file", "workerd-file", "configuration-file",
                 "source-store-path", "miniflare-root", "identity-file", "wasm-file", "shim-file", "report-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    actual = observe(options)
    parent = options.report_file.parent
    metadata = parent.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077 or parent.resolve() != parent):
        raise ValueError("namespace report parent is not owner-private")
    descriptor = os.open(options.report_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(actual, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    print("Local OCI SDK namespace observation retained")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise SystemExit("local OCI SDK namespace observation refused") from None
