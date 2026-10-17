"""Stage exact independently verified OCI-only artifact bytes in dedicated local KV.

This client authenticates the owner-private runner peer and retains the original
before dispatch. The runner performs typed byte staging/readback only; the
shared Rust verifier runs before and after. Actual Worker consumption remains a
separate business gate. No provider SDK action or other acceptance slot is used.
"""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess


ARTIFACT_MAXIMUM = 32768
REPLY_FIELDS = frozenset(("version", "status", "key", "artifactSha256", "byteSize",
                          "runnerPid", "runnerStartTicks", "artifactBase64"))


def closed_json(body):
    def pairs(entries):
        value = {}
        for name, item in entries:
            if name in value:
                raise ValueError("duplicate control field")
            value[name] = item
        return value
    return json.loads(body, object_pairs_hook=pairs)


def digest(body):
    return hashlib.sha256(body).hexdigest()


@contextmanager
def private_parent(path):
    """Hold no-follow ancestor descriptors and an owner-private final parent."""
    path = Path(path)
    if path.name in ("", ".", ".."):
        raise ValueError("private filename differs")
    parent = path.parent
    descriptor = os.open("/" if path.is_absolute() else ".",
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        def inspect(final=False):
            observed = os.fstat(descriptor)
            root_sticky = observed.st_uid == 0 and observed.st_mode & stat.S_ISVTX
            if (observed.st_uid not in (0, os.geteuid())
                    or (observed.st_mode & (0o077 if final else 0o022)
                        and (final or not root_sticky))):
                raise ValueError("private ancestor custody differs")
        inspect()
        for component in parent.parts:
            if component in ("/", "."):
                continue
            if component == "..":
                raise ValueError("private traversal differs")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            inspect()
        inspect(final=True)
        yield descriptor, path.name
    finally:
        os.close(descriptor)


def private_file(path, maximum):
    with private_parent(path) as (parent, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.geteuid())
                or before.st_mode & 0o077 or before.st_nlink != 1
                or before.st_size > maximum):
            raise ValueError("private file custody differs")
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    if (len(body) > maximum or len(body) != before.st_size
            or any(getattr(before, field) != getattr(after, field)
                   for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
        raise ValueError("private file changed or exceeds bound")
    return body


def write_new(path, body):
    with private_parent(path) as (parent, name):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as target:
            target.write(body)
            target.flush()
            os.fsync(target.fileno())
        os.fsync(parent)


def create_directory(path):
    with private_parent(path) as (parent, name):
        os.mkdir(name, mode=0o700, dir_fd=parent)
        os.fsync(parent)


def namespace_module():
    path = Path(__file__).with_name("_hub-oci-sdk-namespace.py")
    specification = importlib.util.spec_from_file_location("oci_namespace", path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def verifier_arguments(options, artifact):
    return [str(options.reviewer_tool), "oci-sdk-verify", "--artifact-file", str(artifact),
            "--reviewer-public-key-file", str(options.public_key_file),
            "--reviewer-key-id", options.reviewer_key_id,
            "--deployment-id", options.deployment_id, "--public-origin", options.public_origin,
            "--source-digest", options.source_digest, "--script-version", options.script_version]


def run_tool(arguments):
    # The selected source-built CLI emits one bounded digest/key line. Capture
    # output privately without printing diagnostic input values or changing env.
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=30, check=False)
    if result.returncode or len(result.stdout) > 256 or len(result.stderr) > 8192:
        raise ValueError("source-built OCI verifier refused")
    return result.stdout.decode("ascii").rstrip("\n")


def verify_reply(body, artifact, key, runner):
    """Check exact stored bytes and process original; return no permission proof."""
    reply = closed_json(body)
    if (not isinstance(reply, dict) or set(reply) != REPLY_FIELDS
            or type(reply["version"]) is not int or reply["version"] != 1
            or reply["status"] != "stored" or reply["key"] != key
            or reply["artifactSha256"] != digest(artifact)
            or reply["byteSize"] != str(len(artifact))
            or type(reply["runnerPid"]) is not int or reply["runnerPid"] != runner["pid"]
            or reply["runnerStartTicks"] != runner["startTicks"]):
        raise ValueError("OCI staged readback original differs")
    encoded = reply["artifactBase64"]
    if not isinstance(encoded, str) or len(encoded) > 4 * ((ARTIFACT_MAXIMUM + 2) // 3):
        raise ValueError("OCI staged readback exceeds bound")
    readback = base64.b64decode(encoded, validate=True)
    if readback != artifact or base64.b64encode(readback).decode() != encoded:
        raise ValueError("OCI staged readback bytes differ")
    return readback


class StagingExchangeError(ValueError):
    def __init__(self, partial):
        super().__init__("OCI staging exchange did not complete")
        self.partial = partial


def exchange(path, request, runner):
    """Authenticate one retained owned Unix peer before the exact bounded control."""
    with private_parent(path) as (parent, name):
        observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(observed.st_mode) or observed.st_uid != os.geteuid()
                or stat.S_IMODE(observed.st_mode) != 0o600):
            raise ValueError("OCI staging socket custody differs")
    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(10)
            peer.connect(str(path))
            pid, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid != runner["pid"] or uid != runner["ownerUid"]:
                raise ValueError("OCI staging peer differs")
            peer.sendall(request)
            peer.shutdown(socket.SHUT_WR)
            while block := peer.recv(4096):
                response.extend(block)
                if len(response) > 65536:
                    raise ValueError("OCI staged reply exceeds bound")
    except (OSError, ValueError) as error:
        raise StagingExchangeError(bytes(response)) from error
    return bytes(response)


def install(options):
    namespace = namespace_module()
    artifact = private_file(options.artifact_file, ARTIFACT_MAXIMUM)
    if digest(artifact) != options.artifact_sha256:
        raise ValueError("reviewed artifact changed")
    report = closed_json(private_file(options.namespace_report, 16384))
    if (not isinstance(report, dict) or set(report) != namespace.FIELDS
            or report["observationScope"] != "oci_sdk_emulator_namespace_readback"
            or report["buildDerivedSourceDigest"] != options.source_digest
            or report["buildDerivedScriptVersion"] != options.script_version):
        raise ValueError("OCI selected namespace/source differs")
    tool_hash, _ = namespace.hash_file(options.reviewer_tool, 512 * 1024 * 1024)
    if tool_hash != options.reviewer_tool_sha256:
        raise ValueError("selected verifier bytes differ")
    if run_tool(verifier_arguments(options, options.artifact_file)) != options.artifact_sha256:
        raise ValueError("source-built artifact verification differs")
    key = run_tool([str(options.reviewer_tool), "oci-sdk-registry-key",
                    "--deployment-id", options.deployment_id,
                    "--source-digest", options.source_digest,
                    "--script-version", options.script_version])
    if not re.fullmatch(r"oci-sdk-emulator-v1-[0-9a-f]{64}", key):
        raise ValueError("OCI registry slot malformed")
    runner = namespace.process_identity(report["runnerPid"], options.runner_executable)
    if runner["startTicks"] != report["runnerStartTicks"]:
        raise ValueError("OCI selected runner lifetime differs")
    request = json.dumps({"version": 1, "kind": "oci-sdk-acceptance-install",
                          "key": key, "artifactBase64": base64.b64encode(artifact).decode(),
                          "artifactSha256": options.artifact_sha256},
                         sort_keys=True, separators=(",", ":")).encode()
    create_directory(options.output_directory)
    write_new(options.output_directory / "request.json", request)
    # A lost/error reply leaves this exact original retained. Never retry it or
    # infer installation/SDK settlement from a process timeout or partial reply.
    try:
        response = exchange(options.socket_file, request, runner)
    except StagingExchangeError as error:
        write_new(options.output_directory / "response.partial", error.partial)
        raise
    write_new(options.output_directory / "response.json", response)
    readback = verify_reply(response, artifact, key, runner)
    if namespace.process_identity(runner["pid"], options.runner_executable) != runner:
        raise ValueError("OCI runner changed during staging")
    readback_file = options.output_directory / "readback.json"
    write_new(readback_file, readback)
    if run_tool(verifier_arguments(options, readback_file)) != options.artifact_sha256:
        raise ValueError("source-built readback verification differs")
    after_tool_hash, _ = namespace.hash_file(options.reviewer_tool, 512 * 1024 * 1024)
    if after_tool_hash != tool_hash:
        raise ValueError("selected verifier changed during staging")
    receipt = {"version": 1, "observationScope": "oci_sdk_kv_staging_and_readback",
               "key": key, "artifactSha256": options.artifact_sha256,
               "requestSha256": digest(request), "responseSha256": digest(response),
               "readbackSha256": digest(readback), "verifierSha256": tool_hash,
               "runnerPid": runner["pid"], "runnerStartTicks": runner["startTicks"]}
    write_new(options.output_directory / "receipt.json",
              json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("socket-file", "namespace-report", "runner-executable", "artifact-file",
                 "reviewer-tool", "public-key-file", "output-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("artifact-sha256", "reviewer-tool-sha256", "reviewer-key-id", "deployment-id",
                 "public-origin", "source-digest", "script-version"):
        parser.add_argument("--" + name, required=True)
    options = parser.parse_args()
    try:
        print(json.dumps(install(options), sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, TypeError):
        raise SystemExit("OCI SDK staging refused; preserve any retained original/reply") from None


if __name__ == "__main__":
    main()
