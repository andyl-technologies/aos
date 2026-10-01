"""Prepare or dispatch one retained local SDK anchor original without replay.

This fixture requires the independently observed dedicated emulator namespace.
Its immutable original precedes the one-shot socket dispatch. Status reads only
retained files. No phase creates acceptance, deletes objects, or retries an
unknown effect. The namespace reader is an explicit adjacent source dependency.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time


spec = importlib.util.spec_from_file_location(
    "oci_namespace_reader", Path(__file__).with_name("_hub-oci-sdk-namespace.py"))
namespace_reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(namespace_reader)


def persist(path, body):
    """Create and sync a private receipt and its containing directory."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def json_bytes(value):
    """Serialize retained fixture bytes consistently without claiming a wire MAC."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def prepare(namespace_file, output_directory):
    """Retain a fresh bounded random original before any socket or SDK effect."""
    body = namespace_reader.bounded_file(namespace_file, 16384)
    observation = namespace_reader.closed_json(body)
    if (set(observation) != namespace_reader.FIELDS
            or observation["observationScope"] != "oci_sdk_emulator_namespace_readback"
            or not re.fullmatch(r"oci-sdk-qualification-[0-9a-f]{32}", observation["namespaceId"])):
        raise ValueError("anchor requires a dedicated observed local SDK namespace")
    parent = output_directory.parent
    metadata = parent.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077 or parent.resolve() != parent):
        raise ValueError("anchor original parent custody differs")
    output_directory.mkdir(mode=0o700)
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    payload = os.urandom(256)
    now = int(time.time())
    original = {"version": 1, "runId": os.urandom(16).hex(), "issuedAt": str(now),
        "expiresAt": str(now + 30), "namespaceObservationBase64": base64.b64encode(body).decode(),
        "namespaceObservationSha256": hashlib.sha256(body).hexdigest(),
        "payloadBase64": base64.b64encode(payload).decode(),
        "payloadSha256": hashlib.sha256(payload).hexdigest(), "payloadByteSize": str(len(payload))}
    original_bytes = json_bytes(original)
    persist(output_directory / "original.json", original_bytes)
    request = {"version": 1, "kind": "oci-sdk-anchor-create",
        "originalBase64": base64.b64encode(original_bytes).decode(),
        "originalSha256": hashlib.sha256(original_bytes).hexdigest()}
    persist(output_directory / "request.json", json_bytes(request))
    return {"version": 1, "status": "prepared", "runId": original["runId"],
            "originalSha256": request["originalSha256"]}


def validated_original(body):
    """Check the exact original and its embedded bytes before socket dispatch."""
    original = namespace_reader.closed_json(body)
    fields = {"version", "runId", "issuedAt", "expiresAt", "namespaceObservationBase64",
        "namespaceObservationSha256", "payloadBase64", "payloadSha256", "payloadByteSize"}
    if (body != json_bytes(original) or set(original) != fields or type(original["version"]) is not int
            or original["version"] != 1 or not isinstance(original["runId"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", original["runId"])
            or any(not isinstance(original[field], str)
                or not re.fullmatch(r"[1-9][0-9]{0,11}", original[field])
                for field in ("issuedAt", "expiresAt", "payloadByteSize"))
            or not 0 < int(original["expiresAt"]) - int(original["issuedAt"]) <= 30):
        raise ValueError("anchor original schema differs")
    for label, limit in (("namespaceObservation", 16384), ("payload", 1024)):
        encoded, digest = original[label + "Base64"], original[label + "Sha256"]
        if (not isinstance(encoded, str) or len(encoded) > ((limit + 2) // 3) * 4
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("anchor original embedded encoding differs")
        decoded = base64.b64decode(encoded, validate=True)
        if (not decoded or len(decoded) > limit or base64.b64encode(decoded).decode() != encoded
                or hashlib.sha256(decoded).hexdigest() != digest):
            raise ValueError("anchor original embedded bytes differ")
        if label == "payload" and original["payloadByteSize"] != str(len(decoded)):
            raise ValueError("anchor original size differs")
        if label == "namespaceObservation":
            observation = namespace_reader.closed_json(decoded)
    if (set(observation) != namespace_reader.FIELDS
            or observation["observationScope"] != "oci_sdk_emulator_namespace_readback"
            or not re.fullmatch(r"oci-sdk-qualification-[0-9a-f]{32}", observation["namespaceId"])):
        raise ValueError("anchor original dedicated namespace differs")
    return original, observation


def dispatch(original_directory, socket_file, node_file):
    """Send one exact original to its pinned runner and never automatically resend."""
    original_bytes = namespace_reader.bounded_file(original_directory / "original.json", 32768)
    original, observation = validated_original(original_bytes)
    request_bytes = namespace_reader.bounded_file(original_directory / "request.json", 65536)
    request = namespace_reader.closed_json(request_bytes)
    if (request != {"version": 1, "kind": "oci-sdk-anchor-create",
            "originalBase64": base64.b64encode(original_bytes).decode(),
            "originalSha256": hashlib.sha256(original_bytes).hexdigest()}
            or not int(original["issuedAt"]) <= int(time.time()) < int(original["expiresAt"])):
        raise ValueError("anchor original changed or expired before dispatch")
    runner = namespace_reader.process_identity(observation["runnerPid"], node_file)
    if runner["startTicks"] != observation["runnerStartTicks"]:
        raise ValueError("anchor runner lifetime changed")
    metadata = socket_file.lstat()
    if (not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise ValueError("anchor socket custody differs")
    # This create-new dispatch original is permanent even if connection or
    # reply capture fails. A second dispatch invocation refuses before send.
    persist(original_directory / "dispatch-intent.json", json_bytes({
        "version": 1, "requestSha256": hashlib.sha256(request_bytes).hexdigest(),
        "runnerPid": runner["pid"], "runnerStartTicks": runner["startTicks"],
        "observedAtUnixSeconds": str(int(time.time()))}))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(15)
        peer.connect(str(socket_file))
        pid, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != runner["pid"] or uid != runner["ownerUid"]:
            raise ValueError("anchor peer differs")
        if not int(original["issuedAt"]) <= int(time.time()) < int(original["expiresAt"]):
            raise ValueError("anchor original expired before send; retain dispatch intent")
        peer.sendall(request_bytes)
        peer.shutdown(socket.SHUT_WR)
        response = bytearray()
        while block := peer.recv(4096):
            response.extend(block)
            if len(response) > 16384:
                raise ValueError("anchor response exceeds its bound")
    persist(original_directory / "response.json", response)
    if not int(original["issuedAt"]) <= int(time.time()) < int(original["expiresAt"]):
        raise ValueError("anchor reply arrived after expiry; retain captured response")
    result = namespace_reader.closed_json(response)
    if (runner != namespace_reader.process_identity(runner["pid"], node_file)
            or result.get("originalSha256") != request["originalSha256"]
            or result.get("runId") != original["runId"]):
        raise ValueError("anchor receipt identity differs; retain original")
    if result.get("status") != "observed":
        raise ValueError("anchor has no complete positive receipt; retain original")
    if (set(result) != {"version", "status", "anchor", "runId", "originalSha256",
            "namespaceObservationSha256", "completedAt", "sdkInvocations"}
            or type(result["version"]) is not int or result["version"] != 1
            or result["sdkInvocations"] != {"put": 1, "get": 1}
            or any(type(value) is not int for value in result["sdkInvocations"].values())
            or not isinstance(result["completedAt"], str)
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z",
                result["completedAt"])):
        raise ValueError("anchor positive receipt scope differs")
    completed = namespace_reader.datetime.fromisoformat(result["completedAt"].replace("Z", "+00:00"))
    if not int(original["issuedAt"]) <= completed.timestamp() < int(original["expiresAt"]):
        raise ValueError("anchor positive completed outside the original interval")
    anchor = result["anchor"]
    key = ".aos-oci-sdk-qualification/" + original["runId"] + "/anchor"
    if (set(anchor) != {"object", "sha256"}
            or set(anchor["object"]) != {"key", "provider_version", "etag", "size"}
            or anchor["object"]["key"] != key
            or not re.fullmatch(r"[0-9a-f]{32}", anchor["object"]["provider_version"])
            or not re.fullmatch(r'"[0-9a-f]{32}"', anchor["object"]["etag"])
            or type(anchor["object"]["size"]) is not int
            or anchor["object"]["size"] != int(original["payloadByteSize"])
            or anchor["sha256"] != original["payloadSha256"]
            or result["namespaceObservationSha256"] != original["namespaceObservationSha256"]):
        raise ValueError("anchor positive receipt differs from exact retained bytes")
    persist(original_directory / "anchor.json", json_bytes(anchor))
    return {"version": 1, "status": "observed", "runId": original["runId"],
            "anchorSha256": hashlib.sha256(json_bytes(anchor)).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="phase", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--namespace-observation-file", type=Path, required=True)
    prepare_parser.add_argument("--output-directory", type=Path, required=True)
    dispatch_parser = commands.add_parser("dispatch")
    dispatch_parser.add_argument("--original-directory", type=Path, required=True)
    dispatch_parser.add_argument("--socket-file", type=Path, required=True)
    dispatch_parser.add_argument("--node-file", type=Path, required=True)
    status_parser = commands.add_parser("status")
    status_parser.add_argument("--original-directory", type=Path, required=True)
    options = parser.parse_args()
    if options.phase == "prepare":
        result = prepare(options.namespace_observation_file, options.output_directory)
    elif options.phase == "dispatch":
        result = dispatch(options.original_directory, options.socket_file, options.node_file)
    else:
        result = {"version": 1, "scope": "retained_files_only",
            "files": {name: hashlib.sha256(namespace_reader.bounded_file(
                options.original_directory / name, 65536)).hexdigest()
                for name in ("original.json", "request.json", "dispatch-intent.json", "response.json", "anchor.json")
                if (options.original_directory / name).exists()}}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise SystemExit("local OCI SDK anchor fixture refused; retain originals") from None
