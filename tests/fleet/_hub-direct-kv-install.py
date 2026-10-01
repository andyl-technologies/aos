"""Install a selected signed artifact through the live emulator's private KV API.

The receipt records exact bytes and the observed runner lifetime. The Worker
still verifies independent acceptance against its real source and typed profile.
An unknown transport outcome remains unknown and must be inspected separately.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct


def private_file(path, maximum_bytes):
    """Read a bounded stable input under the fixture operator's custody."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_mode & 0o077 or before.st_nlink != 1
            or before.st_size > maximum_bytes
        ):
            raise ValueError("installation input custody or bounds differ")
        body = source.read(maximum_bytes + 1)
        after = os.fstat(source.fileno())
    identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(body) > maximum_bytes or any(
        getattr(before, field) != getattr(after, field) for field in identity
    ):
        raise ValueError("installation input changed during observation")
    return body


def runner_lifetime(pid):
    """Read the actual process start tick, independently of the control receipt."""
    text = (Path("/proc") / str(pid) / "stat").read_text()
    prefix, separator, tail = text.rpartition(") ")
    if not separator or not prefix.startswith(f"{pid} ("):
        raise ValueError("runner process identity is unavailable")
    return tail.split()[19]


def retain(directory, name, observation):
    """Write a new durable observation without overwriting an earlier outcome."""
    descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(json.dumps(observation, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())


def install(options):
    """Record one explicit installation attempt against the exact live runner."""
    artifact = private_file(options.artifact_file, 64 * 1024)
    key = private_file(options.registry_key_file, 1024).decode().strip()
    if not re.fullmatch(
        r"aos\.direct-upload\.acceptance\.v1/[A-Za-z0-9_.:-]+/[0-9a-f]{64}/emulated-[0-9a-f]{64}",
        key,
    ):
        raise ValueError("shared acceptance registry key differs")
    pid_text = private_file(options.runner_pid_file, 32).decode().strip()
    if not re.fullmatch(r"[1-9][0-9]{0,9}", pid_text):
        raise ValueError("runner process identifier differs")
    pid = int(pid_text)
    lifetime = runner_lifetime(pid)
    socket_identity = options.socket_file.lstat()
    if (
        not stat.S_ISSOCK(socket_identity.st_mode)
        or socket_identity.st_uid != os.getuid() or socket_identity.st_mode & 0o077
    ):
        raise ValueError("acceptance control socket is not owner-private")
    options.output_directory.mkdir(mode=0o700)
    observation = {
        "version": 1, "key": key,
        "artifactSha256": hashlib.sha256(artifact).hexdigest(),
        "byteSize": str(len(artifact)), "runnerPid": pid,
        "runnerStartTicks": lifetime, "status": "pending",
    }
    retain(options.output_directory, "pending.json", observation)
    request = json.dumps({
        "version": 1, "key": key,
        "artifactBase64": base64.b64encode(artifact).decode(),
        "artifactSha256": observation["artifactSha256"],
    }).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(15)
            peer.connect(str(options.socket_file))
            peer_pid, peer_uid, _ = struct.unpack(
                "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
            )
            if peer_pid != pid or peer_uid != os.getuid() or runner_lifetime(pid) != lifetime:
                raise ValueError("actual acceptance control peer differs from runner")
            peer.sendall(request)
            peer.shutdown(socket.SHUT_WR)
            chunks = []
            byte_size = 0
            while block := peer.recv(4096):
                byte_size += len(block)
                if byte_size > 4096:
                    raise ValueError("acceptance control receipt exceeds bound")
                chunks.append(block)
        receipt = json.loads(b"".join(chunks))
        if receipt == {"version": 1, "status": "refused"}:
            observation["status"] = "refused"
        elif receipt == {
            "version": 1, "status": "installed", "key": key,
            "artifactSha256": observation["artifactSha256"],
            "byteSize": observation["byteSize"], "runnerPid": pid,
        } and runner_lifetime(pid) == lifetime:
            observation["status"] = "installed"
        else:
            raise ValueError("acceptance control receipt differs from selected bytes")
    except (OSError, ValueError, KeyError, IndexError):
        observation["status"] = "unknown"
    retain(options.output_directory, "outcome.json", observation)
    print(json.dumps(observation, sort_keys=True))
    if observation["status"] != "installed":
        raise RuntimeError("selected acceptance installation has no positive receipt")


def main():
    """Run the explicitly selected artifact installation once."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("socket-file", "artifact-file", "registry-key-file", "runner-pid-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    install(parser.parse_args())


if __name__ == "__main__":
    main()
