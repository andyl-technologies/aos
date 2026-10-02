"""Delegates native messages unchanged before an explicitly armed test barrier.

The selected immutable fixture retains the actual backend executable. Controls
are root-owned regular files beneath a protected runtime directory. The barrier
never invents handler results or alters the backend's invocation or response.
"""

import hashlib
import json
import os
import selectors
import stat
import subprocess
import sys
import time

ROOT = "/run/aos/native-handler-interception"
LIMIT = 16 * 1024 * 1024
CONTROL_LIMIT = 16384


def read_control(name):
    """Reads a bounded protected control without following a symbolic link."""
    try:
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("interception directory is not protected")
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError("interception control is not protected")
            contents = source.read(CONTROL_LIMIT + 1)
        if len(contents) > CONTROL_LIMIT:
            raise ValueError("interception control exceeds its bound")
        return json.loads(contents)
    finally:
        os.close(directory)


def delegate(payload, operation, timeout):
    """Captures bounded real backend bytes, leaving process cancellation external."""
    with subprocess.Popen([BACKEND, operation], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        process.stdin.write(payload)
        process.stdin.close()
        captured = bytearray()
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as poller:
            poller.register(process.stdout, selectors.EVENT_READ)
            while poller.get_map():
                if time.monotonic() >= deadline:
                    process.kill()
                    raise TimeoutError("native delegate exceeded its invocation budget")
                for key, _ in poller.select(0.05):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        poller.unregister(key.fileobj)
                        continue
                    captured.extend(chunk)
                    if len(captured) > LIMIT:
                        process.kill()
                        raise ValueError("native delegate response exceeds its bound")
        try:
            status = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            raise TimeoutError("native delegate exceeded its invocation budget") from error
    return status, bytes(captured)


def retain_capture(identity, response):
    """Durably records a real response digest before holding its transport."""
    receipt = dict(identity, schema="aos.qualification.native-handler-response",
                   responseSha256="sha256:" + hashlib.sha256(response).hexdigest(),
                   responseSize=len(response))
    temporary = ROOT + "/capture-" + str(os.getpid()) + ".json"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, ROOT + "/captured.json")


def main():
    """Runs one unchanged native exchange and an optional response barrier."""
    if len(sys.argv) != 2 or sys.argv[1] not in ("apply", "remove", "observe"):
        raise ValueError("expected a native handler operation")
    operation = sys.argv[1]
    payload = sys.stdin.buffer.read(LIMIT + 1)
    if len(payload) > LIMIT:
        raise ValueError("native invocation exceeds its bound")
    invocation = json.loads(payload)
    identity = {"effect": invocation["id"], "revision": invocation["revision"],
                "action": invocation["action"], "operation": operation}
    timeout = invocation["effect"]["timeout_ms"] / 1000
    if not 0 < timeout <= 86400:
        raise ValueError("invalid native invocation budget")
    armed = read_control("armed.json")
    if armed is not None and (set(armed) != set(identity) | {"schema"}
                              or armed["schema"] != "aos.qualification.native-handler-barrier"):
        raise ValueError("invalid response barrier control")
    status, response = delegate(payload, operation, timeout)
    if status != 0:
        sys.exit(status if 0 < status < 256 else 1)
    if armed == dict(identity, schema="aos.qualification.native-handler-barrier"):
        retain_capture(identity, response)
        deadline = time.monotonic() + timeout + 5
        while read_control("release.json") != armed:
            if time.monotonic() >= deadline:
                raise TimeoutError("qualification response barrier expired")
            time.sleep(0.05)
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
