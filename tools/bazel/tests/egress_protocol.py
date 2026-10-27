"""Exercises installed egress processes with independently authenticated requests."""

import base64
from contextlib import contextmanager
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import time


CONTRACT = "aos-hardened-egress-v3"
CURRENT_KEY = bytes([7]) * 32
NEXT_KEY = bytes([9]) * 32


def field(value):
    encoded = value.encode()
    return struct.pack(">Q", len(encoded)) + encoded


def signature(key, domain, timestamp, nonce):
    message = domain + struct.pack(">q", timestamp) + field(nonce)
    return base64.urlsafe_b64encode(hmac.digest(key, message, "sha256")).decode().rstrip("=")


def challenge(key=CURRENT_KEY, key_id="current", timestamp=None, nonce=None):
    timestamp = int(time.time()) if timestamp is None else timestamp
    nonce = secrets.token_urlsafe(32) if nonce is None else nonce
    return {
        "x-aos-egress-contract": CONTRACT,
        "x-aos-egress-key-id": key_id,
        "x-aos-egress-timestamp": str(timestamp),
        "x-aos-egress-nonce": nonce,
        "x-aos-egress-signature": signature(
            key, b"aos-hardened-egress-challenge-v3\0", timestamp, nonce,
        ),
    }


def request(port, method, path, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


@contextmanager
def gateway(binary, directory):
    """Starts one installed executable with real persistent SQLite state."""
    port = free_port()
    arguments = [
        str(binary), "--listen", f"127.0.0.1:{port}",
        "--gateway-key-file", str(directory / "current.key"), "--key-id", "current",
        "--next-key-file", str(directory / "next.key"), "--next-key-id", "next",
        "--nonce-database-url", "sqlite://" + str(directory / "nonce.sqlite"),
    ]
    environment = {key: value for key, value in os.environ.items() if not key.startswith("HUB_EGRESS_")}
    with (directory / "process.log").open("ab") as log:
        process = subprocess.Popen(arguments, stdout=log, stderr=log, env=environment)
        try:
            deadline = time.monotonic() + 30
            while True:
                if process.poll() is not None:
                    raise ValueError("installed egress exited before readiness: " + (directory / "process.log").read_text())
                try:
                    status, _, body = request(port, "GET", "/healthz")
                    if status == 204 and not body:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                if time.monotonic() >= deadline:
                    raise ValueError("installed egress did not become ready")
                time.sleep(0.05)
            yield port
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def accepted_challenge(port, headers, key):
    status, returned, body = request(port, "POST", "/v1/challenge", headers)
    if status != 204 or body:
        raise ValueError("installed egress rejected an authenticated challenge")
    if (returned.get("x-aos-egress-contract") != CONTRACT
            or returned.get("x-aos-egress-key-id") != headers["x-aos-egress-key-id"]
            or returned.get("x-aos-egress-nonce") != headers["x-aos-egress-nonce"]
            or returned.get("cache-control") != "no-store"):
        raise ValueError("installed egress changed its authenticated response envelope")
    timestamp = int(returned["x-aos-egress-timestamp"])
    if abs(timestamp - int(time.time())) > 5:
        raise ValueError("installed egress returned a stale response timestamp")
    expected = signature(
        key, b"aos-hardened-egress-challenge-response-v3\0",
        timestamp, headers["x-aos-egress-nonce"],
    )
    if not hmac.compare_digest(returned.get("x-aos-egress-signature", ""), expected):
        raise ValueError("installed egress response signature failed independent verification")
    return status


def rejected_challenge(port, headers):
    status, returned, body = request(port, "POST", "/v1/challenge", headers)
    if (status != 401 or returned.get("cache-control") != "no-store"
            or body != b"hardened egress request rejected"):
        raise ValueError("installed egress accepted invalid or replayed challenge evidence")
    return status


def qualify(packages):
    """Requires key overlap, independent MAC verification and durable replay rejection."""
    if set(packages) != {"ordinary", "bazel"}:
        raise ValueError("egress qualification requires both installed package roots")
    records = {}
    for driver, outputs in packages.items():
        binary = Path(outputs["out"]) / "bin/aos-hub-egress"
        with tempfile.TemporaryDirectory(prefix="hub-installed-egress-") as temporary:
            directory = Path(temporary)
            for name, key in [("current", CURRENT_KEY), ("next", NEXT_KEY)]:
                path = directory / (name + ".key")
                path.write_bytes(key)
                path.chmod(0o600)
            cases = {}
            with gateway(binary, directory) as port:
                cases["health"] = request(port, "GET", "/healthz")[0]
                cases["missing_evidence"] = rejected_challenge(port, {})
                nonce = secrets.token_urlsafe(32)
                now = int(time.time())
                cases["wrong_key"] = rejected_challenge(port, challenge(bytes([8]) * 32, nonce=nonce))
                cases["stale"] = rejected_challenge(port, challenge(timestamp=now - 120, nonce=nonce))
                cases["future"] = rejected_challenge(port, challenge(timestamp=now + 120, nonce=nonce))
                cases["unknown_key"] = rejected_challenge(port, challenge(key_id="retired", nonce=nonce))
                replay = challenge(nonce=nonce)
                cases["current_key_independent_response_mac"] = accepted_challenge(port, replay, CURRENT_KEY)
                cases["same_process_replay"] = rejected_challenge(port, replay)
                cases["overlap_key_independent_response_mac"] = accepted_challenge(
                    port, challenge(NEXT_KEY, "next"), NEXT_KEY,
                )
                status, returned, body = request(port, "POST", "/v1/fetch")
                if status != 502 or returned.get("cache-control") != "no-store" or body != b"hardened egress request rejected":
                    raise ValueError("installed egress accepted an unauthenticated upstream request")
                cases["unauthenticated_fetch"] = status
            if not (directory / "nonce.sqlite").is_file():
                raise ValueError("installed egress omitted its durable nonce database")
            with gateway(binary, directory) as port:
                # Reject an inconclusive run: stale evidence would also return
                # 401 and would not prove that the nonce survived the restart.
                if not 0 <= int(time.time()) - int(replay["x-aos-egress-timestamp"]) <= 30:
                    raise ValueError("restart replay evidence is outside the fresh proof window")
                cases["replay_after_process_restart"] = rejected_challenge(port, replay)
                cases["fresh_after_process_restart"] = accepted_challenge(port, challenge(), CURRENT_KEY)
            records[driver] = cases
    if len({json.dumps(cases, sort_keys=True) for cases in records.values()}) != 1:
        raise ValueError("installed egress processes differ in protocol behavior")
    return records


if __name__ == "__main__":
    import sys

    packages = json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps(qualify(packages), indent=2, sort_keys=True))
