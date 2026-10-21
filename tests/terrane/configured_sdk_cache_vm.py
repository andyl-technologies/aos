"""Checks actual configured CLI snapshots with separately recovered native caches."""

import fcntl
import os
import struct
import select
import subprocess
import sys
import time
import tomllib


PAYLOAD = b"independent configured SDK snapshot payload\n"


def manifest_payload():
    """Computes the supervisor's independent expected multi-chunk plaintext."""
    state = 7
    result = bytearray()
    for _ in range(2097153):
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        result.append(state & 255)
    return bytes(result)


def actor(driver, image, label, arguments, success=True):
    """Runs one fresh source-bound actor under the original supervisor's bounds."""
    command = ["setpriv", "--reuid", "840", "--regid", "840", "--groups", "844,845",
               "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
               "--no-new-privs", str(image / "bin" / arguments[0]), *map(str, arguments[1:])]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    output = [bytearray(), bytearray()]
    streams = {process.stdout: output[0], process.stderr: output[1]}
    deadline = min(driver.DEADLINE, time.monotonic() + 30)
    try:
        while streams:
            remaining = deadline - time.monotonic()
            driver.require(remaining > 0, "native SDK actor deadline: " + label)
            ready, _, _ = select.select(list(streams), [], [], remaining)
            driver.require(ready, "native SDK actor output timeout: " + label)
            for stream in ready:
                chunk = os.read(stream.fileno(), 4096)
                if chunk:
                    streams[stream].extend(chunk)
                    driver.require(len(streams[stream]) <= driver.MAX_OUTPUT,
                                   "native SDK actor output bound: " + label)
                else:
                    stream.close()
                    del streams[stream]
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        driver.stop(process)
        for suffix, data in zip(["stdout", "stderr"], output):
            (driver.ROOT / "proof-logs" / ("native-sdk-" + label + "." + suffix)).write_bytes(data)
            print(data.decode("utf-8", errors="replace"), end="", flush=True)

    driver.require(process.returncode == (0 if success else 1),
                   "native SDK actor exit status: " + label)
    return tuple(map(bytes, output))


def host_configuration(driver, refused=False, mode="never"):
    """Uses the same explicit one-second retirement/grace policy as reassembly controls."""
    root = driver.ROOT / "positive"
    text = f"""
[host_tier]
path = "{root}"
size_bytes = 67108864
reassembly = "{mode}"
[host_tier.publisher]
socket_path = "/run/terrane-initial-publisher/publisher.sock"
serve_uid = 840
publish_uid = 841
content_uid = 840
content_gid = 845
max_connections = 8
[host_tier.quota]
socket_path = "{root}/quota.sock"
configuration_epoch = "00000000000000000000000000000001"
"""
    for domain, directory in [("public", "public"), ("private:fixture", "private")]:
        owner = "not-enrolled" if refused else "fixture-" + directory
        text += f"""
[host_tier.domains."{domain}"]
path = "{root}/{directory}"
administrative_root = "{root}/{directory}-admin"
wipe = "none"
quota_owner_id = "{owner}"
[host_tier.domains."{domain}".publisher]
retirement_grace_ms = 1000
chunk_profile = "cdc-1m"
chunk_seed = "{"07" * 32}"
[host_tier.domains."{domain}".cache]
state_gid = 844
capacity_bytes = 25165824
low_watermark_bytes = 16777216
probation_bytes = 65536
release_grace_seconds = 1
scan_limit = 64
max_read_bytes = 2097152
state_bytes = 65536
state_records = 64
inventory_entries = 128
queued_commands = 4
metadata_sync_hold_bytes = 262144
publisher_wait_budget_ms = 10000
consumer_lease_seconds = 30
[host_tier.domains."{domain}".cache.portable]
max_file_bytes = 67108864
max_input_bytes = 268435456
max_files = 4096
max_selected_bytes = 33554432
[host_tier.domains."{domain}".cache.lower]
budget_ms = 10000
failure_threshold = 3
probe_interval_ms = 5000
"""
    return text


def cache_states(driver):
    """Reads actual durable native policy without treating it as a live grant."""
    result = {}
    for domain in ["public", "private"]:
        path = driver.ROOT / "positive" / domain / "state/cache/records.toml"
        result[domain] = path.read_bytes() if path.exists() else None
    return result


def verify_funding(driver, directory, before, after):
    """Distinguishes actual startup allowance from still-funded consumer grace."""
    owner = "fixture-" + directory
    reservations = after["reservations"]
    driver.require(len({row["id"] for row in reservations}) == len(reservations),
                   "native SDK repeats a reservation token")
    added = [row for row in reservations if row not in before["reservations"]]
    bootstraps = []
    for row in added:
        driver.require(row["owner"] == owner and row["bytes"] == 262144,
                       "native SDK changed a new hold's exact owner or funding")
        names = {"consumer:" + row["id"], "consumer-grace:" + row["id"]}
        leases = [lease for lease in after["leases"] if lease["owner"] in names]
        if not leases:
            bootstraps.append(row)
            continue
        driver.require(len(leases) == 1, "native SDK gives one consumer two lifecycle owners")
        lease = leases[0]
        driver.require(lease["owner"].startswith("consumer-grace:"),
                       "completed SDK still owns a live consumer grant")
        pins = [pin for pin in after["pins"] if pin["owner"] == lease["owner"]]
        driver.require(pins and all(pin["expires"] == lease["expires"]
                                   and len(pin["hash"]) == 64
                                   and all(char in "0123456789abcdef" for char in pin["hash"])
                                   for pin in pins),
                       "native SDK consumer hold lacks its exact durable pin closure")
    driver.require(len(bootstraps) == 1,
                   "native SDK lacks exactly one new bootstrap hold: " + repr(added))
    now = int(time.time())
    for row in before["reservations"]:
        if row in reservations:
            continue
        names = {"consumer:" + row["id"], "consumer-grace:" + row["id"]}
        leases = [lease for lease in before["leases"] if lease["owner"] in names]
        driver.require(len(leases) == 1 and row["owner"] == owner and row["bytes"] == 262144,
                       "native SDK dropped an original non-consumer hold")
        lease = leases[0]
        end = lease["expires"] + (1 if lease["owner"].startswith("consumer:") else 0)
        driver.require(end <= now,
                       "native SDK dropped consumer funding before its original grace expired")


def run(driver, image):
    """Requires real native startup and a closed failure before SDK presentation."""
    driver.require((image / "share/configured_sdk_proof.py").read_bytes()
                   == (driver.SOURCE / "tests/terrane/configured_sdk_proof.py").read_bytes(),
                   "native SDK launcher differs from bound source")
    subprocess.run([sys.executable, str(image / "share/configured_sdk_proof.py"),
                    "verify", str(image), str(driver.SOURCE)], check=True, timeout=30)
    parent = driver.ROOT / "configured-sdk"
    parent.mkdir(mode=0o700)
    os.chown(parent, 840, 840)

    large = manifest_payload()
    for name, refused, mode, payload in [
            ("inline", False, "never", PAYLOAD),
            ("never", False, "never", large),
            ("always", False, "always", large),
            ("profile", True, "never", PAYLOAD),
            ("refused", True, "never", PAYLOAD)]:
        root = parent / name
        setup = "setup-manifest" if payload == large else "setup"
        actor(driver, image, name + "-setup",
              ["configured-sdk-cache-example", setup, root, 840])
        config = root / "config.toml"
        host = host_configuration(driver, name == "refused", mode)
        if name == "profile":
            host = host.replace("07" * 32, "08" * 32)
        config.write_text(config.read_text() + host)
        before = cache_states(driver)
        stdout, stderr = actor(driver, image, name + "-cli",
              ["configured-sdk-cache-cli", "--config", config, "--role", "serve"],
              success=not refused)
        after = cache_states(driver)
        actor(driver, image, name + "-publication",
              ["configured-sdk-cache-example", "verify-reopen-publication", root, 840])
        if refused:
            if name == "profile":
                driver.require(not stdout and stderr ==
                               b"terrane: configured SDK native cache profile differs from original repository\n",
                               "profile mismatch did not fail at the original/native binding")
            driver.require(after == before
                           and all(not (root / ("snapshot-" + item)).exists()
                                   for item in ["first", "second"]),
                           "unavailable native custody started presentation or changed policy")
            witness = ("mismatched original profile" if name == "profile" else "an unenrolled native cache")
            print("PASS actual configured SDK refuses " + witness + " before any snapshot or policy effect", flush=True)
            continue

        root.with_suffix(".stdout").write_bytes(stdout)
        root.with_suffix(".stderr").write_bytes(stderr)
        actor(driver, image, name + "-verify",
              ["configured-sdk-cache-example", "verify-cli", root, 840])
        for directory, encoded in after.items():
            state = tomllib.loads(encoded.decode())
            old = tomllib.loads(before[directory].decode()) if before[directory] else {"reservations": [], "leases": [], "pins": []}
            verify_funding(driver, directory, old, state)
        for item in ["first", "second"]:
            path = root / ("snapshot-" + item) / "file"
            driver.require(path.read_bytes() == payload and path.stat().st_uid == 840,
                           "native SDK snapshot differs from independent original payload")
        sealed = driver.ROOT / "positive/private/sealed"
        candidates = [path for path in sealed.rglob("*")
                      if path.is_file() and path.stat().st_size == len(payload)
                      and path.read_bytes() == payload]
        if name == "never":
            driver.require(not candidates, "never-mode manifest unexpectedly assembled a whole object")
            print("PASS actual configured SDK never policy reads a native multi-chunk object without whole-object sealing", flush=True)
        else:
            driver.require(len(candidates) == 1, "native SDK did not read a genuine whole sealed object")
            metadata = candidates[0].stat()
            driver.require(metadata.st_uid == 841 and metadata.st_gid == 845
                           and metadata.st_nlink == 1 and metadata.st_mode & 0o7777 == 0o400,
                           "native SDK sealed object has different original custody")
            measurement = bytearray(68)
            struct.pack_into("=HH", measurement, 0, 0, 64)
            with candidates[0].open("rb") as file:
                fcntl.ioctl(file, 0xc0046686, measurement, True)
            algorithm, digest_size = struct.unpack_from("=HH", measurement)
            driver.require(algorithm == 1 and digest_size == 32,
                           "native SDK whole object lacks actual SHA-256 fs-verity")
            print("PASS actual configured SDK " + mode + " policy reads genuine fs-verity object and completes cache handoff", flush=True)
        offline, _ = actor(driver, image, name + "-offline",
                           ["configured-sdk-cache-example", "read-cache-offline", root, 840])
        for witness in [
                b"PASS: actual native driver bounds an indefinitely pending lower read",
                b"PASS: actual shared native circuit blocks lower misses while resident content remains readable",
                b"PASS: actual native circuit permits one bounded scheduled lower probe and reopens on failure",
                b"PASS: actual confined SDK reads recovered native residents while original lower chunks are unavailable"]:
            driver.require(offline.splitlines().count(witness) == 1,
                           "native SDK actor omitted or repeated a lower failure control")
        print("PASS actual configured CLI recovers both native cache owners and materializes signed original-authority SDK snapshots", flush=True)
