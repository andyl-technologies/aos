"""Checks actual configured CLI snapshots with separately recovered native caches."""

import os
import select
import subprocess
import sys
import time
import tomllib


PAYLOAD = b"independent configured SDK snapshot payload\n"


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


def host_configuration(driver, refused=False):
    """Supplies explicit operator intent for the two independently enrolled owners."""
    root = driver.ROOT / "positive"
    text = f"""
[host_tier]
path = "{root}"
size_bytes = 67108864
reassembly = "never"
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
retirement_grace_ms = 30000
chunk_profile = "cdc-1m"
chunk_seed = "{"07" * 32}"
[host_tier.domains."{domain}".cache]
state_gid = 844
capacity_bytes = 25165824
low_watermark_bytes = 16777216
probation_bytes = 65536
release_grace_seconds = 30
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
"""
    return text


def cache_states(driver):
    """Reads actual durable native policy without treating it as a live grant."""
    result = {}
    for domain in ["public", "private"]:
        path = driver.ROOT / "positive" / domain / "state/cache/records.toml"
        result[domain] = path.read_bytes() if path.exists() else None
    return result


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

    for name, refused in [("success", False), ("refused", True)]:
        root = parent / name
        actor(driver, image, name + "-setup",
              ["configured-sdk-cache-example", "setup", root, 840])
        config = root / "config.toml"
        config.write_text(config.read_text() + host_configuration(driver, refused))
        before = cache_states(driver)
        stdout, stderr = actor(driver, image, name + "-cli",
              ["configured-sdk-cache-cli", "--config", config, "--role", "serve"],
              success=not refused)
        after = cache_states(driver)
        actor(driver, image, name + "-publication",
              ["configured-sdk-cache-example", "verify-reopen-publication", root, 840])
        if refused:
            driver.require(after == before
                           and all(not (root / ("snapshot-" + item)).exists()
                                   for item in ["first", "second"]),
                           "unavailable native custody started presentation or changed policy")
            print("PASS actual configured SDK refuses an unenrolled native cache before any snapshot or policy effect", flush=True)
            continue

        root.with_suffix(".stdout").write_bytes(stdout)
        root.with_suffix(".stderr").write_bytes(stderr)
        actor(driver, image, name + "-verify",
              ["configured-sdk-cache-example", "verify-cli", root, 840])
        for directory, encoded in after.items():
            state = tomllib.loads(encoded.decode())
            old = tomllib.loads(before[directory].decode()) if before[directory] else {"reservations": []}
            added = [row for row in state["reservations"] if row not in old["reservations"]]
            driver.require(len(added) == 1 and added[0]["bytes"] == 262144
                           and added[0]["owner"] == "fixture-" + directory
                           and all(row in state["reservations"] for row in old["reservations"]),
                           "native SDK lacks exact newly funded recovery of each original owner")
        for item in ["first", "second"]:
            path = root / ("snapshot-" + item) / "file"
            driver.require(path.read_bytes() == PAYLOAD and path.stat().st_uid == 840,
                           "native SDK snapshot differs from independent original payload")
        print("PASS actual configured CLI recovers both native cache owners and materializes signed original-authority SDK snapshots", flush=True)
