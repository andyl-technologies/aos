"""Supervises genuine fresh enrollment and credential-separated guest witnesses.

The administrative example creates Core receipts and consumes them in the same
process. This supervisor transports no receipt, descriptor list or asserted
authority between cases. All fixture data and logs reside on guest disk.
"""

import hashlib
import json
import os
import pathlib
import runpy
import select
import signal
import subprocess
import sys
import time
import tomllib

IMAGE = pathlib.Path(sys.argv[1])
SOURCE = pathlib.Path(sys.argv[2])
SCENARIO = sys.argv[3] if len(sys.argv) == 4 else "enrollment"
ROOT = pathlib.Path(os.environ["TERRANE_INITIAL_FIXTURE_ROOT"])
EXECUTABLE = IMAGE / "bin/initial_enrollment_fixture"
MAX_OUTPUT = 256 * 1024
ADMIN_CASES = ["positive", "unknown", "wrong-profile", "incomplete", "preexisting",
               "reused-project", "partial-quota", "initialize-positive", "initialize-existing",
               "initialize-unsafe-parent"]
ADMIN_CAPS = "-all,+sys_admin,+dac_read_search,+fowner,+chown,+fsetid"
QUERY_CAPS = "-all,+sys_admin,+dac_read_search"
DEADLINE = time.monotonic() + 240


def require(condition, message):
    """Stops on unsupported, missing or ambiguous physical evidence."""
    if not condition:
        raise RuntimeError(message)


def verify_inputs():
    """Checks the completed image identity again before guest fixture effects."""
    identity = json.loads((IMAGE / "share/identity.json").read_text())
    for filename in ["initial_enrollment_vm.py", "initial_enrollment_image.py", "configured_sdk_cache_vm.py"]:
        key = "tests/terrane/" + filename
        expected = identity["input_sha256"][key]
        require(hashlib.sha256((SOURCE / key).read_bytes()).hexdigest() == expected,
                "supervisor input differs from image: " + filename)
        require(identity["installed_scripts_sha256"]["share/" + filename] == expected
                and hashlib.sha256((IMAGE / "share" / filename).read_bytes()).hexdigest() == expected,
                "installed supervisor input differs from bound source: " + filename)
    require(pathlib.Path(__file__).resolve() == IMAGE / "share/initial_enrollment_vm.py"
            and pathlib.Path(__file__).read_bytes() == (SOURCE / "tests/terrane/initial_enrollment_vm.py").read_bytes(),
            "executed supervisor is not the bound installed script")
    require(os.environ.get("LD_LIBRARY_PATH") == identity["runtime_library_path"],
            "guest runtime environment differs from completed image")
    require(identity["native_cases_executed"] == [], "image already claims unobserved native evidence")
    require(os.geteuid() == 0 and ROOT.is_absolute() and ROOT.resolve() == ROOT
            and ROOT.is_dir() and ROOT.stat().st_uid == 0
            and ROOT.stat().st_mode & 0o7777 == 0o755,
            "guest fixture requires explicit canonical host-root disk custody")
    require(os.statvfs(ROOT).f_frsize == 4096, "fixture ext4 block size differs")
    mount_rows = []
    for line in pathlib.Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if fields[4] == str(ROOT):
            separator = fields.index("-")
            mount_rows.append((fields[separator + 1], fields[separator + 3]))
    require(len(mount_rows) == 1 and mount_rows[0][0] == "ext4"
            and "prjquota" in mount_rows[0][1].split(","),
            "fixture is not the actual project-quota ext4 guest mount")


def admin_command(selector, query=False):
    """Drops quota override capability even for explicit root administration."""
    # CAP_SYS_RESOURCE is deliberately absent: genuine EDQUOT must not be
    # bypassed by the initial host-root caller during the partial-quota case.
    caps = QUERY_CAPS if query else ADMIN_CAPS
    return ["setpriv", "--bounding-set=" + caps, "--clear-groups",
            "--inh-caps=-all", "--ambient-caps=-all", str(EXECUTABLE), selector]


def role_command(selector, uid, groups):
    """Establishes all role restrictions before Rust or Tokio can start threads."""
    command = ["setpriv", "--reuid", str(uid), "--regid", str(uid)]
    command += ["--groups", ",".join(map(str, groups))] if groups else ["--clear-groups"]
    return [*command, "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
            "--no-new-privs", str(EXECUTABLE), selector]


def stop(process):
    """Stops only this supervisor's own guest process group with bounded waits."""
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def run_case(selector, command, expected_pass=True):
    """Requires exit status and the exact terminal witness under output/deadline caps."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    output = bytearray()
    deadline = min(DEADLINE, time.monotonic() + 30)
    try:
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "fixture timeout: " + selector)
            readable, _, _ = select.select([process.stdout], [], [], remaining)
            require(readable, "fixture output timeout: " + selector)
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            output.extend(chunk)
            require(len(output) <= MAX_OUTPUT, "fixture output bound exceeded: " + selector)
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        stop(process)
        text = bytes(output).decode("utf-8", errors="replace")
        (ROOT / "proof-logs" / (selector + ".log")).write_text(text)
        print(text, end="", flush=True)
    witness = "INITIAL_ENROLLMENT_PASS " + selector
    lines = text.splitlines()
    if expected_pass:
        require(process.returncode == 0 and lines and lines[-1] == witness
                and lines.count(witness) == 1,
                "missing exact successful physical witness: " + selector)
    else:
        require(selector == "capabilities-update" and process.returncode != 0
                and not any(line.startswith("INITIAL_ENROLLMENT_PASS ") for line in lines)
                and "unsafe native physical fence" in text
                and lines.count("PASS both enrolled Originals refuse changed payload custody through the actual native fence without changing selected bytes, registration or native custody") == 1,
                "missing actual Original native-fence refusal and preservation witness")
        print("UNQUALIFIED capabilities-update: actual Original native-fence refusal", flush=True)


def broker_ready(process):
    """Waits for actual broker bind without confusing bind with a successful query."""
    socket = ROOT / "positive/quota.sock"
    output = bytearray()
    deadline = min(DEADLINE, time.monotonic() + 15)
    while not socket.exists():
        require(process.poll() is None and time.monotonic() < deadline,
                "actual quota broker failed before bind")
        readable, _, _ = select.select([process.stdout], [], [], 0.05)
        if readable:
            output.extend(os.read(process.stdout.fileno(), 4096))
            require(len(output) <= MAX_OUTPUT, "quota broker output exceeded bound")
    status = (pathlib.Path("/proc") / str(process.pid) / "status").read_text()
    fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
    require(fields["Uid"].split() == ["0"] * 4, "query broker left actual root identity")
    mask = (1 << 2) | (1 << 21)  # CAP_DAC_READ_SEARCH and CAP_SYS_ADMIN only.
    for name in ["CapInh", "CapAmb"]:
        require(int(fields[name], 16) == 0, "query broker inherited ambient privilege")
    for name in ["CapPrm", "CapEff", "CapBnd"]:
        require(int(fields[name], 16) == mask, "query broker capability set differs: " + name)
    return output


def wait_released_consumer_grace(inline_files):
    """Allows original durable deadlines to elapse before reusing the bounded owner."""
    deadlines = []
    for domain in ["public", "private"]:
        path = ROOT / "positive" / domain / "state/cache/records.toml"
        state = tomllib.loads(path.read_text())
        released = [row["expires"] for row in state["leases"]
                    if row["owner"].startswith("consumer-grace:")]
        require(released, "preceding native reads retained no consumer release grace")
        deadlines.extend(released)

        inline = [row for row in inline_files if row[0] == domain]
        require(len(inline) == 1 and inline[0][5] == 0,
                "release wait lacks the original empty inline inode")
        body_hash = pathlib.Path(inline[0][1]).name
        body_pins = [row for row in state["pins"] if row["hash"] == body_hash]
        leases = {row["owner"]: row["expires"] for row in state["leases"]}
        require(body_pins and any(row["owner"].startswith("publication-grace:")
                                 for row in body_pins),
                "original inline body lacks durable publication release grace")
        require(all(row["owner"].startswith(("publication-grace:", "consumer-grace:"))
                    and leases.get(row["owner"]) == row["expires"] for row in body_pins),
                "original inline body has an unmatched or unreleased promise")
        deadlines.extend(row["expires"] for row in body_pins)
        (ROOT / ("proof-logs/inline-release-grace-" + domain + ".json")).write_text(
            json.dumps({"inode": inline[0], "pins": body_pins,
                        "leases": {row["owner"]: leases[row["owner"]] for row in body_pins}},
                       indent=2) + "\n")
    latest = max(deadlines)
    require(latest <= time.time() + 31, "release grace exceeds configured 30-second bound")

    # Earlier cases retain independent grace promises in this 64-record owner.
    # The native owner must expire its cold grants before another complete object
    # can fit; the supervisor waits on their original persisted deadlines.
    while time.time() <= latest:
        require(time.monotonic() < DEADLINE, "fixture deadline while waiting for release grace")
        time.sleep(min(0.25, max(0.01, latest - time.time())))
    print("PASS original consumer release grace elapsed before bounded native object reopening", flush=True)
    print("PASS original inline inode publication and consumer promises expired before native recovery", flush=True)



def sealed_snapshot():
    """Observes actual publisher-only inodes without granting consumer access."""
    rows = []
    for domain in ["public", "private"]:
        sealed = ROOT / "positive" / domain / "sealed"
        for path in sorted(sealed.rglob("*")):
            metadata = path.lstat()
            rows.append((domain, str(path.relative_to(sealed)), metadata.st_dev,
                         metadata.st_ino, metadata.st_mode, metadata.st_size))
    return rows


def configured_publication():
    """Requires the real two-domain publisher and actual content-role preparation."""
    publisher_selector = "publisher-reassembly" if SCENARIO in ["reassembly", "private-release", "cold-private-release", "cold-manifest-release", "cold-public-pressure", "cold-manifest-pressure", "sdk", "sdk-refusals", "sdk-wipe", "surface"] else "publisher-positive"
    publisher = subprocess.Popen(role_command(publisher_selector, 841, [845]),
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)
    try:
        socket = pathlib.Path("/run/terrane-initial-publisher/publisher.sock")
        deadline = min(DEADLINE, time.monotonic() + 20)
        while not socket.exists():
            require(publisher.poll() is None and time.monotonic() < deadline,
                    "configured publisher failed before binding actual listener")
            time.sleep(0.02)
        if SCENARIO == "surface":
            runpy.run_path(str(IMAGE / "share/configured_sdk_cache_vm.py"))["run_surface"](
                sys.modules[__name__], pathlib.Path(os.environ["TERRANE_CONFIGURED_SDK_IMAGE"]),
                pathlib.Path(os.environ["TERRANE_CONFIGURED_SURFACE_IMAGE"]))
        elif SCENARIO in ["sdk", "sdk-refusals", "sdk-wipe"]:
            runpy.run_path(str(IMAGE / "share/configured_sdk_cache_vm.py"))["run"](
                sys.modules[__name__], pathlib.Path(os.environ["TERRANE_CONFIGURED_SDK_IMAGE"]),
                wipe_only=SCENARIO == "sdk-wipe", refusals=SCENARIO == "sdk-refusals")
        elif SCENARIO in ["cold-private-release", "cold-manifest-release", "cold-public-pressure", "cold-manifest-pressure"]:
            manifest = SCENARIO in ["cold-manifest-release", "cold-manifest-pressure"]
            pressure = SCENARIO in ["cold-public-pressure", "cold-manifest-pressure"]
            seed_selector = "seed-manifest-release-public-private" if manifest else "seed-release-public-private"
            recovered_selector = "recovered-manifest-release-public-private" if manifest else "recovered-release-public-private"
            if pressure:
                recovered_selector = "recovered-manifest-pressure-public-private" if manifest else "recovered-pressure-public-private"
            run_case(seed_selector, role_command(seed_selector, 840, [844, 845]))
            seeded = [row for row in sealed_snapshot() if (row[4] & 0o170000) == 0o100000]
            require(len(seeded) == 2 and {row[0] for row in seeded} == {"public", "private"}
                    and all(row[5] == (262145 if manifest else 1337) for row in seeded),
                    "cold release seed lacks original sealed inodes in both domains")
            run_case(recovered_selector, role_command(recovered_selector, 840, [844, 845]))
            after = [row for row in sealed_snapshot() if (row[4] & 0o170000) == 0o100000]
            if pressure:
                require(after == [], "cold pressure retained original sealed backing")
                print("PASS root observed original public and private cold inode removal after actual FIFO pressure and private release", flush=True)
            else:
                require(after == [row for row in seeded if row[0] == "public"],
                        "cold release replaced a public inode or retained private backing")
                print("PASS root observed cold private erasure and unchanged original public inode across independent owner recovery", flush=True)
        elif SCENARIO == "private-release":
            run_case("release-public-private", role_command("release-public-private", 840, [844, 845]))
            files = [row for row in sealed_snapshot() if (row[4] & 0o170000) == 0o100000]
            require(len(files) == 1 and files[0][0] == "public" and files[0][5] == 1337,
                    "final release did not erase the actual private inode while retaining public cache")
            print("PASS root observed private sealed erasure and retained public inode after actual consumer and backing closure", flush=True)
        elif SCENARIO == "reassembly":
            before = sealed_snapshot()
            run_case("reassembly-public-private", role_command("reassembly-public-private", 840, [844, 845]))
            after = sealed_snapshot()
            prior = {(row[0], row[1]): row for row in before}
            current = {(row[0], row[1]): row for row in after}
            require(all(current.get(key) == row for key, row in prior.items()),
                    "manifest reassembly changed an original sealed inode")
            files = [row for key, row in current.items() if key not in prior
                     and (row[4] & 0o170000) == 0o100000]
            require(len(files) == 6, "reassembly lacks six actual sealed inodes")
            sizes = []
            for domain in ["public", "private"]:
                domain_files = [row for row in files if row[0] == domain]
                lengths = sorted(row[5] for row in domain_files)
                require(len(domain_files) == 3 and lengths[:2] == [1337, 262145] and lengths[2] > lengths[1],
                        "domain lacks actual inline, single and multi-chunk sealed objects")
                sizes.append(lengths)
            require(sizes[0] == sizes[1], "domain reassembly plaintext lengths differ")
            print("PASS root observed six distinct inline, single and multi-chunk sealed inodes across both native domains", flush=True)
        else:
            before_ready = sealed_snapshot()
            run_case("ready-public-private", role_command("ready-public-private", 840, [844, 845]))
            ready_log = (ROOT / "proof-logs/ready-public-private.log").read_text()
            for populated in ["false", "true"]:
                for domain in ["public", "private:fixture"]:
                    witness = (
                        "PASS actual native status fresh quota query and unchanged synchronized policy, "
                        "populated=" + populated + " for " + domain)
                    require(ready_log.splitlines().count(witness) == 1,
                            "missing exact actual native status observation: " + domain)
            sealed_after = sealed_snapshot()
            before_paths = {(row[0], row[1]): row for row in before_ready}
            after_paths = {(row[0], row[1]): row for row in sealed_after}
            require(all(after_paths.get(key) == row for key, row in before_paths.items()),
                    "inline sealing changed an original sealed inode")
            new_files = [row for key, row in after_paths.items()
                         if key not in before_paths and not (row[4] & 0o170000) == 0o040000]
            require(len(new_files) == 2 and {row[0] for row in new_files} == {"public", "private"}
                    and all((row[4] & 0o170000) == 0o100000 and row[5] == 0 for row in new_files),
                    "inline sealing lacks exactly one actual empty sealed inode per domain")
            print("PASS root observed actual distinct empty sealed inodes in both native domains", flush=True)
            wait_released_consumer_grace(new_files)
            # The consumer cannot inspect this publisher-only namespace. Root observes
            # the original sealed inodes around the complete unprivileged operation.
            sealed_before = sealed_snapshot()
            (ROOT / "proof-logs/sealed-chunked-before.json").write_text(
                json.dumps(sealed_before, indent=2) + "\n")
            run_case("open-public-private", role_command("open-public-private", 840, [844, 845]))
            sealed_after = sealed_snapshot()
            (ROOT / "proof-logs/sealed-chunked-after.json").write_text(
                json.dumps(sealed_after, indent=2) + "\n")
            if sealed_after != sealed_before:
                prior = {(row[0], row[1]): row for row in sealed_before}
                current = {(row[0], row[1]): row for row in sealed_after}
                changes = {
                    "removed": [row for key, row in prior.items() if key not in current],
                    "added": [row for key, row in current.items() if key not in prior],
                    "changed": [(row, current[key]) for key, row in prior.items()
                                if key in current and current[key] != row],
                }
                print("SEALED_CHUNKED_TRANSITION " + json.dumps(changes, sort_keys=True), flush=True)
            private_inline = [row for row in new_files if row[0] == "private"]
            require(len(private_inline) == 1 and private_inline[0] in sealed_before,
                    "original private inline inode disappeared before recovery")
            expected = [row for row in sealed_before if row != private_inline[0]]
            # Recovery must erase the released private inline body. Never-mode
            # chunked reads still cannot create, replace or modify sealed output.
            require(sealed_after == expected,
                    "chunked reads changed sealed custody beyond exact private inline retirement")
            print("PASS root observed exact private inline retirement and unchanged remaining sealed inodes across native chunked object reads", flush=True)
        require(publisher.poll() is None, "configured publisher exited during actual preparation")
    finally:
        stop(publisher)
        output = publisher.stdout.read(MAX_OUTPUT + 1)
        require(len(output) <= MAX_OUTPUT, "configured publisher output bound exceeded")
        text = output.decode("utf-8", errors="replace")
        (ROOT / "proof-logs/publisher.log").write_text(text)
        print(text, end="", flush=True)


def main():
    """Runs real same-process enrollment, authenticated queries and credential refusals."""
    require(len(sys.argv) in [3, 4] and SCENARIO in ["enrollment", "reassembly", "private-release", "cold-private-release", "cold-manifest-release", "cold-public-pressure", "cold-manifest-pressure", "sdk", "sdk-refusals", "sdk-wipe", "surface"],
            "requires a registered native proof scenario")
    verify_inputs()
    # Fixture TOML publication intentionally respects the caller's umask. Fix
    # this administrative input before any child creates portable metadata.
    os.umask(0o022)
    logs = ROOT / "proof-logs"
    logs.mkdir(mode=0o700)
    for selector in ADMIN_CASES:
        run_case(selector, admin_command(selector))

    broker = subprocess.Popen(admin_command("serve-positive", query=True),
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              start_new_session=True)
    broker_output = bytearray()
    try:
        broker_output.extend(broker_ready(broker))
        # The fixture itself verifies UID/GID's four status fields, exact
        # supplementary groups, all five empty capability sets and NNP before
        # runtime construction, then performs actual v3 authenticated queries.
        run_case("read-public", role_command("read-public", 840, [844, 845]))
        run_case("read-private", role_command("read-private", 840, [844, 845]))
        run_case("read-publisher", role_command("read-publisher", 841, [845]))
        run_case("foreign-private", role_command("foreign-private", 842, []))
        configured_publication()
        run_case("verify-positive", admin_command("verify-positive"))
        run_case("capabilities-update", admin_command("capabilities-update"), expected_pass=False)
        require(broker.poll() is None, "actual quota broker exited during queries")
        print("PASS bounded initial enrollment component evidence; NativeReady/BKT15/task acceptance remain unqualified", flush=True)
    finally:
        stop(broker)
        remainder = broker.stdout.read(MAX_OUTPUT + 1)
        broker_output.extend(remainder)
        require(len(broker_output) <= MAX_OUTPUT, "quota broker output exceeded bound")
        text = bytes(broker_output).decode("utf-8", errors="replace")
        (logs / "quota-broker.log").write_text(text)
        print(text, end="", flush=True)


if __name__ == "__main__":
    main()
