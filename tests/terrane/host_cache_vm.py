"""Supervises real bounded native cache component witnesses inside the ext4 VM.

This script never manufactures native proof objects. Root explicitly provisions
finite projects and runs the privileged helper; separate empty-capability Unix
identities execute the actual publisher CLI and confined cache example.
"""

import ast
import hashlib
import json
import os
import pathlib
import re
import resource
import runpy
import shutil
import select
import signal
import socket
import subprocess
import sys
import time
import tomllib

IMAGE = pathlib.Path(sys.argv[1])
SOURCE = pathlib.Path(sys.argv[2])
MOUNT = pathlib.Path(os.environ["TERRANE_CACHE_VM_ROOT"])
ADMIN = pathlib.Path("/var/lib/terrane-host")
RUNTIME = pathlib.Path("/run/terrane-cache-proof")
PUB_RUNTIME = pathlib.Path("/run/terrane-publish")
HARD = 8 * 1024 * 1024
EPOCH = "00000000000000000000000000000001"
MANIFEST_CASES = [
    ("manifest-recovery", "seed-manifest", "recover-manifest", True, "valid manifest"),
    ("manifest-mismatch", "seed-bad-manifest", "refuse-manifest", False, "manifest mismatch"),
    ("manifest-unsealed", "seed-unsealed-manifest",
     "refuse-unsealed-manifest", False, "unsealed manifest"),
    ("manifest-unsealed-writable", "seed-unsealed-writable-manifest",
     "refuse-unsealed-writable-manifest", False, "unsealed writable manifest"),
    ("manifest-truncated", "seed-truncated-manifest",
     "refuse-truncated-manifest", False, "truncated manifest"),
    ("manifest-sealed-writable", "seed-writable-manifest",
     "recover-writable-manifest", True, "valid manifest"),
    ("manifest-mixed", "seed-mixed-manifest",
     "recover-mixed-manifest", True, "valid mixed content"),
    ("manifest-mixed-mismatch", "seed-mixed-bad-manifest",
     "refuse-mixed-manifest", False, "mixed manifest mismatch"),
]
MIXED_CASES = {"manifest-mixed", "manifest-mixed-mismatch"}
INLINE_BYTES = b"independent inline cold candidate"
CASES = [
    "empty", "pin", "lease", "reservation", "residence", "unknown",
    "state-file", "state-directory", "cancel", "edquot", "exclusive",
    "admission-chunk", "admission-metadata", "admission-cancel",
    "publication-inline", "publication-cancel", "publication-transfer",
    "publication-transfer-cancel", "publication-transfer-conflict",
    "retention-running", "retention-running-cancel",
    "publication-manifest", "publication-manifest-cancel", "publication-manifest-bad-whole",
    "publication-manifest-dictionary",
    "publication-manifest-reuse",
    "publication-manifest-reuse-bad-whole",
] + [row[0] for row in MANIFEST_CASES]

LABELS = ["layout-root", "chunks", "objects", "sealed", "staging", "quarantine",
          "pending-delete", "state"]
BUDGET = HARD * len(CASES)
PROVISION_CAPS = "-all,+sys_admin,+dac_read_search,+fowner,+chown,+fsetid"
QUERY_CAPS = "-all,+sys_admin,+dac_read_search"
# Root administration writes across role-owned directories before role startup.
SEED_CAPS = "-all,+dac_override,+fowner,+chown,+fsetid"


def require(condition, message):
    """Fails this component witness rather than reporting unsupported as pass."""
    if not condition:
        raise RuntimeError(message)


def run(arguments, **kwargs):
    """Runs one explicit guest action with bounded completion."""
    return subprocess.run(list(map(str, arguments)), check=True, timeout=30, **kwargs)


def metadata(path, uid, gid, mode):
    """Applies exactly the deployed module's scaffold ownership and mode."""
    os.chown(path, uid, gid)
    path.chmod(mode)


def domain(case):
    return "public" if case == "empty" else "tenant:" + case


def root(case):
    return MOUNT / case


def owner(case):
    return "native-cache-" + case


def project(case):
    return 52001 + CASES.index(case)


def role_command(uid, arguments):
    """Executes a distinct role with all five capability sets empty."""
    groups = "844,845" if uid == 840 else "845"
    return ["setpriv", "--reuid", str(uid), "--regid", str(uid), "--groups", groups,
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", *map(str, arguments)]


def native_descriptor_budget():
    """Bounds retained roots and bodies in this fixture's configured native roles."""
    # Provisioning, quota queries and publication retain all configured domains.
    # The inherited 1024 soft ceiling cannot cover this expanded inventory; set
    # a finite allowance only in each dedicated child, before its role bootstrap.
    resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))


def admin_command(caps, arguments):
    """Bounds the explicit administrative helper independently of role processes."""
    return ["setpriv", "--bounding-set=" + caps, "--clear-groups",
            "--inh-caps=-all", "--ambient-caps=-all", *map(str, arguments)]


def actor_environment(case, uuid):
    """Supplies public fixed connection metadata, never a quota observation."""
    return dict(os.environ, TERRANE_CACHE_ROOT=str(root(case)), TERRANE_CACHE_DOMAIN=domain(case),
                TERRANE_CACHE_OWNER=owner(case), TERRANE_CACHE_PROJECT=str(project(case)),
                TERRANE_CACHE_QUOTA_SOCKET=str(RUNTIME / "quota.sock"),
                TERRANE_CACHE_PUBLISHER_SOCKET=str(PUB_RUNTIME / "publisher.sock"),
                TERRANE_CACHE_BUDGET=str(BUDGET), TERRANE_CACHE_UUID=uuid)


def actor(case, mode, uuid):
    """Executes an actual confined cache actor and retains its complete output."""
    result = subprocess.run(role_command(840, [IMAGE / "bin/host_cache_fixture", mode]),
                            env=actor_environment(case, uuid), text=True, capture_output=True, timeout=30)
    print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", flush=True)
    require(result.returncode == 0 and "PASS " in result.stdout,
            "actual actor failed: " + case + "/" + mode)
    return result.stdout


def administrative_preflight(stage):
    """Reports bounded fixed guest ancestry without weakening native validation."""
    protected = [pathlib.Path(path) for path in ["/", "/var", "/var/lib", "/mnt", "/run"]]
    protected.extend([MOUNT, ADMIN, ADMIN / "project-claims", RUNTIME])
    for path in [*protected, PUB_RUNTIME]:
        if not path.exists():
            print(f"administrative preflight {stage}: {path} missing", flush=True)
            require(stage == "before", "missing configured guest ancestor: " + str(path))
            continue
        value = path.lstat()
        print(f"administrative preflight {stage}: {path} uid={value.st_uid} "
              f"gid={value.st_gid} mode={value.st_mode & 0o7777:04o}", flush=True)
        if stage == "after" and path in protected:
            require(path.is_dir() and not path.is_symlink()
                    and value.st_uid == 0 and value.st_mode & 0o022 == 0,
                    "unsafe configured guest ancestor: " + str(path))


def scaffold():
    """Creates only directory scaffolding before genuine explicit provisioning."""
    # The minimal Firecracker init mounts /run without a mode option, so
    # Linux defaults it to sticky 01777. Match the deployed protected runtime
    # parent before the real helper traverses it; child modes cannot repair it.
    metadata(pathlib.Path("/run"), 0, 0, 0o755)
    ADMIN.mkdir(parents=True, exist_ok=True)
    metadata(ADMIN, 0, 0, 0o700)
    (ADMIN / "project-claims").mkdir()
    metadata(ADMIN / "project-claims", 0, 0, 0o700)
    RUNTIME.mkdir(parents=True)
    metadata(RUNTIME, 0, 0, 0o755)
    PUB_RUNTIME.mkdir(parents=True)
    metadata(PUB_RUNTIME, 841, 845, 0o2750)
    for case in CASES:
        path = root(case)
        path.mkdir()
        metadata(path, 0, 0, 0o755)
        for label in LABELS[1:]:
            directory = path / label
            directory.mkdir()
            custody = ((0, 0, 0o755) if label == "state" else
                       (841, 841, 0o700) if label in {"sealed", "staging", "pending-delete"}
                       else (840, 845, 0o2770))
            metadata(directory, *custody)
        for name, uid, gid, mode in [("cache", 840, 844, 0o2770), ("publication", 841, 841, 0o700)]:
            directory = path / "state" / name
            directory.mkdir()
            metadata(directory, uid, gid, mode)


def configurations():
    """Writes separate privileged provisioning and readable configured CLI input."""
    quota = [f"socket = {json.dumps(str(RUNTIME / 'quota.sock'))}", f'epoch = "{EPOCH}"',
             f"tier_charge_budget_bytes = {BUDGET}"]
    publisher = ['role = "publish"', 'store = ' + json.dumps('disk(' + str(root('empty')) + ')'), '[host_tier]',
                 f"path = {json.dumps(str(root('empty')))}", f"size_bytes = {BUDGET}",
                 'reassembly = "never"', '[host_tier.publisher]',
                 f"socket_path = {json.dumps(str(PUB_RUNTIME / 'publisher.sock'))}",
                 "serve_uid = 840", "publish_uid = 841", "content_uid = 840", "content_gid = 845",
                 "max_connections = 32", "[host_tier.quota]",
                 f"socket_path = {json.dumps(str(RUNTIME / 'quota.sock'))}",
                 f'configuration_epoch = "{EPOCH}"']
    for case in CASES:
        quota.extend(["[[owners]]", f"owner_id = {json.dumps(owner(case))}",
                      f"domain = {json.dumps(domain(case))}", f"project_id = {project(case)}",
                      f"hard_limit_bytes = {HARD}", "allowed_client_uids = [0, 840, 841]"])
        for label in LABELS:
            path = root(case) if label == "layout-root" else root(case) / label
            quota.extend(["[[owners.roots]]", f"role_directory = {json.dumps(label)}",
                          f"path = {json.dumps(str(path))}"])
        table = "host_tier.domains." + json.dumps(domain(case))
        publisher.extend([f"[{table}]", f"path = {json.dumps(str(root(case)))}", 'wipe = "none"',
                          f"quota_owner_id = {json.dumps(owner(case))}", f"[{table}.publisher]",
                          "retirement_grace_ms = 30000", 'chunk_profile = "cdc-1m"',
                          'chunk_seed = "' + "00" * 32 + '"'])
    quota_path = ADMIN / "host.toml"
    quota_path.write_text("\n".join(quota) + "\n")
    metadata(quota_path, 0, 0, 0o600)
    cli_path = RUNTIME / "publisher.toml"
    cli_path.write_text("\n".join(publisher) + "\n")
    metadata(cli_path, 0, 0, 0o644)
    return quota_path, cli_path


def cold_candidates():
    """Seeds actual bounded untrusted records without granting native authority."""
    bodies = {
        "pin": '[[pins]]\nowner = "cold"\nhash = "' + "00" * 32 + '"\nexpires = 1\n',
        "lease": '[[leases]]\nowner = "cold"\nexpires = 1\n',
        "reservation": '[[reservations]]\nid = "cold"\nowner = "cold"\nbytes = 262144\n',
        "residence": '[[residences]]\nchunk = "' + "00" * 32 + '"\nobject = "' + "11" * 32 + '"\noffset = 0\nlength = 1\n',
    }
    for case, record in bodies.items():
        categories = {"pin": "pins", "lease": "leases", "reservation": "reservations", "residence": "residences"}
        text = "version = 1\n" + "".join(name + " = []\n" for name in categories.values()
                                                    if name != categories[case]) + record
        path = root(case) / "state/cache/records.toml"
        path.write_text(text)
        metadata(path, 840, 844, 0o660)
    unknown = root("unknown") / "chunks/unrecognized-name"
    unknown.write_bytes(b"untrusted actual unknown body")
    metadata(unknown, 840, 845, 0o660)
    sibling = root("state-file") / "state/unhandled.tmp"
    sibling.write_bytes(b"unknown policy sibling must survive")
    metadata(sibling, 840, 844, 0o660)
    sibling = root("state-directory") / "state/old-policy"
    sibling.mkdir()
    metadata(sibling, 840, 844, 0o770)


def publisher_confinement_cases():
    """Exercises actual kernel enforcement and preexisting descriptor rejection."""
    cases = [
        ("publisher-confinement",
         "PASS actual publisher kernel denies Internet sockets and permits Unix transport; no Ready"),
        ("publisher-reject-descriptor",
         "PASS actual publisher rejects an undeclared preexisting network descriptor"),
        ("publisher-reject-stdio",
         "PASS actual publisher rejects a network socket inherited as standard input"),
    ]
    for mode, expected in cases:
        # The socket remains unbound; passing it as stdin exercises the actual
        # inherited descriptor, with no interface or external service involved.
        inherited = (socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                     if mode == "publisher-reject-stdio" else None)
        try:
            result = subprocess.run(role_command(841, [IMAGE / "bin/host_cache_fixture", mode]),
                                    stdin=inherited, capture_output=True, text=True, timeout=20)
        finally:
            if inherited is not None:
                inherited.close()
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", flush=True)
        require(result.returncode == 0 and result.stdout.splitlines() == [expected],
                "actual publisher confinement control failed: " + mode)


def seed_manifests(uuid):
    """Creates untrusted sealed and unsealed candidates before either role starts."""
    seeded = {}
    for case, mode, _, _, _ in MANIFEST_CASES:
        try:
            result = run(admin_command(SEED_CAPS, [IMAGE / "bin/host_cache_fixture", mode]),
                         env=actor_environment(case, uuid), text=True, capture_output=True)
        except subprocess.CalledProcessError as error:
            print(error.stdout or "", end="", flush=True)
            print(error.stderr or "", end="", flush=True)
            raise
        require(result.stdout.splitlines() == [
            "SEEDED actual cold manifest candidate; no publication or recovery authority"
        ], "missing actual cold seed witness: " + case)
        bodies = list((root(case) / "sealed").glob("*/*"))
        packs = list((root(case) / "objects/pack").glob("*/*"))
        require(len(bodies) == (2 if case in MIXED_CASES else 1) and len(packs) == 2
                and sorted(path.suffix for path in packs) == [".idx", ".pack"]
                and list((root(case) / "state/publication").iterdir()) == []
                and list((root(case) / "state/cache").iterdir()) == [],
                "seed fabricated policy/publication state or omitted physical bytes")
        # This identifies fixture inputs by their exact seeded bytes only;
        # actual native adoption must independently verify their kernel seals
        # and registered identities before any recovery completion can exist.
        companions = [path for path in bodies if case in MIXED_CASES
                      and path.read_bytes() == INLINE_BYTES]
        require(len(companions) == (1 if case in MIXED_CASES else 0),
                "mixed seed omitted its independent inline candidate")
        remaining = [path for path in bodies if path not in companions]
        require(len(remaining) == 1, "fixture manifest candidate is ambiguous")
        body = remaining[0]
        seeded[case] = {"body": body, "inode": body.stat().st_ino,
                        "hash": hashlib.sha256(body.read_bytes()).hexdigest(),
                        "companions": [(path, path.stat().st_ino) for path in companions],
                        "packs": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in packs}}
    return seeded


def manifest_recovery_cases(uuid, seeded, helper):
    """Checks actual recovery, final read-only mode and quarantine of rejected files."""
    for case, _, mode, recovers, label in MANIFEST_CASES:
        if case == "manifest-mixed":
            output = runpy.run_path(str(IMAGE / "share/manifest_publication_vm.py"))[
                "run_mixed_source_pin"](sys.modules[__name__], helper, uuid, seeded[case])
        else:
            output = actor(case, mode, uuid)
        expected = ("PASS actual manifest recovery reconstructed verified residences and acknowledged Resume; no Ready"
                    if recovers else
                    f"PASS actual {label} retained metadata funding and faulted custody; no Resume")
        if case == "manifest-mixed":
            expected = "PASS actual mixed recovery adopted inline and manifest bytes and acknowledged Resume; no Ready"
        require(expected in output.splitlines(), "missing native manifest result: " + case)
        if case == "manifest-recovery":
            runpy.run_path(str(IMAGE / "share/manifest_publication_vm.py"))[
                "check_recovered_reassembly"](sys.modules[__name__], case, output, seeded[case])
        require("PASS actual recovered source refused without acknowledged Resume; policy unchanged"
                in output.splitlines(), "recovery source bypassed actual Resume: " + case)
        if recovers:
            require(output.splitlines().count(
                "PASS actual recovered manifest ranges read while embedded policy held; original custody unchanged") == 2,
                "missing actual lock-free recovered reads before/after Running mutation: " + case)
            require("PASS actual recovered ranges survived a new Running admission; original metadata retained"
                    in output.splitlines(), "recovered source reused the cold completion predicate: " + case)
        original = seeded[case]
        if case in MIXED_CASES:
            require(output.splitlines().count(
                "PASS actual adopted inline source refused before complete recovery and Resume; policy unchanged") == 1,
                "adopted inline registry bypassed complete recovery and Resume")
        for path, inode in original["companions"]:
            require(path.stat().st_ino == inode and path.read_bytes() == INLINE_BYTES
                    and path.stat().st_mode & 0o7777 == 0o400,
                    "mixed recovery changed its independently adopted inline candidate")
            bindings = list((root(case) / "state/publication").glob("*-" + path.name + ".toml"))
            require(len(bindings) == 1 and bindings[0].stat().st_uid == 841,
                    "mixed recovery omitted actual inline adoption before manifest completion/refusal")
        for name, digest in original["packs"].items():
            require(hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() == digest,
                    "manifest recovery changed retained metadata bytes")
        if recovers:
            retained = original["body"]
            require(retained.stat().st_ino == original["inode"]
                    and retained.stat().st_mode & 0o7777 == 0o400,
                    "recovery replaced original sealed body or omitted final read-only mode")
        else:
            require(not original["body"].exists(), "rejected body survived under canonical name")
            quarantined = [path for path in (root(case) / "quarantine").rglob("*")
                           if path.is_file() and path.stat().st_ino == original["inode"]]
            require(len(quarantined) == 1, "actual rejected inode was not retained in quarantine")
            retained = quarantined[0]
        require(hashlib.sha256(retained.read_bytes()).hexdigest() == original["hash"],
                "recovery changed actual candidate body bytes")


def process_status(process, uid):
    """Checks actual running-role identity and every capability set."""
    require(process.poll() is None, "role exited before currentness inspection")
    status = (pathlib.Path("/proc") / str(process.pid) / "status").read_text()
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]:
        require(f"{name}:\t0000000000000000" in status.splitlines(), name + " is not empty")
    require(f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}" in status.splitlines(), "actual role UID mismatch")
    require("NoNewPrivs:\t1" in status.splitlines() and "Seccomp:\t2" in status.splitlines(),
            "actual role confinement absent")
    return status


class Lines:
    """Reads a real actor handshake with bounded deadlines and buffered bytes."""
    def __init__(self, process):
        self.process = process
        self.bytes = b""
        self.printed = 0

    def until(self, expected, timeout=10):
        deadline = time.monotonic() + timeout
        while expected.encode() not in self.bytes:
            require(self.process.poll() is None, "actor exited before handshake: " + expected)
            remaining = deadline - time.monotonic()
            require(remaining > 0, "actor handshake deadline: " + expected)
            ready, _, _ = select.select([self.process.stdout], [], [], remaining)
            require(ready, "actor handshake timeout: " + expected)
            chunk = os.read(self.process.stdout.fileno(), 4096)
            require(chunk, "actor stdout closed before handshake")
            self.bytes += chunk
        print(self.bytes[self.printed:].decode(), end="", flush=True)
        self.printed = len(self.bytes)


def controlled_actor(case, mode, uuid):
    """Starts a genuine actor with only inherited ordinary control/stdio pipes."""
    return subprocess.Popen(role_command(840, [IMAGE / "bin/host_cache_fixture", mode]),
                            env=actor_environment(case, uuid), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def finish_controlled(process, command):
    """Requires physical command completion after a real supervisor control."""
    output, _ = process.communicate((command + "\n").encode(), timeout=15)
    print(output.decode(), end="", flush=True)
    require(process.returncode == 0 and b"PASS " in output, "controlled actor failed")


def cancel_case(helper, uuid):
    """Drops an actually pending enqueued waiter while only the helper is stopped."""
    process = controlled_actor("cancel", "cancel", uuid)
    stopped = False
    try:
        lines = Lines(process)
        lines.until("READY actual preparation and owner")
        process_status(process, 840)
        helper.send_signal(signal.SIGSTOP)
        stopped = True
        deadline = time.monotonic() + 1
        while True:
            status = (pathlib.Path("/proc") / str(helper.pid) / "status").read_text()
            if any(line.startswith("State:\tT") or line.startswith("State:\tt") for line in status.splitlines()):
                break
            require(time.monotonic() < deadline, "helper stop was not acknowledged")
            time.sleep(0.005)
        process.stdin.write(b"enqueue\n")
        process.stdin.flush()
        lines.until("CANCELLED accepted pending waiter", timeout=1)
        helper.send_signal(signal.SIGCONT)
        stopped = False
        finish_controlled(process, "resumed")
    finally:
        # A failed witness must never strand the privileged query helper stopped.
        if stopped and helper.poll() is None:
            helper.send_signal(signal.SIGCONT)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def exclusive_case(uuid):
    """Confirms actual exclusive state custody rather than trusting a role flag."""
    process = controlled_actor("exclusive", "hold", uuid)
    try:
        Lines(process).until("READY actual exclusive state owner")
        process_status(process, 840)
        actor("exclusive", "start-refuse", uuid)
        finish_controlled(process, "release")
        actor("exclusive", "empty", uuid)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def admission_cases(helper, uuid):
    """Requires actual Resume and exact native chunk/pair completion witnesses."""
    acknowledgement = "ACK actual empty recovery Resume; no Ready"
    for case, mode, witness in [
        ("admission-chunk", "admit-chunk",
         "PASS actual repeated chunk refusals, valid canonical admission and finite policy capacity; no Ready"),
        ("admission-metadata", "admit-metadata",
         "PASS actual repeated metadata refusals and fully verified canonical pair with retained holds; no Ready"),
    ]:
        output = actor(case, mode, uuid)
        require(output.splitlines() == [acknowledgement, witness],
                "missing exact encoded-admission completion: " + case)

    process = controlled_actor("admission-cancel", "admit-cancel", uuid)
    stopped = False
    try:
        lines = Lines(process)
        lines.until("READY actual admission Resume acknowledged; wait for stopped-helper control")
        require(acknowledgement.encode() in lines.bytes,
                "cancellation fixture never acknowledged actual Resume")
        process_status(process, 840)

        # Bound the whole stopped interval below one second and inside the query
        # deadline. Enqueue only after the real helper is observed stopped.
        deadline = time.monotonic() + 0.8
        helper.send_signal(signal.SIGSTOP)
        stopped = True
        while True:
            status = (pathlib.Path("/proc") / str(helper.pid) / "status").read_text()
            require(helper.poll() is None, "quota helper exited before admission cancellation")
            if any(line.startswith("State:\tT") or line.startswith("State:\tt")
                   for line in status.splitlines()):
                break
            require(time.monotonic() < deadline, "helper stop was not acknowledged")
            time.sleep(0.005)
        process.stdin.write(b"enqueue\n")
        process.stdin.flush()
        lines.until("CANCELLED accepted admission waiter; physical owner retained",
                    timeout=max(0, deadline - time.monotonic()))
        require(time.monotonic() < deadline, "admission cancellation exceeded stopped interval")
        helper.send_signal(signal.SIGCONT)
        stopped = False

        # An arbitrary later error cannot prove completion of the abandoned job.
        # The actor requires a second valid acknowledgment and checks both actual
        # canonical bodies and their still-durable holds before emitting this line.
        output, _ = process.communicate(b"resumed\n", timeout=15)
        print(output.decode(), end="", flush=True)
        require(process.returncode == 0 and output.decode().splitlines() == [
            "PASS dropped admission waiter retained physical completion, both canonical inodes and durable holds; no Ready"
        ], "missing exact physical completion after dropping admission waiter")
    finally:
        if stopped and helper.poll() is None:
            helper.send_signal(signal.SIGCONT)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def publication_cases(publisher, uuid):
    """Exercises actual funded publication, no-replace and abandoned waiters."""
    def staging_snapshot(case):
        directory = root(case) / "staging" / str(publisher.pid)
        entries = list((root(case) / "staging").iterdir())
        require(entries == [directory] and not directory.is_symlink(),
                "publication staging differs from the actual publisher-ID directory")
        observed = directory.stat()
        require(directory.is_dir() and observed.st_uid == observed.st_gid == 841
                and observed.st_mode & 0o7777 == 0o700 and list(directory.iterdir()) == [],
                "publication left temporary files or changed private staging custody")
        return observed.st_dev, observed.st_ino

    inline_staging = staging_snapshot("publication-inline")
    output = actor("publication-inline", "publish-inline", uuid)
    require(output.splitlines() == [
        "PASS actual inline publication verified bytes, retained funding and no-replace inode; no Ready"
    ], "missing actual inline publication completion")
    require(staging_snapshot("publication-inline") == inline_staging,
            "inline publication replaced the actual private staging directory")

    case = "publication-cancel"
    cancelled_staging = staging_snapshot(case)
    process = controlled_actor(case, "publish-inline-cancel", uuid)
    stopped = False
    try:
        lines = Lines(process)
        lines.until("READY actual inline publication Resume acknowledged; wait for stopped-publisher control")
        process_status(process, 840)
        publisher.send_signal(signal.SIGSTOP)
        stopped = True
        deadline = time.monotonic() + 4
        while True:
            status = (pathlib.Path("/proc") / str(publisher.pid) / "status").read_text()
            require(publisher.poll() is None, "publisher exited before inline cancellation")
            if any(line.startswith("State:\tT") or line.startswith("State:\tt")
                   for line in status.splitlines()):
                break
            require(time.monotonic() < deadline, "publisher stop was not acknowledged")
            time.sleep(0.005)
        process.stdin.write(b"start\n")
        process.stdin.flush()
        lines.until("QUEUED actual inline publication; wait for durable funding control")
        snapshot = root(case) / "state/cache/records.toml"
        while True:
            state = tomllib.loads(snapshot.read_text())
            require(process.poll() is None and time.monotonic() < deadline,
                    "inline publication did not durably fund its stopped exchange")
            if len(state["reservations"]) == 2 and len(state["pins"]) == len(state["leases"]) == 1:
                require(state["residences"] == [], "stopped publisher already supplied a residence")
                break
            time.sleep(0.005)
        require(list((root(case) / "sealed").glob("*/*")) == [],
                "stopped publisher already supplied a canonical inode")
        process.stdin.write(b"cancel\n")
        process.stdin.flush()
        lines.until("CANCELLED actual inline publication waiter; physical owner retained")
        publisher.send_signal(signal.SIGCONT)
        stopped = False
        deadline = time.monotonic() + 10
        while True:
            state = tomllib.loads(snapshot.read_text())
            require(process.poll() is None and time.monotonic() < deadline,
                    "abandoned inline command did not publish a durable residence")
            if len(state["residences"]) == 1:
                break
            time.sleep(0.005)
        bodies = list((root(case) / "sealed").glob("*/*"))
        require(len(bodies) == 1, "abandoned inline command did not retain exactly one canonical inode")
        body = bodies[0]
        inode = body.stat().st_ino
        digest = hashlib.sha256(body.read_bytes()).hexdigest()
        output, _ = process.communicate(b"finish\n", timeout=15)
        print(output.decode(), end="", flush=True)
        require(process.returncode == 0 and output.decode().splitlines() == [
            "PASS dropped inline waiter retained physical publication, canonical inode and durable holds; no Ready"
        ], "missing exact physical inline completion after dropping its waiter")
        require(body.stat().st_ino == inode and hashlib.sha256(body.read_bytes()).hexdigest() == digest,
                "repeated publication replaced the abandoned command's actual canonical inode")
        require(list((root(case) / "chunks").glob("*/*")) == []
                and staging_snapshot(case) == cancelled_staging,
                "inline publication left a duplicate standalone or staging file")
    finally:
        if stopped and publisher.poll() is None:
            publisher.send_signal(signal.SIGCONT)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def inline_transfer_cases(publisher, uuid):
    """Checks actual source inodes, pending leases, cancellation and collision refusal."""
    for suffix in ["", "-cancel", "-conflict"]:
        case = "publication-transfer" + suffix
        process = controlled_actor(case, "publish-inline-transfer" + suffix, uuid)
        stopped = False
        try:
            lines = Lines(process)
            lines.until("READY actual standalone admission retained; wait for transfer control")
            print(process_status(process, 840), flush=True)
            staging = root(case) / "staging" / str(publisher.pid)
            require(not staging.is_symlink(), "transfer staging directory is a symlink")
            staged_identity = (staging.stat().st_dev, staging.stat().st_ino)
            sources = list((root(case) / "chunks").glob("*/*"))
            require(len(sources) == 1, "transfer lacks exactly one actual standalone source")
            source = sources[0]
            original = source.stat()
            original_bytes = source.read_bytes()
            digest, separator, codec = source.name.partition(".")
            require(separator and len(digest) == 64 and codec == "0"
                    and source.parent.name == digest[:2]
                    and original.st_uid == 840 and original.st_gid == 845
                    and original.st_nlink == 1 and original.st_mode & 0o7777 == 0o640,
                    "actual transfer source has another canonical shape or custody")
            pending = root(case) / "pending-delete" / digest
            snapshot = root(case) / "state/cache/records.toml"
            collision = None
            if suffix == "-conflict":
                pending.write_bytes(b"occupied pending transfer name must survive")
                metadata(pending, 841, 841, 0o400)
                collision = (pending.stat().st_ino, pending.read_bytes())
            if suffix == "-cancel":
                publisher.send_signal(signal.SIGSTOP)
                stopped = True
                deadline = time.monotonic() + 4
                while True:
                    status = (pathlib.Path("/proc") / str(publisher.pid) / "status").read_text()
                    require(publisher.poll() is None, "publisher exited before transfer cancellation")
                    if any(line.startswith("State:\tT") or line.startswith("State:\tt")
                           for line in status.splitlines()):
                        break
                    require(time.monotonic() < deadline, "transfer publisher stop was not acknowledged")
                    time.sleep(0.005)
            process.stdin.write(b"start\n")
            process.stdin.flush()
            if suffix == "-cancel":
                lines.until("QUEUED actual inline transfer; wait for durable funding control")
                deadline = time.monotonic() + 4
                while True:
                    state = tomllib.loads(snapshot.read_text())
                    require(process.poll() is None and time.monotonic() < deadline,
                            "transfer did not durably retain its publication funding")
                    if len(state["reservations"]) == 3 and len(state["pins"]) == len(state["leases"]) == 2:
                        require(state["residences"] == [], "stopped transfer supplied a residence")
                        break
                    time.sleep(0.005)
                require(source.stat().st_ino == original.st_ino and source.read_bytes() == original_bytes
                        and not pending.exists() and list((root(case) / "sealed").glob("*/*")) == [],
                        "stopped publisher changed an actual transfer source or supplied backing")
                process.stdin.write(b"cancel\n")
                process.stdin.flush()
                lines.until("CANCELLED inline transfer waiter; actual source and physical owner retained")
                publisher.send_signal(signal.SIGCONT)
                stopped = False
                deadline = time.monotonic() + 15
                while True:
                    state = tomllib.loads(snapshot.read_text())
                    require(process.poll() is None and time.monotonic() < deadline,
                            "abandoned transfer lost physical retirement or residence completion")
                    if len(state["residences"]) == 1 and not source.exists():
                        break
                    time.sleep(0.005)
            output, _ = process.communicate(b"finish\n" if suffix == "-cancel" else None, timeout=20)
            print(output.decode(), end="", flush=True)
            expected = ("PASS occupied pending name refused inline transfer while retaining original inode, sealed outcome and funded fault; no Ready"
                        if collision else "PASS actual inline transfer retained original source, pending retirement, sealed bytes and durable holds; no Ready")
            require(process.returncode == 0 and output.decode().splitlines() == [expected],
                    "missing exact actual inline transfer result: " + case)
            bodies = list((root(case) / "sealed").glob("*/*"))
            require(len(bodies) == 1 and bodies[0].name == digest
                    and bodies[0].read_bytes() == original_bytes[1:],
                    "transfer lost the actual independently published sealed bytes")
            state = tomllib.loads(snapshot.read_text())
            if collision:
                require((pending.stat().st_ino, pending.read_bytes()) == collision
                        and source.stat().st_ino == original.st_ino and source.read_bytes() == original_bytes
                        and state["residences"] == [] and len(state["reservations"]) == 3,
                        "failed transfer replaced a pending/canonical inode or discarded durable exclusion")
            else:
                retired = pending.stat()
                require(not source.exists() and list((root(case) / "chunks").glob("*/*")) == []
                        and (retired.st_dev, retired.st_ino) == (original.st_dev, original.st_ino)
                        and retired.st_nlink == 1 and pending.read_bytes() == original_bytes,
                        "transfer replaced/unlinked the source instead of retaining its exact pending inode")
                leases = list((root(case) / "state/publication").glob("retirement-*.toml"))
                require(len(leases) == 1, "actual transfer lacks its durable publisher retirement lease")
                lease = tomllib.loads(leases[0].read_text())
                require(lease["domain"] == domain(case) and lease["version"] == 1
                        and lease["device"] == retired.st_dev and lease["inode"] == retired.st_ino
                        and lease["changed_seconds"] == retired.st_ctime_ns // 1_000_000_000
                        and lease["changed_nanoseconds"] == retired.st_ctime_ns % 1_000_000_000
                        and lease["deadline_unix_ms"] > 0
                        and len(state["residences"]) == 1 and len(state["reservations"]) == 4,
                        "transfer retirement lease or completed policy names another actual source")
            require(not staging.is_symlink()
                    and (staging.stat().st_dev, staging.stat().st_ino) == staged_identity
                    and list((root(case) / "staging").iterdir()) == [staging]
                    and staging.stat().st_uid == staging.stat().st_gid == 841
                    and staging.stat().st_mode & 0o7777 == 0o700 and list(staging.iterdir()) == [],
                    "transfer left private staging files or changed publisher directory custody")
        finally:
            if stopped and publisher.poll() is None:
                publisher.send_signal(signal.SIGCONT)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def running_retention_cases(helper, uuid):
    """Requires actual post-Resume metadata pins, including an abandoned waiter."""
    output = actor("retention-running", "retain-running", uuid)
    require(output.splitlines() == [
        "PASS actual Running metadata retention kept both original inodes and distinct durable pins across later work; no Ready"
    ], "missing actual Running metadata retention completion")
    case = "retention-running-cancel"
    process = controlled_actor(case, "retain-running-cancel", uuid)
    stopped = False
    try:
        lines = Lines(process)
        lines.until("READY actual metadata admission and Resume; wait for stopped-helper retention control")
        print(process_status(process, 840), flush=True)
        members = list((root(case) / "objects/pack").glob("*/*"))
        require(len(members) == 2 and {path.suffix for path in members} == {".pack", ".idx"},
                "Running retention lacks its actual canonical metadata pair")
        original = {str(path): (path.stat().st_dev, path.stat().st_ino, path.read_bytes()) for path in members}
        helper.send_signal(signal.SIGSTOP)
        stopped = True
        deadline = time.monotonic() + 4
        while True:
            status = (pathlib.Path("/proc") / str(helper.pid) / "status").read_text()
            require(helper.poll() is None, "helper exited before Running retention cancellation")
            if any(line.startswith("State:\tT") or line.startswith("State:\tt") for line in status.splitlines()):
                break
            require(time.monotonic() < deadline, "retention helper stop was not acknowledged")
            time.sleep(0.005)
        process.stdin.write(b"enqueue\n")
        process.stdin.flush()
        lines.until("CANCELLED accepted metadata retention waiter; physical owner retained",
                    timeout=max(0, deadline - time.monotonic()))
        require(time.monotonic() < deadline, "metadata waiter cancellation exceeded stopped interval")
        helper.send_signal(signal.SIGCONT)
        stopped = False
        output, _ = process.communicate(b"resumed\n", timeout=20)
        print(output.decode(), end="", flush=True)
        require(process.returncode == 0 and output.decode().splitlines() == [
            "PASS actual Running metadata retention kept both original inodes and distinct durable pins across later work; no Ready"
        ], "dropped metadata waiter lacks actual physical completion and a later valid acknowledgment")
        for path in members:
            require((path.stat().st_dev, path.stat().st_ino, path.read_bytes()) == original[str(path)],
                    "Running retention replaced or altered a canonical metadata member")
        state = tomllib.loads((root(case) / "state/cache/records.toml").read_text())
        require(len(state["reservations"]) == 4 and len(state["pins"]) == 6
                and len(state["leases"]) == 3 and state["residences"] == []
                and len([lease for lease in state["leases"] if lease["owner"].startswith("metadata:")]) == 2,
                "abandoned retention lost a distinct physical command's durable pin closure")
    finally:
        if stopped and helper.poll() is None:
            helper.send_signal(signal.SIGCONT)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def verify_image():
    """Independently checks final ELF bytes and retained original Cargo events."""
    identity = json.loads((IMAGE / "share/identity.json").read_text())
    require(identity["schema_version"] == 1 and identity["source"] == str(SOURCE)
            and identity["native_cases_executed"] == [], "image source or execution identity mismatch")
    supervisor_source = SOURCE / "tests/terrane/host_cache_vm.py"
    supervisor = IMAGE / "share/host_cache_vm.py"
    supervisor_hash = hashlib.sha256(supervisor.read_bytes()).hexdigest()
    require(identity["supervisor"] == {"source_path": "tests/terrane/host_cache_vm.py",
                                      "installed_path": "share/host_cache_vm.py", "sha256": supervisor_hash}
            and supervisor_hash == identity["input_sha256"]["tests/terrane/host_cache_vm.py"]
            and supervisor.read_bytes() == supervisor_source.read_bytes(),
            "installed VM supervisor differs from immutable source")
    require(pathlib.Path(__file__).read_bytes() == supervisor_source.read_bytes(),
            "executed VM supervisor differs from source")
    helper_name = "manifest_publication_vm.py"
    helper_source = SOURCE / "tests/terrane" / helper_name
    helper_installed = IMAGE / "share" / helper_name
    helper_hash = hashlib.sha256(helper_installed.read_bytes()).hexdigest()
    require(identity["supervisor_helpers"] == {helper_name: {
                "source_path": "tests/terrane/" + helper_name,
                "installed_path": "share/" + helper_name, "sha256": helper_hash}}
            and helper_hash == identity["input_sha256"]["tests/terrane/" + helper_name]
            and helper_installed.read_bytes() == helper_source.read_bytes(),
            "installed manifest supervisor helper differs from immutable source")
    expected = {"host_cache_fixture": ("terrane-fs", "example", ["native-test-fixtures", "tokio"]),
                "terrane": ("terrane-cli", "bin", []), "aos-terrane-host": ("aos-terrane", "bin", []),
                "terrane-fs-unit": ("terrane-fs", "lib", ["native-test-fixtures", "tokio"])}
    require(set(identity["artifacts"]) == set(expected), "incomplete native image executable set")
    packages = json.loads((IMAGE / "share/host-cache-packages.json").read_text())["packages"]
    profile = {"opt_level": "0", "debuginfo": 2, "debug_assertions": True,
               "overflow_checks": True, "test": False}
    source_contract = unit_source_contract()
    for name, (package, kind, features) in expected.items():
        record = identity["artifacts"][name]
        artifact = record["cargo_artifact"]
        original = [json.loads(line) for line in (IMAGE / f"share/host-cache-{name}.jsonl").read_text().splitlines()]
        selected = [item for item in original if item.get("reason") == "compiler-artifact"
                    and item.get("executable") and item.get("target", {}).get("name") == ("terrane_fs" if kind == "lib" else name)]
        metadata_packages = [item for item in packages if item["name"] == package]
        require(len(metadata_packages) == len(selected) == 1 and selected[0] == artifact,
                "retained original Cargo event mismatch: " + name)
        targets = [item for item in metadata_packages[0]["targets"] if item["name"] == ("terrane_fs" if kind == "lib" else name) and item["kind"] == [kind]]
        require(len(targets) == 1 and artifact["target"] == targets[0]
                and artifact["package_id"] == metadata_packages[0]["id"]
                and artifact["profile"] == (source_contract["UNIT_PROFILE"] if kind == "lib" else profile)
                and sorted(artifact["features"]) == features
                and record["installed_path"] == "bin/" + name, "Cargo target/profile/features changed: " + name)
        executable = IMAGE / record["installed_path"]
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        require(executable.read_bytes().startswith(b"\x7fELF")
                and digest == record["cargo_elf_sha256"] == record["installed_elf_sha256"],
                "final installed ELF differs from actual Cargo output: " + name)
    for name, expected_hash in identity["input_sha256"].items():
        path = SOURCE / name if name.startswith("tests/") else SOURCE / "crates" / name
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash, "immutable input hash mismatch: " + name)
    library_path = (IMAGE / "share/runtime-library-path").read_text().strip()
    directories = [pathlib.Path(value) for value in library_path.split(":")]
    require(directories and directories[0] == IMAGE / "lib"
            and all(path.is_dir() and (path == IMAGE / "lib" or path.resolve().is_relative_to("/nix/store")) for path in directories),
            "unsafe runtime library search path")
    require(os.environ.get("LD_LIBRARY_PATH") == library_path, "actual runtime library path differs from image")


def parse_unit_inventory(output):
    """Accepts one complete libtest list rather than a filtered zero-test run."""
    lines = [line for line in output.splitlines() if line]
    require(lines and re.fullmatch(r"\d+ tests?, 0 benchmarks?", lines[-1]),
            "missing actual FS unit inventory summary")
    names = [line.removesuffix(": test") for line in lines[:-1]]
    require(all(line.endswith(": test") for line in lines[:-1])
            and 0 < len(names) <= 4096 and len(names) == len(set(names))
            and int(lines[-1].split()[0]) == len(names), "invalid actual FS unit inventory")
    return sorted(names)


def unit_source_contract():
    """Reads literal reviewed selectors from the immutable source-bound installer."""
    tree = ast.parse((SOURCE / "tests/terrane/host_cache_image.py").read_text())
    values = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            if node.targets[0].id in {"UNIT_TESTS", "UNIT_PREFIXES", "UNIT_PROFILE"}:
                values[node.targets[0].id] = ast.literal_eval(node.value)
    require(set(values) == {"UNIT_TESTS", "UNIT_PREFIXES", "UNIT_PROFILE"}
            and len(values["UNIT_TESTS"]) == len(set(values["UNIT_TESTS"])) == 47,
            "missing immutable FS unit contract")
    return values


# This fresh interpreter runs only after setpriv has dropped every capability
# and group. Its status witness is emitted before exec of the exact bound ELF;
# no native service handle or host-tier write authority enters this process.
UNIT_LAUNCHER = """
import json, os, pathlib, sys
status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines())
assert status["Uid"].split() == ["842"] * 4 and status["Gid"].split() == ["842"] * 4
assert not os.getgroups() and status["NoNewPrivs"].strip() == "1"
for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]:
    assert int(status[key].strip(), 16) == 0, key
print("UNIT_IDENTITY " + json.dumps({key: status[key].strip() for key in
      ["Uid", "Gid", "Groups", "NoNewPrivs", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]}, sort_keys=True), flush=True)
os.execv(sys.argv[1], sys.argv[1:])
"""


def isolated_unit_command(arguments):
    """Selects the non-role identity with no cache groups or capabilities."""
    return ["setpriv", "--reuid", "842", "--regid", "842", "--clear-groups",
            "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
            sys.executable, "-c", UNIT_LAUNCHER, str(IMAGE / "bin/terrane-fs-unit"), *arguments]


def unit_output(result):
    """Requires the actual identity witness and successful subprocess completion."""
    print(result.stdout, end="", flush=True)
    print(result.stderr, end="", flush=True)
    lines = result.stdout.splitlines()
    require(result.returncode == 0 and lines and lines[0].startswith("UNIT_IDENTITY "),
            "isolated FS unit process failed or lacked its identity witness")
    witness = json.loads(lines[0].removeprefix("UNIT_IDENTITY "))
    require(witness["Uid"].split() == ["842"] * 4 and witness["Gid"].split() == ["842"] * 4
            and witness["Groups"] == "" and witness["NoNewPrivs"] == "1"
            and all(int(witness[key], 16) == 0 for key in
                    ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]), "invalid unit identity")
    return "\n".join(lines[1:]), witness


def filesystem_unit_cases():
    """Runs every selected unchanged test on actual ext4, independently by name."""
    identity = json.loads((IMAGE / "share/identity.json").read_text())
    contract = unit_source_contract()
    unit = identity["unit_tests"]
    require(unit["selected_inventory"] == sorted(contract["UNIT_TESTS"])
            and unit["prefixes"] == list(contract["UNIT_PREFIXES"])
            and unit["profile"] == contract["UNIT_PROFILE"]
            and unit["guest_uid"] == unit["guest_gid"] == 842
            and unit["working_directory"] == "crates/terrane-fs", "FS unit source contract changed")
    require(subprocess.check_output(["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(MOUNT)],
                                    text=True, timeout=5).strip() == "ext4", "unit TMPDIR is not actual ext4")
    temporary_root = MOUNT / "unit-tests"
    temporary_root.mkdir(mode=0o700)
    metadata(temporary_root, 842, 842, 0o700)
    cwd = SOURCE / unit["working_directory"]
    records = []
    unit_elf = IMAGE / "bin/terrane-fs-unit"
    unit_hash = hashlib.sha256(unit_elf.read_bytes()).hexdigest()
    try:
        discovery = temporary_root / "discovery"
        discovery.mkdir(mode=0o700)
        metadata(discovery, 842, 842, 0o700)
        environment = dict(os.environ, TMPDIR=str(discovery), RUST_TEST_THREADS="1")
        result = subprocess.run(isolated_unit_command(["--list"]), env=environment, cwd=cwd,
                                text=True, capture_output=True, timeout=30, close_fds=True)
        output, _ = unit_output(result)
        inventory = parse_unit_inventory(output)
        selected = [name for name in inventory if name.startswith(tuple(contract["UNIT_PREFIXES"]))]
        require(inventory == unit["full_inventory"] and selected == unit["selected_inventory"],
                "actual guest FS unit inventory differs from bound artifact")
        shutil.rmtree(discovery)
        for index, name in enumerate(selected):
            temporary = temporary_root / f"case-{index:02d}"
            temporary.mkdir(mode=0o700)
            metadata(temporary, 842, 842, 0o700)
            require(temporary.stat().st_dev == MOUNT.stat().st_dev, "unit scratch left ext4 device")
            environment = dict(os.environ, TMPDIR=str(temporary), RUST_TEST_THREADS="1")
            result = subprocess.run(isolated_unit_command(["--exact", name, "--nocapture", "--test-threads=1"]),
                                    env=environment, cwd=cwd, text=True, capture_output=True,
                                    timeout=30, close_fds=True)
            output, witness = unit_output(result)
            summary_pattern = (r"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; "
                               r"0 measured; (\d+) filtered out; finished in .+$")
            summaries = re.findall(summary_pattern, output)
            require(summaries == [str(len(inventory) - 1)]
                    and f"test {name} ... ok" in output, "FS unit did not execute exactly the selected test: " + name)
            records.append({"name": name, "passed": 1, "failed": 0, "ignored": 0,
                            "filtered": len(inventory) - 1, "identity": witness,
                            "scratch_device": temporary.stat().st_dev, "elf_sha256": unit_hash})
            print("FS_UNIT_RESULT " + json.dumps(records[-1], sort_keys=True), flush=True)
            shutil.rmtree(temporary)
        require(len(records) == 47 and hashlib.sha256(unit_elf.read_bytes()).hexdigest() == unit_hash,
                "incomplete FS ext4 unit execution or changed executable")
        print("PASS all47 focused FS unit cases on ext4 (41 existing plus six admission/snapshot cases); no native Ready claim", flush=True)
    finally:
        shutil.rmtree(temporary_root)


def main():
    """Runs actual helper, actual CLI publisher and isolated native controls."""
    require(os.geteuid() == 0, "VM supervisor requires explicit root administration")
    verify_image()
    filesystem_unit_cases()
    publisher_confinement_cases()
    administrative_preflight("before")
    scaffold()
    administrative_preflight("after")
    quota_config, publisher_config = configurations()
    ledger = ADMIN / "ledger.toml"
    helper_bin = IMAGE / "bin/aos-terrane-host"
    run(admin_command(PROVISION_CAPS, [helper_bin, "provision", "--config", quota_config, "--ledger", ledger]),
        preexec_fn=native_descriptor_budget)
    cold_candidates()
    uuid = subprocess.check_output(["blkid", "-s", "UUID", "-o", "value",
                                    os.environ["TERRANE_CACHE_VM_IMAGE"]], text=True, timeout=5).strip().replace("-", "")
    require(len(uuid) == 32, "actual ext4 UUID unavailable")
    manifest_candidates = seed_manifests(uuid)
    logs = []
    children = []
    try:
        for name in ["helper", "publisher"]:
            logs.append((RUNTIME / (name + ".log")).open("wb"))
        helper = subprocess.Popen(admin_command(QUERY_CAPS, [helper_bin, "serve", "--config", quota_config, "--ledger", ledger]),
                                  stdout=logs[0], stderr=subprocess.STDOUT,
                                  preexec_fn=native_descriptor_budget)
        children.append(helper)
        deadline = time.monotonic() + 10
        while True:
            result = subprocess.run([str(helper_bin), "query", "--config", str(quota_config), "--owner", owner("empty"), "--domain", "public"], capture_output=True, timeout=6)
            if result.returncode == 0:
                break
            require(helper.poll() is None and time.monotonic() < deadline, "actual quota helper failed readiness")
            time.sleep(0.02)
        publisher = subprocess.Popen(role_command(841, [IMAGE / "bin/terrane", "--config", publisher_config, "--role", "publish"]),
                                     stdout=logs[1], stderr=subprocess.STDOUT,
                                     preexec_fn=native_descriptor_budget)
        children.append(publisher)
        deadline = time.monotonic() + 15
        while True:
            result = subprocess.run(role_command(840, [IMAGE / "bin/host_cache_fixture", "prepare"]), env=actor_environment("empty", uuid), text=True, capture_output=True, timeout=12)
            if result.returncode == 0:
                require("PASS actual native preparation" in result.stdout, "no actual preparation witness")
                print(result.stdout, end="", flush=True)
                break
            require(publisher.poll() is None and time.monotonic() < deadline, "actual configured CLI publisher failed preparation: " + result.stderr)
            time.sleep(0.02)
        print(process_status(publisher, 841), flush=True)
        actor("empty", "empty", uuid)
        # The successful recovery's durable bootstrap hold is itself cold state;
        # a restart must refuse it rather than silently clear or reuse capacity.
        actor("empty", "refuse", uuid)
        for case in ["pin", "lease", "reservation", "residence", "unknown", "state-file", "state-directory"]:
            candidate = (root(case) / "state/cache/records.toml" if case in {"pin", "lease", "reservation", "residence"}
                         else root(case) / "chunks/unrecognized-name" if case == "unknown"
                         else root(case) / "state/unhandled.tmp" if case == "state-file" else None)
            before = {str(candidate): hashlib.sha256(candidate.read_bytes()).hexdigest()} if candidate else {}
            directory_identity = (root(case) / "state/old-policy").stat().st_ino if case == "state-directory" else None
            if case == "unknown":
                output = actor(case, "late-refuse", uuid)
                require(output.splitlines() == [
                    "PASS actual late refusal retained funded hold, faulted custody and unchanged unknown inode; no Resume"
                ], "missing exact funded late-refusal witness")
            else:
                actor(case, "refuse", uuid)
            for name, digest in before.items():
                require(pathlib.Path(name).is_file() and hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() == digest,
                        "cold candidate was changed or deleted: " + name)
            if case == "state-directory":
                path = root(case) / "state/old-policy"
                require(path.is_dir() and path.stat().st_ino == directory_identity and list(path.iterdir()) == [],
                        "unknown state directory changed or disappeared")
        cancel_case(helper, uuid)
        exclusive_case(uuid)
        actor("edquot", "edquot", uuid)
        admission_cases(helper, uuid)
        publication_cases(publisher, uuid)
        inline_transfer_cases(publisher, uuid)
        # Preserve resource facts at the failed preparation boundary without
        # changing limits, retrying physical work or weakening its assertions.
        try:
            process_root = pathlib.Path(f"/proc/{publisher.pid}")
            filesystem = os.statvfs(MOUNT)
            print("PUBLISHER_PREPARATION_RESOURCES " + json.dumps({
                "open_descriptors": len(list((process_root / "fd").iterdir())),
                "limits": (process_root / "limits").read_text(),
                "filesystem_available_bytes": filesystem.f_bavail * filesystem.f_frsize,
                "filesystem_available_inodes": filesystem.f_favail,
            }, sort_keys=True), flush=True)
        except OSError as error:
            print("PUBLISHER_PREPARATION_RESOURCES unavailable: " + str(error), flush=True)
        running_retention_cases(helper, uuid)
        runpy.run_path(str(IMAGE / "share/manifest_publication_vm.py"))["run"](sys.modules[__name__], publisher, uuid)
        manifest_recovery_cases(uuid, manifest_candidates, helper)
        print("PASS bounded native cache recovery, encoded admission and inline publication; full Running publication/BKT15 remain unqualified", flush=True)
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.send_signal(signal.SIGCONT)
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        for log in logs:
            log.close()
        for name in ["helper", "publisher"]:
            path = RUNTIME / (name + ".log")
            if path.exists():
                print(name + " actual process log:\n" + path.read_text(errors="replace"), flush=True)


if __name__ == "__main__":
    main()
