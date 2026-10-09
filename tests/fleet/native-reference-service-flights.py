"""Runs admitted service and account flights with independent live observations.

The selected descriptor stays byte-for-byte equal to the matrix projection.
Apply recreates an explicitly retired fixture resource; remove retains its
checked predecessor graph. Systemd dispatch attempts are separate from the
process-written invocation marker and account database observations.
"""

import base64
import hashlib
import json
import shlex

OPERATIONS = {
    ("serviceManagement", "realize"),
    ("identity", "group"),
    ("identity", "principal"),
    ("identity", "membership"),
}
SCENARIOS = {
    "interrupt-after-durable-intent",
    "lose-external-result",
    "interrupt-after-durable-outcome",
    "cancel-pending-invocation",
    "expire-invocation-deadline",
    "fail-manager-after-dispatch-attempt",
    "reject-uncertain-recovery",
    "activate-retained-target",
    "reject-foreign-resource-mutation",
    "block-dependent-effect",
}
ROOT = "/var/lib/aos/native-service-qualification"

# This program runs inside the resource-owning guest. It deliberately reads
# systemd, procfs, and account databases rather than private handler receipts.
ORACLE_SOURCE = r'''
import hashlib
import json
from pathlib import Path
import subprocess
import stat
import sys

request = json.loads(sys.argv[1])


def account(database, name):
    rows = [line.split(":") for line in Path("/etc/" + database).read_text().splitlines()
            if line.split(":", 1)[0] == name]
    if len(rows) > 1:
        raise RuntimeError("duplicate account database identity")
    return rows[0] if rows else None


def service(name, raw=False):
    unit = name + ".service"
    result = subprocess.run([request["systemctl"], "show", unit,
        "--property=Id,LoadState,ActiveState,MainPID,ExecMainPID,InvocationID,FragmentPath,ControlGroup"],
        check=False, capture_output=True, text=True)
    properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if result.returncode and properties.get("LoadState") != "not-found":
        raise RuntimeError("systemd unit observation failed")
    if not {"LoadState", "ActiveState", "MainPID"}.issubset(properties):
        raise RuntimeError("incomplete systemd unit observation")
    fragment = Path("/etc/systemd/system") / unit
    if fragment.is_symlink():
        raise RuntimeError("selected manager unit is an unexpected symbolic link")
    exists = fragment.is_file()
    metadata = fragment.stat() if exists else None
    unit_metadata = {"uid": metadata.st_uid, "gid": metadata.st_gid,
                     "mode": stat.S_IMODE(metadata.st_mode)} if metadata else None
    digest = hashlib.sha256(fragment.read_bytes()).hexdigest() if exists else None
    pid = int(properties.get("MainPID", "0"))
    if not pid and properties.get("ActiveState") == "activating":
        pid = int(properties.get("ExecMainPID", "0"))
    command = []
    processes = []
    if pid:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
        cgroup = properties.get("ControlGroup", "")
        if not cgroup.startswith("/") or ".." in Path(cgroup).parts:
            raise RuntimeError("invalid observed service cgroup")
        processes = sorted(int(value) for value in (Path("/sys/fs/cgroup") / cgroup.lstrip("/") / "cgroup.procs").read_text().split())
        if pid not in processes:
            raise RuntimeError("main process is absent from its real cgroup")
    marker_name = {"native-service-foreign": "foreign", "native-service-qualification": "selected",
                   "native-service-deadline": "deadline", "native-service-deadline-remove": "deadline-remove"}[name]
    marker = Path(request["root"]) / (marker_name + ".invocations")
    invocations = marker.read_text().splitlines() if marker.exists() else []
    if any(line != "invoked" for line in invocations):
        raise RuntimeError("unexpected process-owned invocation marker")
    value = {"owners": ["systemd:" + unit] if exists else [],
             "unitPresent": exists, "unitDigest": digest, "unitMetadata": unit_metadata,
             "active": properties.get("ActiveState") == "active",
             "command": command, "processCount": len(processes),
             "invocations": len(invocations)}
    if name == "native-service-deadline-remove":
        stop_marker = Path(request["root"]) / "deadline-stop.invocations"
        stop_lines = stop_marker.read_text().splitlines() if stop_marker.exists() else []
        if any(line != "invoked" for line in stop_lines):
            raise RuntimeError("unexpected stop command invocation marker")
        value["stopInvocations"] = len(stop_lines)
    if raw:
        value.update(properties=properties, processes=processes)
    return value



def account_mount():
    path = "/etc/group"
    records = []

    def decode(value):
        for escaped, literal in ((r"\040", " "), (r"\011", "\t"), (r"\012", "\n"), (r"\134", "\\")):
            value = value.replace(escaped, literal)
        return value

    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, separator, after = line.partition(" - ")
        fields, filesystem = before.split(), after.split()
        if not separator or len(fields) < 6 or len(filesystem) < 3:
            raise RuntimeError("invalid live mount information")
        if decode(fields[4]) == path:
            records.append((fields, filesystem))
    if not records:
        return None
    if len(records) != 1:
        raise RuntimeError("ambiguous account database mount")
    fields, filesystem = records[0]
    options = sorted(fields[5].split(","))
    if "ro" not in options or "rw" in options:
        raise RuntimeError("account database is not protected by its read-only mount")
    return {"kind": "read-only-account-database", "path": path,
            "mountId": int(fields[0]), "device": fields[2], "root": decode(fields[3]),
            "mountPoint": decode(fields[4]), "options": options,
            "filesystem": filesystem[0], "source": decode(filesystem[1]),
            "superOptions": sorted(filesystem[2].split(",")),
            "contentSha256": "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()}

def selected():
    operation = request["operation"]
    if operation == "realize":
        return service(request.get("service", "native-service-qualification"))
    if operation == "group":
        row = account("group", "aos-nq-selected")
        return {"owners": ["group:" + row[0]] if row else [], "row": row}
    if operation == "principal":
        row = account("passwd", "aos-nq-selected")
        return {"owners": ["principal:" + row[0]] if row else [], "row": row}
    if operation == "membership":
        row = account("group", "aos-nq-members")
        if row is None:
            raise RuntimeError("membership group disappeared")
        members = sorted(filter(None, row[3].split(",")))
        granted = "aos-nq-member" in members
        value = {"owners": ["membership:aos-nq-members:aos-nq-member"] if granted else [],
                 "granted": granted, "members": members}
        if request.get("accountMount"):
            value["precondition"] = account_mount()
        return value
    raise RuntimeError("unsupported live account observation")


foreign_members = account("group", "aos-nq-members")
if foreign_members is None or "aos-nq-foreign" not in foreign_members[3].split(","):
    raise RuntimeError("foreign membership disappeared")
print(json.dumps({"selected": selected(), "foreign": {
    "service": service("native-service-foreign", raw=True),
    "group": account("group", "aos-nq-foreign"),
    "principal": account("passwd", "aos-nq-foreign"),
    "membership": "aos-nq-foreign" in foreign_members[3].split(","),
    # Membership owns a pair, not its upstream group or principal. Preserve
    # those actual row identities while allowing the selected pair to change.
    "membershipGroupIdentity": foreign_members[:3],
    "membershipPrincipal": account("passwd", "aos-nq-member"),
}}, sort_keys=True))
'''



def resource_name(cell):
    """Selects the authored blocking service only for real deadline cells."""
    if cell["operation"]["name"] == "realize" and cell["scenario"]["id"] == "expire-invocation-deadline":
        return "native-service-deadline" + ("-remove" if cell["action"] == "remove" else "")
    return "native-service-qualification"

def supports(cell, adapter, graph):
    """Accepts concrete native proof routes and authenticated controlled effects."""
    pair = (cell["operation"]["ability"], cell["operation"]["name"])
    return (
        pair in OPERATIONS
        and cell["action"] in {"apply", "remove"}
        and not (cell["scenario"]["id"] == "activate-retained-target" and cell["action"] != "apply")

        and cell["scenario"]["id"] in SCENARIOS
        and any(node["identity"][-3:] == [*pair, resource_name(cell)]
                and node["handler"] == adapter["handler"]
                and node["identity"][:-4] == cell["scope"]
                for node in graph["nodes"].values())
    )


def observe(operation, service_name="native-service-qualification", account_mount=False):
    """Executes the source-backed oracle through the guest's AOS-built Python."""
    encoded = base64.b64encode(ORACLE_SOURCE.encode()).decode()
    launcher = "import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<native-service-oracle>','exec'))"
    request = {"operation": operation, "root": ROOT, "systemctl": SYSTEMCTL, "service": service_name, "accountMount": account_mount}
    return json.loads(runtime.succeed(f"{PYTHON} -c {shlex.quote(launcher)} {shlex.quote(json.dumps(request))}"))


def selected_effect(graph, cell, adapter):
    """Requires the controlled resource in the authenticated native evaluation."""
    pair = [cell["operation"]["ability"], cell["operation"]["name"]]
    effects = [effect for effect, node in graph["nodes"].items()
               if node["identity"][-3:] == pair + [resource_name(cell)]
               and node["handler"] == adapter["handler"]
               and node["identity"][:-4] == cell["scope"]]
    if len(effects) != 1:
        raise RuntimeError("controlled native operation has no unique admitted effect")
    return effects[0]


def wait_process(name):
    """Waits for the actual exec transition before recording a stable witness."""
    unit = shlex.quote(name + ".service")
    runtime.wait_until_succeeds(
        f"{SYSTEMCTL} is-active --quiet {unit} && "
        f'test "$({COREUTILS}/cat /proc/$({SYSTEMCTL} show --property=MainPID --value {unit})/comm)" = sleep',
        timeout=180,
    )



def hold_account_lock(unit):
    """Holds the real account backend's POSIX lock in an independent process."""
    marker = ROOT + "/" + unit + ".lock-ready"
    lock_unit = unit + "-account-lock"
    program = """import fcntl, os, time
from pathlib import Path
lock = os.open('/etc/.pwd.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
fcntl.lockf(lock, fcntl.LOCK_EX)
Path(%r).write_text(str(os.getpid()))
while True:
    time.sleep(1)
""" % marker
    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(marker)}")
    runtime.succeed(f"{SYSTEMD_RUN} --unit={shlex.quote(lock_unit)} --property=Type=exec "
                    f"{PYTHON} -c {shlex.quote(program)}")
    runtime.wait_until_succeeds(f"test -s {shlex.quote(marker)}", timeout=30)
    # A marker alone cannot prove lock ownership. Check the kernel's live
    # POSIX write-lock record against the actual lock inode and process.
    verification = """from pathlib import Path
import os
pid = int(Path(%r).read_text())
metadata = os.stat('/etc/.pwd.lock')
identity = f'{os.major(metadata.st_dev):02x}:{os.minor(metadata.st_dev):02x}:{metadata.st_ino}'
rows = [line.split() for line in Path('/proc/locks').read_text().splitlines()]
assert any(row[1:5] == ['POSIX', 'ADVISORY', 'WRITE', str(pid)] and row[5] == identity for row in rows)
os.kill(pid, 0)
""" % marker
    runtime.succeed(f"{PYTHON} -c {shlex.quote(verification)}")


def run_service_deadline(cell, adapter, graph):
    """Dispatches an admitted unbounded unit command under the native deadline."""
    name = resource_name(cell)
    effect = selected_effect(graph, cell, adapter)
    node = graph["nodes"][effect]
    unit = "native-deadline-" + hashlib.sha256(cell["id"].encode()).hexdigest()[:20]
    enabled = {"deadline": False, "deadlineRemove": cell["action"] == "remove"}
    original = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-baseline",
        {"aos": {"nativeServiceQualification": {"enabled": enabled}}}, extra_module=OBSERVER_HOST_MODULE)
    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(NATIVE_FLIGHT.TARGET)}")
    apply_reference(original, unit + "-baseline")
    wait_process("native-service-foreign")
    predecessor = current_reference_graph()
    if cell["action"] == "remove":
        wait_process(name)
        current = predecessor["nodes"][effect]
        if current["revision"] != node["revision"]:
            raise RuntimeError("blocking removal fixture differs from its admitted source")
        expected = observe("realize", name)["selected"]
        expected.update(active=False, processCount=2, stopInvocations=1)
        settings = {"aos": {"nativeServiceQualification": {"enabled": {"deadline": False, "deadlineRemove": False}},
                            "activation": {"retire": [effect]}}}
    else:
        # Expected bytes come from the admitted renderer and exact original
        # input before dispatch. They are never copied from the settled unit.
        output = ROOT + "/" + unit + "-render"
        payload = dict(node["input"], enable=True)
        renderer = SERVICE_RENDERER
        runtime.succeed(f"printf %s {shlex.quote(json.dumps({name: payload}))} | "
                        f"{shlex.quote(renderer)} render --output-dir {shlex.quote(output)}")
        digest = runtime.succeed(f"{COREUTILS}/sha256sum {shlex.quote(output + '/' + name + '.service')}").split()[0]
        expected = {"owners": ["systemd:" + name + ".service"], "unitPresent": True,
                    "unitDigest": digest, "unitMetadata": {"uid": 0, "gid": 0, "mode": 420},
                    "active": False, "command": [COREUTILS + "/sleep", "infinity"],
                    "processCount": 1, "invocations": 1}
        runtime.succeed(f"{COREUTILS}/rm -f {ROOT}/deadline.invocations")
        settings = {"aos": {"nativeServiceQualification": {"enabled": {"deadline": True, "deadlineRemove": False}}}}
    candidate = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-candidate", settings,
                                         extra_module=OBSERVER_HOST_MODULE)
    flight = NATIVE_FLIGHT.NativeFlight(cell, effect, candidate, unit,
                                       predecessor if cell["action"] == "remove" else None)
    NATIVE_FLIGHT.run_pending_control(flight, NATIVE_BUILDER, lambda: observe("realize", name),
                                     expected, prepare_block=lambda: None)


MARKER_ORACLE_SOURCE = r'''import hashlib
import json
import os
import stat
import sys
from pathlib import Path

name = sys.argv[1]
root = Path('/var/lib/aos/native-dependency-barrier')
if root.exists():
    directory = root.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or stat.S_IMODE(directory.st_mode) != 0o700:
        raise RuntimeError('marker directory is not an independent protected substrate')


def marker(name):
    path = root / name
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"owners": [], "exists": False}
    with os.fdopen(descriptor, 'rb') as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RuntimeError('marker is not a protected physical claim')
        contents = source.read(16385)
    if len(contents) > 16384:
        raise RuntimeError('marker claim exceeds its bound')
    claim = json.loads(contents)
    if set(claim) != {'effect','revision'} or any(not isinstance(value,str) or not value for value in claim.values()):
        raise RuntimeError('invalid physical marker claim')
    return {"owners": [claim['effect']], "exists": True, "claim": claim,
            "inode": metadata.st_ino, "device": metadata.st_dev,
            "digest": 'sha256:' + hashlib.sha256(contents).hexdigest()}


print(json.dumps({'selected':marker(name),'foreign':marker('foreign-marker')},sort_keys=True))
'''


def observe_marker(name):
    """Reads a physical marker claim and independent protected foreign marker."""
    return json.loads(runtime.succeed(f"{PYTHON} -c {shlex.quote(MARKER_ORACLE_SOURCE)} {shlex.quote(name)}"))


def run_dependency_cell(cell, adapter, graph):
    """Blocks a genuine graph successor or reverse-removal predecessor."""
    operation = cell["operation"]["name"]
    control_name = "service" if operation == "realize" else operation
    unit = "native-dependency-" + hashlib.sha256(cell["id"].encode()).hexdigest()[:20]
    original = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-original",
        {"aos": {"nativeServiceQualification": {"enabled": {"deadline": False, "deadlineRemove": False}}}},
        extra_module=OBSERVER_HOST_MODULE)
    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(NATIVE_FLIGHT.TARGET)}")
    apply_reference(original, unit + "-baseline")
    wait_process("native-service-foreign")
    if operation == "realize":
        wait_process("native-service-qualification")
    predecessor = current_reference_graph()
    effect = selected_effect(predecessor, cell, adapter)
    if predecessor["nodes"][effect] != graph["nodes"][selected_effect(graph, cell, adapter)]:
        raise RuntimeError("dependency producer differs from its admitted original source")
    expected = observe(operation)["selected"]
    settings = {"aos": {"nativeServiceQualification": {"enabled": {
        "service": False, "group": False, "principal": False, "membership": False,
        "deadline": False, "deadlineRemove": False}}}}
    retire_source = (OBSERVER_HOST_MODULE + "\n"
        "aos.nativeDependencyBarrier.requests = lib.mkForce {foreign-marker = {name = \"foreign-marker\";};};\n"
        "aos.nativeServiceQualification.dependencyParents = lib.mkForce {service=null;group=null;principal=null;membership=null;};\n")
    retired = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-retired", settings,
                                       extra_module=retire_source)
    if cell["action"] == "apply":
        apply_reference(retired, unit + "-prepare")
        if operation == "realize":
            runtime.succeed(f"{COREUTILS}/rm -f {ROOT}/selected.invocations")
            expected["invocations"] = 1
        candidate = original
        marker_name = control_name + "-child"
        selected_graph = graph
    else:
        candidate = retired
        marker_name = control_name + "-parent"
        selected_graph = predecessor
        if operation == "realize":
            expected.update(owners=[], unitPresent=False, unitDigest=None, unitMetadata=None,
                            active=False, command=[], processCount=0)
        elif operation in {"group", "principal"}:
            expected = {"owners": [], "row": None}
        else:
            expected.update(owners=[], granted=False,
                            members=[member for member in expected["members"] if member != "aos-nq-member"])
    markers = [key for key,node in selected_graph["nodes"].items()
               if node["identity"][-3:] == ["nativeDependencyBarrier","ensure",marker_name]]
    if len(markers) != 1:
        raise RuntimeError("dependency marker has no unique admitted graph node")
    response_control = {}

    def hold_response():
        response_control.update(NATIVE_FLIGHT.arm_handler_response(cell["action"]))

    flight = NATIVE_FLIGHT.NativeFlight(cell, effect, candidate, unit, selected_graph)
    NATIVE_FLIGHT.run_dependency_block(flight, NATIVE_BUILDER, lambda: observe(operation), expected,
        markers[0], lambda: observe_marker(marker_name), hold_response)
    NATIVE_FLIGHT.captured_handler_response(response_control)

def run_cell(cell, adapter, graph):
    """Retains exact descriptor, interruption, real substrate, and isolation proof."""
    if not supports(cell, adapter, graph):
        raise RuntimeError("service/account cell has no concrete native proof route")
    if cell["scenario"]["id"] == "block-dependent-effect":
        return run_dependency_cell(cell, adapter, graph)
    if resource_name(cell) != "native-service-qualification":
        return run_service_deadline(cell, adapter, graph)
    operation = cell["operation"]["name"]
    control = "service" if operation == "realize" else operation
    slug = hashlib.sha256(cell["id"].encode()).hexdigest()[:20]
    unit = "native-service-" + slug
    original = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-original",
        {"aos": {"nativeServiceQualification": {"enabled": {"deadline": False, "deadlineRemove": False}}}},
        extra_module=OBSERVER_HOST_MODULE)
    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(NATIVE_FLIGHT.TARGET)}")
    apply_reference(original, unit + "-baseline")
    wait_process("native-service-foreign")
    if operation == "realize":
        wait_process("native-service-qualification")
    predecessor = current_reference_graph()
    effect = selected_effect(predecessor, cell, adapter)
    admitted = graph["nodes"][selected_effect(graph, cell, adapter)]
    if predecessor["nodes"][effect]["revision"] != admitted["revision"]:
        raise RuntimeError("fixture revision differs from the admitted matrix source")
    expected = observe(operation)["selected"]
    baseline_row = expected.get("row")
    if cell["scenario"]["id"] == "activate-retained-target":
        # Re-evaluate the exact original source through normal admission. The
        # checked retained receipt must suppress any selected redispatch while
        # the live process/account and independent foreign witness stay equal.
        flight = NATIVE_FLIGHT.NativeFlight(cell, effect, original, unit, predecessor)
        NATIVE_FLIGHT.run_retained_transition(flight, NATIVE_BUILDER, lambda: observe(operation), expected)
        return
    retired = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-retired", {
        "aos": {"nativeServiceQualification": {"enabled": {control: False, "deadline": False, "deadlineRemove": False}},
                "activation": {"retire": [effect]}}
    }, extra_module=OBSERVER_HOST_MODULE)
    if cell["action"] == "apply":
        # Retire through an ordinary source transaction before recreating the
        # exact original revision. The candidate descriptor never changes.
        apply_reference(retired, unit + "-prepare")
        if operation == "realize":
            runtime.succeed(f"{COREUTILS}/rm -f {ROOT}/selected.invocations")
            expected["invocations"] = 1
        candidate = original
    else:
        candidate = retired
        if operation == "realize":
            expected.update(owners=[], unitPresent=False, unitDigest=None, unitMetadata=None, active=False,
                            command=[], processCount=0)
        elif operation in {"group", "principal"}:
            expected = {"owners": [], "row": None}
        else:
            expected.update(owners=[], granted=False,
                            members=[member for member in expected["members"] if member != "aos-nq-member"])
    flight = NATIVE_FLIGHT.NativeFlight(cell, effect, candidate, unit,
                                       predecessor if cell["action"] == "remove" else None)
    if cell["scenario"]["id"] in {"cancel-pending-invocation", "expire-invocation-deadline"}:
        # Cancellation precedes dispatch; the account deadline blocks on the
        # actual shared POSIX account lock before any row can be mutated.
        unchanged = observe(operation)["selected"]
        prepare = (lambda: hold_account_lock(unit)) if operation != "realize" else None
        NATIVE_FLIGHT.run_pending_control(flight, NATIVE_BUILDER, lambda: observe(operation),
                                         unchanged, prepare_block=prepare)
        return
    if cell["scenario"]["id"] in {"fail-manager-after-dispatch-attempt", "reject-uncertain-recovery", "reject-foreign-resource-mutation"}:
        if operation == "membership" and cell["scenario"]["id"] == "reject-foreign-resource-mutation":
            expected = observe(operation, account_mount=True)["selected"]
            mounted = False

            def protect_account_database():
                nonlocal mounted
                runtime.succeed(f"{MOUNT} --bind /etc/group /etc/group")
                mounted = True
                runtime.succeed(f"{MOUNT} --options remount,bind,ro /etc/group")
                precondition = observe(operation, account_mount=True)["selected"]["precondition"]
                if precondition is None:
                    raise RuntimeError("protected account database has no actual mount")
                expected["precondition"] = precondition
            try:
                NATIVE_FLIGHT.run_rejection(flight, NATIVE_BUILDER,
                    lambda: observe(operation, account_mount=True), expected, protect_account_database)
            finally:
                # Only the independent fixture mount is released; the native
                # failed journal and account rows remain intact for inspection.
                if mounted:
                    runtime.succeed(f"{UMOUNT} /etc/group")
            return
        if operation == "membership":
            control = {}

            def arm_observation():
                operation_to_hold = cell["action"] if cell["scenario"]["id"] == "fail-manager-after-dispatch-attempt" else "observe"
                control.update(NATIVE_FLIGHT.arm_handler_response(operation_to_hold))

            NATIVE_FLIGHT.run_rejection(flight, NATIVE_BUILDER, lambda: observe(operation), expected,
                                       arm_observation)
            NATIVE_FLIGHT.captured_handler_response(control)
            return
        if operation in {"group", "principal"}:
            conflict_row = list(baseline_row)
            conflict_row[2] = "61509"
            expected = {"owners": [operation + ":aos-nq-selected"], "row": conflict_row}

            def inject_account():
                database = "group" if operation == "group" else "passwd"
                program = r"""import fcntl, os
from pathlib import Path
lock = os.open('/etc/.pwd.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
fcntl.lockf(lock, fcntl.LOCK_EX)
path = Path('/etc/' + %r)
row = %r
rows = path.read_text().splitlines()
rows = [line for line in rows if line.split(':', 1)[0] != row[0]]
rows.append(':'.join(row))
path.write_text('\n'.join(rows) + '\n')
os.close(lock)
""" % (database, conflict_row)
                runtime.succeed(f"{PYTHON} -c {shlex.quote(program)}")
            # Before-remove interruption preserves the original owned row.
            # This boundary proves an attempted dispatch, not invocation.
            boundary = "dispatch-started" if cell["action"] == "remove" else "dispatch-returned"
            NATIVE_FLIGHT.run_rejection(flight, NATIVE_BUILDER, lambda: observe(operation), expected,
                                       inject_account, interruption_boundary=boundary)
            return
        # Only the selected disposable unit is replaced. This is an actual
        # ownership conflict, not a fabricated handler failure or journal edit.
        conflict = b"[Unit]\nDescription=Independent selected resource conflict\n"
        if cell["scenario"]["id"] in {"fail-manager-after-dispatch-attempt", "reject-foreign-resource-mutation"}:
            expected = observe(operation)["selected"]
        expected.update(owners=["systemd:native-service-qualification.service"], unitPresent=True,
                        unitDigest=hashlib.sha256(conflict).hexdigest(),
                        unitMetadata={"uid": 0, "gid": 0, "mode": 420})

        def inject():
            encoded = base64.b64encode(conflict).decode()
            program = ("import base64,os;from pathlib import Path;"
                       "p=Path('/etc/systemd/system/native-service-qualification.service');"
                       "assert not p.is_symlink();"
                       "p.write_bytes(base64.b64decode(" + repr(encoded) + "));os.chmod(p,0o644)")
            runtime.succeed(f"{PYTHON} -c {shlex.quote(program)}")
        NATIVE_FLIGHT.run_rejection(flight, NATIVE_BUILDER, lambda: observe(operation), expected, inject)
        return
    NATIVE_FLIGHT.run(flight, NATIVE_BUILDER, lambda: observe(operation), expected)
    apply_reference(original, unit + "-restore")
