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
        "--property=Id,LoadState,ActiveState,MainPID,InvocationID,FragmentPath,ControlGroup"],
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
    marker = Path(request["root"]) / ("foreign.invocations" if name.endswith("foreign") else "selected.invocations")
    invocations = marker.read_text().splitlines() if marker.exists() else []
    if any(line != "invoked" for line in invocations):
        raise RuntimeError("unexpected process-owned invocation marker")
    value = {"owners": ["systemd:" + unit] if exists else [],
             "unitPresent": exists, "unitDigest": digest, "unitMetadata": unit_metadata,
             "active": properties.get("ActiveState") == "active",
             "command": command, "processCount": len(processes),
             "invocations": len(invocations)}
    if raw:
        value.update(properties=properties, processes=processes)
    return value


def selected():
    operation = request["operation"]
    if operation == "realize":
        return service("native-service-qualification")
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
        return {"owners": ["membership:aos-nq-members:aos-nq-member"] if granted else [],
                "granted": granted, "members": members}
    raise RuntimeError("unsupported live account observation")


foreign_members = account("group", "aos-nq-members")
if foreign_members is None or "aos-nq-foreign" not in foreign_members[3].split(","):
    raise RuntimeError("foreign membership disappeared")
print(json.dumps({"selected": selected(), "foreign": {
    "service": service("native-service-foreign", raw=True),
    "group": account("group", "aos-nq-foreign"),
    "principal": account("passwd", "aos-nq-foreign"),
    "membership": "aos-nq-foreign" in foreign_members[3].split(","),
}}, sort_keys=True))
'''


def supports(cell, adapter, graph):
    """Accepts only implemented native durability scenarios and actual host effects."""
    pair = (cell["operation"]["ability"], cell["operation"]["name"])
    return (
        pair in OPERATIONS
        and cell["action"] in {"apply", "remove"}
        and cell["scenario"]["id"] in SCENARIOS
        and any(node["identity"][-3:] == [*pair, "native-service-qualification"]
                and node["handler"] == adapter["handler"]
                and node["identity"][:-4] == cell["scope"]
                for node in graph["nodes"].values())
    )


def observe(operation):
    """Executes the source-backed oracle through the guest's AOS-built Python."""
    encoded = base64.b64encode(ORACLE_SOURCE.encode()).decode()
    launcher = "import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<native-service-oracle>','exec'))"
    request = {"operation": operation, "root": ROOT, "systemctl": SYSTEMCTL}
    return json.loads(runtime.succeed(f"{PYTHON} -c {shlex.quote(launcher)} {shlex.quote(json.dumps(request))}"))


def selected_effect(graph, cell, adapter):
    """Requires the controlled resource in the authenticated native evaluation."""
    pair = [cell["operation"]["ability"], cell["operation"]["name"]]
    effects = [effect for effect, node in graph["nodes"].items()
               if node["identity"][-3:] == pair + ["native-service-qualification"]
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


def run_cell(cell, adapter, graph):
    """Retains exact descriptor, interruption, real substrate, and isolation proof."""
    if not supports(cell, adapter, graph):
        raise RuntimeError("service/account cell has no concrete native proof route")
    operation = cell["operation"]["name"]
    control = "service" if operation == "realize" else operation
    slug = hashlib.sha256(cell["id"].encode()).hexdigest()[:20]
    unit = "native-service-" + slug
    original = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-original", extra_module=OBSERVER_HOST_MODULE)
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
    retired = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-retired", {
        "aos": {"nativeServiceQualification": {"enabled": {control: False}},
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
    NATIVE_FLIGHT.run(flight, NATIVE_BUILDER, lambda: observe(operation), expected)
    apply_reference(original, unit + "-restore")
