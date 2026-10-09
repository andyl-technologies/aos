"""Connect the confined held request to a real ordinary Native index command.

Fleet owns the initial Nginx route and actual SQL/transport observers. This
helper supplies listener/process custody and the exact public placement update;
it does not authenticate a plan or infer provider counts from a refusal.
"""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import time


def _module(file, name):
    specification = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _guest(machine, tools, action, values):
    code = Path(__file__).read_text()
    selected = {"action": action, "values": values}
    program = code + "\nprint(json.dumps(_guest_action(json.loads(base64.b64decode(" \
        + repr(base64.b64encode(json.dumps(selected).encode()).decode()) + ")))))\n"
    command = shlex.quote(tools["python"]) + " - <<'STALE_INDEX_PROGRAM'\n" \
        + program + "STALE_INDEX_PROGRAM\n"
    status, stdout, _ = machine.agent.request(command.encode(), timeout=45)
    if status:
        raise RuntimeError("Stale-index guest operation failed; private originals retained")
    return json.loads(stdout)


def _control(installation, request):
    process = _module(installation["processModuleFile"], "stale_process")
    if process.process_identity(installation["process"]["pid"]) != installation["process"]:
        raise ValueError("Stale-index listener lifetime changed")
    body = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(5)
        channel.connect(installation["socketFile"])
        pid, uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != installation["process"]["pid"] or uid != os.getuid():
            raise ValueError("Stale-index control peer changed")
        channel.sendall(body)
        response = bytearray()
        while True:
            chunk = channel.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > 16384:
                raise ValueError("Stale-index control reply exceeds bound")
    reply = json.loads(response)
    if set(reply) != {"version", "status", "result"} or reply["version"] != 1 \
            or reply["status"] != "observed":
        raise ValueError("Stale-index control refused")
    return reply["result"]


def _guest_action(selected):
    os.umask(0o077)
    value = selected["values"]
    action = selected["action"]
    process = _module(value["processModuleFile"], "stale_process")
    if action == "start-listener":
        configuration = value["configuration"]
        root = Path(configuration["root"])
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        configuration_file = root / "configuration.private.json"
        process.private_write(configuration_file, json.dumps(configuration).encode())
        argv = [value["node"], value["listenerFile"], str(configuration_file)]
        with (root / "process.log").open("xb") as output:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                stderr=output, start_new_session=True)
        deadline = time.monotonic() + 10
        while not (root / "ready.json").exists():
            if child.poll() is not None or time.monotonic() >= deadline:
                raise ValueError("Stale-index listener did not become ready; child retained")
            time.sleep(0.05)
        pin = process.process_identity(child.pid)
        if pin["ownerUid"] != os.getuid():
            raise ValueError("Stale-index listener owner differs")
        ready = json.loads((root / "ready.json").read_bytes())
        if ready["pid"] != child.pid or ready["port"] != configuration["listenPort"]:
            raise ValueError("Stale-index listener selection differs")
        with Path(value["node"]).open("rb") as executable:
            expected = hashlib.file_digest(executable, "sha256").hexdigest()
        if pin["executableSha256"] != expected:
            raise ValueError("Stale-index Node executable differs")
        receipt = {"version": 1, "process": pin, "arguments": argv,
            "configurationFile": str(configuration_file),
            "configurationSha256": hashlib.sha256(configuration_file.read_bytes()).hexdigest(),
            "listenerSha256": hashlib.sha256(Path(value["listenerFile"]).read_bytes()).hexdigest(),
            "holdModuleSha256": hashlib.sha256(Path(configuration["holdModuleFile"]).read_bytes()).hexdigest(),
            "processModuleFile": value["processModuleFile"], "socketFile": ready["socketFile"],
            "root": str(root), "scope": "actual fixture listener custody only"}
        process.private_write(root / "installation.json", json.dumps(receipt).encode())
        return receipt
    if action == "capture-environment":
        return process.capture_environment(value["nativeProcess"], value["file"])
    if action == "control":
        return _control(value["installation"], value["request"])
    if action == "launch-index":
        root = Path(value["root"])
        root.mkdir(mode=0o700, exist_ok=False)
        process.checked_environment(value["environment"], value["executable"])
        process.private_write(root / "selection.private.json", json.dumps(value).encode())
        program = "import importlib.util,json; s=importlib.util.spec_from_file_location('p'," \
            + repr(value["processModuleFile"]) + "); m=importlib.util.module_from_spec(s); " \
            + "s.loader.exec_module(m); m.supervise_index(json.load(open(" \
            + repr(str(root / "selection.private.json")) + ")))"
        with (root / "supervisor.log").open("xb") as output:
            child = subprocess.Popen([value["python"], "-c", program], stdin=subprocess.DEVNULL,
                stdout=output, stderr=output, start_new_session=True)
        pin = process.process_identity(child.pid)
        process.private_write(root / "supervisor-process.json", json.dumps(pin).encode())
        return {"root": str(root), "supervisor": pin}
    if action == "index-terminal":
        root = Path(value["root"])
        terminal = root / "index-terminal.json"
        if not terminal.exists():
            return None
        result = json.loads(terminal.read_bytes())
        with (root / "index.stderr.private").open("rb") as source:
            body = source.read(65537)
        if len(body) > 65536:
            raise ValueError("Stale-index stderr exceeds its result bound")
        return {**result, "stderrBase64": base64.b64encode(body).decode()}
    if action == "advance":
        placement = _module(value["placementModuleFile"], "stale_placement")
        # Controls execute on the controller, so only bounded original custody is read here.
        body = placement._private_original(Path(value["originalFile"]), value["requestSha256"])
        return {"bodyBase64": base64.b64encode(body).decode()}
    raise ValueError("Stale-index guest action is unsupported")


def start_direct_stale_index_listener(native, tools, configuration):
    """Start the selected source-built listener before baseline/loading traffic."""
    return _guest(native, tools, "start-listener", {"configuration": configuration,
        "node": tools["node"], "listenerFile": tools["staleIndexListener"],
        "processModuleFile": tools["staleIndexProcess"]})


def capture_direct_stale_index_environment(native, tools, native_process, output):
    """Retain the actual live Native service environment without returning secrets."""
    return _guest(native, tools, "capture-environment", {"nativeProcess": native_process,
        "file": output, "processModuleFile": tools["staleIndexProcess"]})


def run_direct_stale_index_case(native, worker, client, database_machine, tools,
                               controls, registry_setup, source, worker_process):
    """Run the single retained index original and real placement CAS/refusal.

    `tools` supplies actual SELECT-only query/index readers, private retention,
    the listener installation, and freshly captured Native environment. Worker
    authentication/provider traffic must still be joined by Fleet's observers.
    """
    query = tools["staleIndexSqlQuery"]
    read_index = tools["staleIndexReadIndex"]
    retain = tools["staleIndexRetain"]
    installation = tools["staleIndexInstallation"]
    slug = registry_setup["registry"]["slug"]
    name = registry_setup["placement"]["name"]
    literal = lambda value: "'" + value.replace("'", "''") + "'"
    rows = query("SELECT placement.id, placement.resource_version, binding.id, "
        "binding.resource_version, binding.kind, placement.prefix "
        "FROM surface_placements placement JOIN bindings binding ON binding.id=placement.binding_id "
        "JOIN registries registry ON registry.id=placement.registry_id WHERE registry.slug="
        + literal(slug) + " AND placement.name=" + literal(name) + " LIMIT 2")
    if len(rows) != 1 or len(rows[0]) != 6:
        raise ValueError("Stale-index current SQL placement is absent or ambiguous")
    row = rows[0]
    if any(type(value) is not int or not 0 < value < 2**53 for value in row[:4]):
        raise ValueError("Stale-index SQL pins exceed exact JavaScript geometry")
    environment = tools["staleIndexEnvironmentCapture"]
    before = read_index(slug)
    if len(before["index"]) != 1 or before["index"][0][:3] != ["fresh", None, source["sourceCommit"]]:
        raise ValueError("Stale-index source is not the exact fresh signed publication")
    selection = {"version": 1, "originHost": "aos.fleet.test",
        "deployment_id": tools["deploymentId"], "placement_id": row[0],
        "placement_resource_version": row[1], "binding_id": row[2],
        "binding_resource_version": row[3], "binding_kind": row[4], "placement_prefix": row[5]}
    common = {"processModuleFile": tools["staleIndexProcess"], "installation": installation}
    transport_before = _guest(native, tools, "control", {**common,
        "request": {"version": 1, "kind": "transport-status"}})
    if transport_before["overflow"] or transport_before["capacityRefusals"]:
        raise ValueError("Stale-index whole-window transport evidence is incomplete")
    _guest(native, tools, "control", {**common, "request": {"version": 1, "kind": "arm", "selection": selection}})
    root = installation["root"] + "/index"
    launched = _guest(native, tools, "launch-index", {"root": root, "registrySlug": slug,
        "executable": tools["aosHub"], "python": tools["python"], "environment": environment,
        "processModuleFile": tools["staleIndexProcess"]})
    deadline = time.monotonic() + 35
    completed = False
    try:
        while True:
            held = _guest(native, tools, "control", {**common, "request": {"version": 1, "kind": "status"}})
            if held["state"] == "held":
                break
            if held["state"] != "unused" or time.monotonic() >= deadline:
                raise ValueError("No genuine held index request; originals remain retained")
            time.sleep(0.1)
        original = _guest(native, tools, "advance", {"originalFile": installation["root"] + "/hold/original-request.json",
            "requestSha256": held["requestSha256"], "placementModuleFile": tools["stalePlacementHelper"],
            "processModuleFile": tools["staleIndexProcess"]})
        # The already-reviewed helper reads a private original on this controller.
        # Retain the exact received bytes instead of manufacturing an equivalent plan.
        private = Path(tools["staleIndexControllerRoot"])
        private.mkdir(mode=0o700, parents=True, exist_ok=False)
        process = _module(tools["staleIndexProcess"], "stale_process")
        original_file = private / "original-request.private.json"
        process.private_write(original_file, base64.b64decode(original["bodyBase64"], validate=True))
        placement = _module(tools["stalePlacementHelper"], "stale_placement")
        advanced = placement.advance_held_stale_placement(controls, held, original_file,
            {"registrySlug": slug}, name, "stale-index-read-order")
        released = _guest(native, tools, "control", {**common,
            "request": {"version": 1, "kind": "release", "requestSha256": held["requestSha256"]}})
        deadline = time.monotonic() + 95
        while True:
            terminal = _guest(native, tools, "index-terminal", {"root": root,
                "processModuleFile": tools["staleIndexProcess"]})
            if terminal is not None:
                break
            if time.monotonic() >= deadline:
                raise ValueError("Index terminal missing; no timeout/rollback inference")
            time.sleep(0.1)
        stderr = base64.b64decode(terminal.pop("stderrBase64"), validate=True)
        result = {**terminal, "stderr": stderr, "requestSha256": held["requestSha256"]}
        after = read_index(slug)
        verdict = placement.assert_stale_index_refusal(before, after, result, held["requestSha256"])
        transport_after = _guest(native, tools, "control", {**common,
            "request": {"version": 1, "kind": "transport-status"}})
        if transport_after["overflow"] or transport_after["capacityRefusals"]:
            raise ValueError("Stale-index whole-window transport evidence is incomplete")
        receipt = {"version": 1, "held": held, "advanced": advanced, "released": released,
            "launch": launched, "terminal": terminal, "before": before, "after": after,
            "verdict": verdict, "transportBefore": transport_before,
            "transportAfter": transport_after, "providerRequests": None, "nativeBulkBytes": None}
        retain("actual-stale-index-case.private.json", receipt)
        completed = True
        return receipt
    except Exception:
        retain("stale-index-unresolved.private.json", {"version": 1, "launch": launched,
            "providerOutcome": None, "scope": "actual original/SQL/process may remain unresolved; no replay"})
        raise
    finally:
        try:
            _guest(native, tools, "control", {**common,
                "request": {"version": 1, "kind": "close"}})
        except Exception:
            retain("stale-index-close-unresolved.private.json", {"version": 1,
                "providerOutcome": None, "scope": "listener close was not observed"})
            if completed:
                raise ValueError("Stale-index close is unresolved; earlier observations retained")
