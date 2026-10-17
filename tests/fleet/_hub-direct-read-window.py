"""Call the fixed read/cache window while the selected companions remain live.

The controller queries the actual three authoritative indexes. Reference bytes
are copied from retained client files one at a time; HTTP and the real cache
socket run only on the selected Worker guest. This helper never supplies a
publication, cache admission, provider permission or Native byte-budget result.
"""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time
from urllib.parse import urlsplit


MAX_OBJECT_BYTES = 4 * 1024 * 1024
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
# The fixed HTTP cases retain about 320 separate original/header/body/receipt
# files. Leave bounded room for the control inputs and result, not future cases.
MAX_CAPTURE_FILES = 384
MODES = {"hybrid", "native_only", "worker_only"}
OBJECTS = {"git", "package", "metadata", "document", "container"}
PROCESS_MACHINES = {"hybrid_native": "native", "hybrid_worker": "worker",
    "native_only": "native", "worker_only": "worker"}


def _sha(body):
    return hashlib.sha256(body).hexdigest()


def _decode(body):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Read-window JSON repeats a field")
            result[name] = value
        return result

    def invalid(_):
        raise ValueError("Read-window JSON contains nonfinite data")

    return json.loads(body, object_pairs_hook=unique, parse_constant=invalid)


def _file(path, maximum, *, private=False, immutable=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not immutable and before.st_uid != os.getuid()
                or private and before.st_mode & 0o077 or not 0 <= before.st_size <= maximum):
            raise ValueError("Read-window input custody or bound differs")
        body = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    if len(body) != before.st_size or len(body) > maximum or any(
            getattr(before, field) != getattr(after, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
        raise ValueError("Read-window input changed during observation")
    return body


def _private_write(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _module(file, expected, name):
    if not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[^/]+/.+", file):
        raise ValueError("Read-window module is not an installed source input")
    if _sha(_file(file, 1024 * 1024, immutable=True)) != expected:
        raise ValueError("Read-window module differs from the selected source")
    specification = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _process(pin):
    required = {"pid", "startTicks", "ownerUid", "executableSha256"}
    optional = {"commandLineSha256", "commandLineBytes"}
    if (not isinstance(pin, dict) or not required.issubset(pin)
            or set(pin) - required - optional or type(pin["pid"]) is not int or pin["pid"] <= 0
            or type(pin["ownerUid"]) is not int or pin["ownerUid"] < 0
            or not re.fullmatch(r"[1-9][0-9]{0,19}", pin["startTicks"])
            or not re.fullmatch(r"[0-9a-f]{64}", pin["executableSha256"])):
        raise ValueError("Read-window selected process pin is incomplete")
    directory = Path("/proc") / str(pin["pid"])
    before = (directory / "stat").read_text().rpartition(") ")[2].split()
    with (directory / "exe").open("rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    with (directory / "cmdline").open("rb") as arguments:
        command = arguments.read(65537)
    after = (directory / "stat").read_text().rpartition(") ")[2].split()
    actual = {"pid": pin["pid"], "startTicks": before[19],
        "ownerUid": directory.stat().st_uid, "executableSha256": digest,
        "commandLineSha256": _sha(command), "commandLineBytes": str(len(command))}
    if (before[0] == "Z" or after[0] == "Z" or before[19] != after[19] or len(command) > 65536
            or any(actual[field] != expected for field, expected in pin.items())):
        raise ValueError("Read-window runtime lifetime or executable changed")
    return actual


def _configuration(context):
    body = _file(context["workerConfigurationFile"], 1024 * 1024, private=True)
    if _sha(body) != context["workerConfigurationSha256"]:
        raise ValueError("Read-window initial Worker configuration changed")
    # Check the actual fixed observer selected before startup; a control socket
    # response alone must not retroactively select the cache under test.
    value = _decode(body)
    cache = value.get("publicDocumentCacheCase")
    document = context["objects"]["document"]
    if (not isinstance(cache, dict) or set(cache) != {
            "assetVersion", "bodyBytes", "documentSha256", "registrySlug"}
            or cache["registrySlug"] != context["registrySlug"]
            or cache["documentSha256"] != document["sha256"]
            or cache["bodyBytes"] != document["byteSize"]
            or not re.fullmatch(r"[0-9a-f]{8}", cache["assetVersion"])
            or not 1 <= cache["bodyBytes"] <= 256 * 1024
            or value.get("name") != context["cache"]["identity"].get("workerName")):
        raise ValueError("Read-window initial configuration lacks its fixed cache observer")
    observer = value.get("publicDocumentCacheObserverPath")
    if (not isinstance(observer, str)
            or not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[^/]+/.+", observer)
            or _sha(_file(observer, 64 * 1024, immutable=True))
                != context["cache"]["identity"].get("cacheObserverSha256")):
        raise ValueError("Read-window initial cache observer source changed")
    return {"file": context["workerConfigurationFile"], "sha256": _sha(body),
        "byteSize": len(body)}


def _context(context):
    fields = {"version", "registrySlug", "sourceCommit", "packageName", "origins", "objects",
        "privateRegistrySlug", "credentials", "cache", "curlArgv", "evidenceRoot", "processes",
        "workerConfigurationFile", "workerConfigurationSha256", "parityModuleFile",
        "parityModuleSha256", "indexModuleFile", "indexModuleSha256"}
    if (not isinstance(context, dict) or set(context) != fields or type(context["version"]) is not int
            or context["version"] != 1 or set(context["origins"]) != MODES
            or set(context["objects"]) != OBJECTS or set(context["processes"]) != set(PROCESS_MACHINES)
            or set(context["credentials"]) != {"bearerHeaderFile", "cookieHeaderFile"}
            or set(context["cache"]) != {"socketFile", "identity"}
            or not re.fullmatch(r"[0-9a-f]{64}", context["sourceCommit"])
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}/[a-z][a-z0-9-]{0,63}", context["registrySlug"])
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}/[a-z][a-z0-9-]{0,63}", context["privateRegistrySlug"])
            or context["registrySlug"] == context["privateRegistrySlug"]
            or context["registrySlug"].split("/")[0] != context["privateRegistrySlug"].split("/")[0]):
        raise ValueError("Read-window fixed corpus context is incomplete")
    for field in ("parityModuleSha256", "indexModuleSha256", "workerConfigurationSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", context[field]):
            raise ValueError("Read-window source or configuration hash differs")
    for row in context["objects"].values():
        if (set(row) != {"relativePath", "file", "sha256", "byteSize"}
                or type(row["byteSize"]) is not int or not 16 <= row["byteSize"] <= MAX_OBJECT_BYTES
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise ValueError("Read-window source object exceeds the fixed contract")
    for role, selected in context["processes"].items():
        if set(selected) != {"machine", "pin"} or selected["machine"] != PROCESS_MACHINES[role]:
            raise ValueError("Read-window process belongs to another selected guest")
    worker = context["processes"]["hybrid_worker"]["pin"]
    identity = context["cache"]["identity"]
    if (identity.get("runnerPid") != worker.get("pid")
            or identity.get("runnerStartTicks") != worker.get("startTicks")
            or identity.get("configurationSha256") != context["workerConfigurationSha256"]):
        raise ValueError("Read-window cache identity differs from the selected runner")
    root = Path(context["evidenceRoot"])
    if not root.is_absolute() or any(part in {".", ".."} for part in root.parts):
        raise ValueError("Read-window evidence root is not an absolute private path")


def _guest(machine, python, action, values, *, timeout=45):
    code = Path(__file__).read_text()
    encoded = base64.b64encode(json.dumps({"action": action, "values": values}).encode()).decode()
    program = code + "\nprint(json.dumps(_guest_action(_decode(base64.b64decode(" + repr(encoded) + ")))))\n"
    command = shlex.quote(python) + " - <<'READ_WINDOW_PROGRAM'\n" + program + "READ_WINDOW_PROGRAM\n"
    request = command.encode()
    if len(request) > 8 * 1024 * 1024:
        raise ValueError("Read-window guest command exceeds its private transport bound")
    status, stdout, _ = machine.agent.request(request, timeout=timeout)
    if status:
        raise RuntimeError("Read-window guest refused or timed out; actual partial captures retained")
    if len(stdout) > 6 * 1024 * 1024:
        raise ValueError("Read-window guest reply exceeds the fixed bound")
    return _decode(stdout)


def _guest_action(selected):
    os.umask(0o077)
    action, value = selected["action"], selected["values"]
    if action == "process":
        return _process(value)
    if action == "source":
        body = _file(value["file"], value["maximum"], private=value["private"])
        if _sha(body) != value["sha256"] or len(body) != value["byteSize"]:
            raise ValueError("Read-window retained source file differs")
        return {"bodyBase64": base64.b64encode(body).decode(), "sha256": _sha(body), "byteSize": len(body)}
    if action == "credential":
        body = _file(value["file"], 64 * 1024, private=True)
        prefix = value["prefix"]
        header = body.decode().strip()
        if not header.startswith(prefix) or len(header) <= len(prefix) or "\n" in header or "\r" in header:
            raise ValueError("Read-window retained credential header differs")
        return {"bodyBase64": base64.b64encode(body).decode(), "sha256": _sha(body), "byteSize": len(body)}
    if action == "prepare":
        _context(value)
        _process(value["processes"]["hybrid_worker"]["pin"])
        configuration = _configuration(value)
        root = Path(value["evidenceRoot"])
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        (root / "inputs").mkdir(mode=0o700)
        _private_write(root / "context.private.json", json.dumps(value, sort_keys=True).encode())
        return {"configuration": configuration}
    if action == "copy":
        root = Path(value["root"])
        if value["name"] not in OBJECTS | {"bearer", "cookie"}:
            raise ValueError("Read-window transfer name is unsupported")
        if len(value["bodyBase64"]) > (MAX_OBJECT_BYTES + 2) // 3 * 4:
            raise ValueError("Read-window transfer encoding exceeded its closed bound")
        body = base64.b64decode(value["bodyBase64"], validate=True)
        if len(body) > MAX_OBJECT_BYTES or len(body) != value["byteSize"] or _sha(body) != value["sha256"]:
            raise ValueError("Read-window transferred reference bytes changed")
        _private_write(root / "inputs" / value["name"], body)
        return {"sha256": _sha(body), "byteSize": len(body)}
    if action == "run":
        return _run_guest_window(value)
    if action == "companion-step":
        return _companion_step(value)
    raise ValueError("Read-window guest action is unsupported")


def _capture_inventory(root):
    rows, total = [], 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        if any((Path(directory) / name).is_symlink() for name in dirs):
            raise ValueError("Read-window capture contains a directory link")
        for name in sorted(files):
            path = Path(directory) / name
            body = _file(path, MAX_OBJECT_BYTES + 64 * 1024, private=True)
            total += len(body)
            if len(rows) >= MAX_CAPTURE_FILES or total > MAX_CAPTURE_BYTES:
                raise ValueError("Read-window retained captures exceeded their closed total bound")
            rows.append({"file": str(path), "sha256": _sha(body), "byteSize": len(body)})
    return {"files": rows, "totalBytes": total}


def _run_guest_window(context):
    _context(context)
    root = Path(context["evidenceRoot"])
    before = _process(context["processes"]["hybrid_worker"]["pin"])
    configuration = _configuration(context)
    parity = _module(context["parityModuleFile"], context["parityModuleSha256"], "fixed_read_parity")
    selection = {name: context[name] for name in ("version", "registrySlug", "sourceCommit", "packageName", "origins")}
    selection["objects"] = {kind: {**row, "file": str(root / "inputs" / kind)}
        for kind, row in context["objects"].items()}
    parity.select_direct_read_corpus(selection)
    transport = parity.DirectReadHttp(context["curlArgv"], root / "http")
    controls = root / "cache-controls"
    controls.mkdir(mode=0o700)

    def control(kind, label):
        _process(context["processes"]["hybrid_worker"]["pin"])
        return parity.direct_document_cache_control(context["cache"]["socketFile"], kind, controls, label)

    try:
        cache = parity.run_direct_document_cache(selection, transport, control,
            str(root / "inputs" / "bearer"), str(root / "inputs" / "cookie"),
            context["privateRegistrySlug"], context["cache"]["identity"])
        reads = parity.run_direct_read_parity(selection, transport)
        semantic = parity.run_direct_semantic_read_parity(selection, transport)
        if _process(context["processes"]["hybrid_worker"]["pin"]) != before or _configuration(context) != configuration:
            raise ValueError("Read-window selected runtime changed during reads")
        result = {"version": 1, "sourceCommit": context["sourceCommit"], "cache": cache,
            "objectReads": reads, "indexedReads": semantic, "process": before,
            "configuration": configuration, "nativeBulkBytes": None}
        _private_write(root / "result.private.json", json.dumps(result, sort_keys=True).encode())
        return {"result": result, "captures": _capture_inventory(root)}
    except Exception as error:
        _private_write(root / "failure.private.json", json.dumps({"version": 1,
            "outcome": "unresolved", "exceptionType": type(error).__name__, "nativeBulkBytes": None}).encode())
        raise


def run_direct_read_window(client, native, worker, *, tools, context, index_readers, retain):
    """Run the real fixed window before the caller stops any companion process."""
    _context(context)
    if set(index_readers) != MODES or any(not callable(query) for query in index_readers.values()):
        raise ValueError("Read-window actual authoritative readers are missing")
    machines = {"native": native, "worker": worker}

    def processes():
        return {role: _guest(machines[selected["machine"]], tools["python"], "process", selected["pin"])
            for role, selected in context["processes"].items()}

    before = processes()
    projector = _module(context["indexModuleFile"], context["indexModuleSha256"], "fixed_index_projection")
    parity = _module(context["parityModuleFile"], context["parityModuleSha256"], "fixed_read_assertions")
    snapshots = {mode: projector.registry_index_observations(query, context["registrySlug"])
        for mode, query in index_readers.items()}
    encoded = json.dumps(snapshots, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_INDEX_BYTES:
        raise ValueError("Read-window actual index projection exceeded its closed bound")
    retain("read-window-indexes.private.json", snapshots)
    indexes = parity.assert_direct_full_index_parity(snapshots, context["sourceCommit"])
    _guest(worker, tools["python"], "prepare", context)
    for kind, row in context["objects"].items():
        transfer = _guest(client, tools["python"], "source", {**{name: row[name]
            for name in ("file", "sha256", "byteSize")}, "maximum": MAX_OBJECT_BYTES, "private": False})
        _guest(worker, tools["python"], "copy", {**transfer, "root": context["evidenceRoot"], "name": kind})
    for kind, field, prefix in (("bearer", "bearerHeaderFile", "Authorization: Bearer "),
            ("cookie", "cookieHeaderFile", "Cookie: ")):
        transfer = _guest(client, tools["python"], "credential", {
            "file": context["credentials"][field], "prefix": prefix})
        _guest(worker, tools["python"], "copy", {**transfer, "root": context["evidenceRoot"], "name": kind})
    actual = _guest(worker, tools["python"], "run", context, timeout=180)
    after = processes()
    if before != after:
        raise ValueError("Read-window companion runtime changed; actual captures retained")
    result = {"version": 1, "registrySlug": context["registrySlug"], "sourceCommit": context["sourceCommit"],
        "indexParity": indexes, "reads": actual, "processesBefore": before, "processesAfter": after,
        "nativeBulkBytes": None, "scope": "actual fixed signed-corpus HTTP/cache and three authoritative indexes; byte/provider qualification remains separate"}
    retain("actual-called-read-window.json", result)
    return result


def _companion_selection(selection):
    fields = {"version", "mode", "origin", "registrySlug", "source", "coordinates"}
    if (not isinstance(selection, dict) or set(selection) != fields or selection["version"] != 1
            or selection["mode"] not in {"native_only", "worker_only"}
            or not re.fullmatch(r"[0-9a-f]{32}", selection["coordinates"]["runId"])
            or selection["registrySlug"] != "managed-" + selection["coordinates"]["runId"] + "/containers"
            or not re.fullmatch(r"[0-9a-f]{64}", selection["source"]["sourceCommit"])):
        raise ValueError("Companion publication differs from its selected signed corpus")
    origin = urlsplit(selection["origin"])
    if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
            or origin.path or origin.query or origin.fragment
            or selection["coordinates"]["workerOrigin"] != selection["origin"]):
        raise ValueError("Companion publication origin differs from its current route")
    finalized = selection["source"]["finalized"]
    if (not {"release", "layout", "signature_input", "index_digest"}.issubset(finalized)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", finalized["index_digest"])):
        raise ValueError("Companion publication lacks the actual finalized graph")
    for path in [selection["coordinates"]["clientRoot"], selection["source"]["surfaceRoot"],
            *[finalized[name] for name in ("release", "layout", "signature_input")]]:
        if not isinstance(path, str) or not Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("Companion publication source is not an absolute retained guest path")


def _companion_step(value):
    selection, tools, step = value["selection"], value["tools"], value["step"]
    _companion_selection(selection)
    if step not in {"stage", "upload", "publish"}:
        raise ValueError("Companion publication phase is unsupported")
    parent = Path(selection["coordinates"]["clientRoot"])
    metadata = parent.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077):
        raise ValueError("Companion publication parent lacks private guest custody")
    root = parent / "signed-publication"
    if step == "stage":
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        _private_write(root / "selection.private.json", json.dumps(selection, sort_keys=True).encode())
    elif _decode(_file(root / "selection.private.json", 1024 * 1024, private=True)) != selection:
        raise ValueError("Companion publication retained original changed")
    finalized = selection["source"]["finalized"]
    references = _graph_references(finalized)
    if step == "stage":
        _private_write(root / "graph-references.json", json.dumps(references, sort_keys=True).encode())
    elif references != _decode(_file(root / "graph-references.json", 4096, private=True)):
        raise ValueError("Companion publication graph inputs changed")
    if step == "upload":
        stage = _decode(_file(root / "stage.result.private.json", 1024 * 1024, private=True))
        if stage.get("state") != "staged" or stage.get("tag_updated") is not False:
            raise ValueError("Companion signed upload has no exact completed staging positive")
    if step == "publish":
        uploaded = _decode(_file(root / "upload.result.private.json", 1024 * 1024, private=True))
        if uploaded.get("data", {}).get("state") != "ready":
            raise ValueError("Companion graph publication has no ordinary ready upload")
        index = value["index"]
        if (index.get("indexState") != "fresh"
                or index.get("lastIndexedCommit") != selection["source"]["sourceCommit"]):
            raise ValueError("Companion graph publication has no exact current signed index")
        _private_write(root / "index-before-publish.private.json", json.dumps(index, sort_keys=True).encode())

    prefix = [tools["aos"], "--json", "--progress", "off", "--color", "never"]
    if not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[^/]+/bin/aos", tools["aos"]):
        raise ValueError("Companion publication must use the selected source-built CLI")
    if step == "upload":
        argv = prefix + ["hub", "registry", "publish", "upload", selection["registrySlug"],
            "--root", selection["source"]["surfaceRoot"], "--hub", selection["origin"],
            "--token", value["token"], "--direct-upload-journal", str(root / "upload.journal.private.json")]
    else:
        tag = urlsplit(selection["origin"]).netloc + "/aos:managed-" + selection["coordinates"]["runId"]
        argv = prefix + ["container", "publish", "aos", tag, "--release", finalized["release"],
            "--release-layout", finalized["layout"], "--signature-input", finalized["signature_input"],
            "--registry", selection["registrySlug"], "--registry-origin", selection["origin"],
            "--registry-token", value["token"], "--hub", selection["origin"], "--token", value["token"],
            "--idempotency-key",
            "parity-" + selection["coordinates"]["runId"] + "-" + selection["mode"] + "-" + step]
        if step == "stage":
            argv += ["--stage-only"]
    _private_write(root / (step + ".argv.private.json"), json.dumps(argv).encode())
    _private_write(root / (step + ".intent.private.json"), json.dumps({"step": step,
        "sourceCommit": selection["source"]["sourceCommit"], "references": references}).encode())
    stdout_path, stderr_path = root / (step + ".stdout.private"), root / (step + ".stderr.private")
    started = time.time_ns()
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        stdout_path.chmod(0o600)
        stderr_path.chmod(0o600)
        # Inherit the actual supervisor HOME/CA and select the same source-built
        # subprocess tools used by the ordinary producer. Every origin and token
        # is explicit, so a preexisting profile cannot choose another companion.
        environment = dict(os.environ)
        directories = [str(Path(tools["git"]).parent), tools["opensshBin"], tools["nixBin"]]
        if any(not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[^/]+/bin", directory) for directory in directories):
            raise ValueError("Companion subprocess tools are not the selected source-built inputs")
        environment["PATH"] = ":".join(directories + [environment.get("PATH", "")])
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                env=environment, timeout=1100, check=False)
        except subprocess.TimeoutExpired:
            _private_write(root / (step + ".terminal.json"), json.dumps({"version": 1,
                "exitCode": None, "outcome": "unknown", "startedAtUnixNs": str(started),
                "completedAtUnixNs": str(time.time_ns()), "providerSettlement": None}).encode())
            raise
    terminal = {"version": 1, "exitCode": result.returncode,
        "startedAtUnixNs": str(started), "completedAtUnixNs": str(time.time_ns())}
    _private_write(root / (step + ".terminal.json"), json.dumps(terminal).encode())
    if result.returncode:
        raise ValueError("Companion publication command failed; original output retained")
    actual = _decode(_file(stdout_path, 1024 * 1024, private=True))
    if step == "upload":
        if actual.get("data", {}).get("state") != "ready":
            raise ValueError("Companion ordinary publication did not reach ready")
    elif (actual.get("index_digest") != finalized["index_digest"]
            or step == "stage" and (actual.get("state") != "staged" or actual.get("tag_updated") is not False)
            or step == "publish" and (actual.get("verification") != "verified"
                or actual.get("verified_release_root") != finalized["index_digest"]
                or not actual.get("publication_id") or not actual.get("resource_version"))):
        raise ValueError("Companion exact graph publication has no verified phase result")
    if references != _graph_references(finalized):
        raise ValueError("Companion graph inputs changed during publication")
    _private_write(root / (step + ".result.private.json"), json.dumps(actual, sort_keys=True).encode())
    return {"result": actual, "terminal": terminal, "references": references,
        "originalRoot": str(root), "nativeBulkBytes": None}


def _graph_references(finalized):
    # The normal finalizer returns an OCI layout directory. Retain its bounded
    # control inputs; the ordinary CLI performs exact full graph/blob checking.
    # Do not relay or hash multi-gigabyte layer bodies through the controller.
    layout = Path(finalized["layout"])
    metadata = layout.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError("Companion finalizer layout lacks retained directory custody")
    files = {"release": Path(finalized["release"]), "signature_input": Path(finalized["signature_input"]),
        "layout_index": layout / "index.json", "layout_version": layout / "oci-layout",
        "root_index": layout / "blobs/sha256" / finalized["index_digest"].split(":", 1)[1]}
    references = {name: _sha(_file(path, MAX_OBJECT_BYTES)) for name, path in files.items()}
    if "sha256:" + references["root_index"] != finalized["index_digest"]:
        raise ValueError("Companion retained root bytes differ from the finalized graph digest")
    return references


def setup_selected_companion(client, *, tools, selection, controls, setup_registry,
                             configure_route, refresh_token, retain):
    """Stage the retained graph and publish the same signed corpus normally."""
    _companion_selection(selection)
    setup = setup_registry(controls, selection)
    if setup.get("registry", {}).get("slug") != selection["registrySlug"]:
        raise ValueError("Companion normal registry setup selected another surface")
    route = configure_route(controls, setup, selection)
    actual_route = route.get("route", {})
    if (actual_route.get("observation", {}).get("state") != "healthy"
            or actual_route.get("canonicalRenderedUrl", "").rstrip("/") != selection["origin"]):
        raise ValueError("Companion normal route has no exact healthy controller result")
    phases = {}
    command_tools = {name: tools[name] for name in ("aos", "git", "opensshBin", "nixBin")}
    for step in ("stage", "upload"):
        phases[step] = _guest(client, tools["python"], "companion-step", {
            "selection": selection, "tools": command_tools,
            "step": step, "token": refresh_token()}, timeout=1200)
    deadline = time.monotonic() + 240
    observations = []
    while True:
        registry = controls.call("RegistryService", "GetRegistry", {"slug": selection["registrySlug"]})["registry"]
        observations.append({name: registry.get(name) for name in ("indexState", "indexError", "lastIndexedCommit")})
        if (registry.get("indexState") == "fresh"
                and registry.get("lastIndexedCommit") == selection["source"]["sourceCommit"]):
            break
        if time.monotonic() >= deadline:
            retain(selection["mode"] + "-companion-index-unresolved.json", observations)
            raise ValueError("Companion actual index did not reach its exact signed source")
        time.sleep(2)
    phases["publish"] = _guest(client, tools["python"], "companion-step", {
        "selection": selection, "tools": command_tools, "step": "publish",
        "token": refresh_token(), "index": observations[-1]}, timeout=1200)
    result = {"version": 1, "mode": selection["mode"], "registrySlug": selection["registrySlug"],
        "sourceCommit": selection["source"]["sourceCommit"], "route": route,
        "setup": setup, "phases": phases, "indexObservations": observations, "nativeBulkBytes": None}
    retain(selection["mode"] + "-companion-publication.json", result)
    return result
