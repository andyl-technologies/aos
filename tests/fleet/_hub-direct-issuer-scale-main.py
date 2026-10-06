"""Call the genuine Fleet lease-scale setup after the original issuer stops.

This adapter uses normal browser decisions, queued Worker credential validation,
SQL export, actual subprocess supervision and the unchanged TLS issuer proxy.
It accepts no synthetic publication, supplied PASS or substitute process tuple.
The source-built historical reply codec and raw captures remain independent of
this orchestration and are necessary before measured results are assessed.
"""

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import textwrap
import time


SCALE_SOURCE_NAMES = {"setup", "workload", "process", "joins", "collector", "runtime"}


def _scale_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def _scale_capture_file(machine, python, path, maximum_bytes):
    """Capture a closed private file through bounded machine-agent frames.

    Each chunk is at most four MiB before base64 encoding. The complete original
    identity and digest are checked again after transport; partial or substituted
    captures cannot become recorder, process or offered-wave evidence.
    """
    program = """
        import hashlib, os, stat
        from pathlib import Path
        path = Path(selected['path'])
        if path.parent.resolve() != path.parent:
            raise ValueError('closed scale capture path is not canonical')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            before = os.fstat(source.fileno())
            identity = lambda row: [row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns]
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > selected['maximum']):
                raise ValueError('closed scale capture custody or size differs')
            if selected['identity'] is not None and identity(before) != selected['identity']:
                raise ValueError('closed scale capture original changed')
            if selected['offset'] is None:
                answer = {'identity': identity(before), 'sha256': hashlib.file_digest(source, 'sha256').hexdigest()}
            else:
                source.seek(selected['offset'])
                raw = source.read(min(4 * 1024 * 1024, before.st_size - selected['offset']))
                answer = {'identity': identity(before), 'body': base64.b64encode(raw).decode()}
            after = os.fstat(source.fileno())
        if identity(before) != identity(after) or identity(before) != identity(path.stat(follow_symlinks=False)):
            raise ValueError('closed scale capture changed during its selected read')
        print(json.dumps(answer))
    """
    selection = {"path": path, "maximum": maximum_bytes, "identity": None, "offset": None}
    original = json.loads(direct_guest_python(machine, python, program, selection))
    selection["identity"] = original["identity"]
    result = bytearray()
    while len(result) < original["identity"][2]:
        selection["offset"] = len(result)
        piece = json.loads(direct_guest_python(machine, python, program, selection))
        raw = base64.b64decode(piece["body"], validate=True)
        expected = min(4 * 1024 * 1024, original["identity"][2] - len(result))
        if piece["identity"] != original["identity"] or len(raw) != expected:
            raise ValueError("bounded closed-file transport omitted or substituted a chunk")
        result.extend(raw)
    selection["offset"] = None
    final = json.loads(direct_guest_python(machine, python, program, selection))
    if final != original or hashlib.sha256(result).hexdigest() != original["sha256"]:
        raise ValueError("complete actual capture differs from its immutable original")
    return bytes(result)


def _scale_closed(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate selected scale field")
        value[name] = item
    return value


def _scale_modules(tools):
    """Load separately committed fixture namespaces without global-name collisions."""
    references = tools["leaseScaleSources"]
    if set(references) != SCALE_SOURCE_NAMES:
        raise ValueError("called scale fixture has no complete selected source inventory")
    modules = {}
    for name, reference in references.items():
        if set(reference) != {"path", "sha256"} or not str(reference["path"]).startswith("/nix/store/"):
            raise ValueError("scale fixture source requires its selected immutable AOS file")
        path = Path(reference["path"])
        before = path.stat()
        body = path.read_bytes()
        if len(body) > 128 * 1024 or hashlib.sha256(body).hexdigest() != reference["sha256"] or path.stat() != before:
            raise ValueError("selected scale fixture source changed")
        namespace = {"__name__": "aos_fleet_scale_" + name, "__file__": str(path)}
        exec(compile(body, str(path), "exec"), namespace)
        modules[name] = namespace
    # Pure collector helpers are reused, not copied into this orchestrator.
    modules["joins"].update({name: modules["collector"][name] for name in (
        "_closed_object", "_digest", "_unsigned", "_private_file", "collect_local_issuer_observations",
        "measured_latency_summary", "whole_issuer_cpu_fraction", "LOCAL_LEASE_SCALE_POLICY")})
    return modules


def _scale_root(machine, python, root):
    return json.loads(direct_guest_python(machine, python, """
        import os
        from pathlib import Path
        path = Path(selected['root'])
        if not path.is_absolute() or path.parent.resolve() != path.parent:
            raise ValueError('fresh scale root is not canonical')
        metadata = path.parent.stat(follow_symlinks=False)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o7777 != 0o700:
            raise ValueError('fresh scale root parent is not owner-private')
        path.mkdir(mode=0o700, exist_ok=False)
        print(json.dumps({'root': str(path), 'device': path.stat().st_dev,
            'inode': path.stat().st_ino, 'createdUnixNs': __import__('time').time_ns()}))
    """, {"root": root}))


def _scale_base(machine, python):
    """Check the common private parent without adopting any case resource."""
    return json.loads(direct_guest_python(machine, python, """
        import os, stat
        from pathlib import Path
        path = Path('/var/lib/hybrid-lease-scale')
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        metadata = path.stat(follow_symlinks=False)
        if (path.resolve() != path or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise ValueError('scale parent is not exact owner-private custody')
        print(json.dumps({'root': str(path), 'device': metadata.st_dev, 'inode': metadata.st_ino}))
    """, {}))


def _scale_start(machine, tools, modules, root, arguments, files, role, run_id, environment):
    """Launch the real supervisor and retain its selected child's startup receipt."""
    selected = {"version": 1, "root": root, "arguments": arguments, "files": files,
        "role": role, "runId": run_id, "environment": environment}
    reference = tools["leaseScaleSources"]["process"]
    selection_file = root + ".selection.json"
    install_direct_guest_file(machine, tools["python"], selection_file, _scale_bytes(selected))
    return json.loads(direct_guest_python(machine, tools["python"], """
        import hashlib, os, stat, subprocess, time
        from pathlib import Path
        source = Path(selected['source']['path'])
        if hashlib.sha256(source.read_bytes()).hexdigest() != selected['source']['sha256']:
            raise ValueError('selected source-built supervisor changed')
        parent_log = selected['root'] + '.supervisor.log'
        descriptor = os.open(parent_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            supervisor = subprocess.Popen([selected['python'], str(source), 'supervise', selected['selection']],
                stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            process_file = Path(selected['root']) / 'process.json'
            if process_file.exists():
                body = process_file.read_bytes()
                if len(body) > 65536:
                    raise ValueError('actual process receipt exceeds its bound')
                receipt = json.loads(body)
                if (Path(selected['root']) / 'terminal.json').exists():
                    raise ValueError('selected child exited before startup readback')
                print(json.dumps({**receipt, 'supervisorPid': supervisor.pid,
                    'processReceiptSha256': hashlib.sha256(body).hexdigest(),
                    'supervisorLog': parent_log, 'processRoot': selected['root']}))
                break
            if supervisor.poll() is not None:
                raise ValueError('actual supervisor refused selected process; retained without retry')
            time.sleep(0.05)
        else:
            raise ValueError('actual child startup is unresolved; no retry or broad cleanup')
    """, {"python": tools["python"], "source": reference, "selection": selection_file,
        "root": root}, timeout=15))


def _scale_stop(machine, tools, process, label):
    selection = {"process": {name: process[name] for name in (
        "pid", "ownerUid", "startTicks", "arguments", "executable", "executableSha256")},
        "root": process["processRoot"], "interrupt": process["role"] == "issuer"}
    path = process["processRoot"] + ".stop.json"
    install_direct_guest_file(machine, tools["python"], path, _scale_bytes(selection))
    terminal = json.loads(private_guest_command(machine, shlex.join([tools["python"],
        tools["leaseScaleSources"]["process"]["path"], "stop", path]), timeout=40))
    retain_direct_flow(label + "-terminal.json", terminal)
    if terminal["exitCode"] != 0:
        raise ValueError("actual selected process terminal is not successful; retained without retry")
    return terminal


def _scale_issuer_resource(native, worker, tools, selected, renewal):
    """Create new issuer keys/configuration, retaining the actual derived public pin."""
    root = selected["issuerStore"]
    _scale_base(native, tools["python"])
    installation = selected["issuerInstallation"]
    authority = installation["authority"]
    # Preserve the declared Rust field order for the observer's canonical hash.
    installation = {"format_version": installation["format_version"],
        "authority": {name: authority[name] for name in ("authority_id", "guard_namespace_id",
            "physical_resource_evidence_digest", "qualification_digest", "qualified_managed_prefix")},
        **{name: installation[name] for name in ("issuer_resource_id", "runtime_identity", "executor_identity")}}
    profile = {name: selected["timingProfile"][name] for name in (
        "profile_id", "review_digest", "maximum_lifetime", "maximum_clock_uncertainty")}
    configuration = {"format_version": 1, "listen": "127.0.0.1:8444", "journal_file": root + "/journal/journal.sqlite",
        "installation": installation, "hub_root": "/var/lib/aos-hub", "hub_sqlite_file": None,
        "policy": {"timing_profile": profile}, "clock_uncertainty": "2",
        "clock_commit_latency": str(selected["clockCommitLatencySeconds"]), "issuance_enabled": True,
        "publisher_key_file": root + "/publisher.key", "renewal_key_file": root + "/renewal.key",
        "signing_seed_file": root + "/signing-seed.key", "signing_key_id": selected["signingKeyId"],
        "tls": {"certificate_file": tools["issuerCertificate"], "private_key_file": tools["issuerPrivateKey"],
            "expected_server_name": tools["issuerCertificateHost"]}}
    observed = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path
        root = Path(selected['root'])
        root.mkdir(mode=0o700, exist_ok=False)
        # Configuration and keys must never occupy the journal's private parent.
        (root / 'journal').mkdir(mode=0o700, exist_ok=False)
        seed = os.urandom(32)
        check = subprocess.run([selected['openssl'], 'x509', '-noout', '-in', selected['certificate'],
            '-checkhost', selected['hostname']], capture_output=True, check=False, timeout=15)
        if check.returncode:
            raise ValueError('selected actual issuer certificate does not cover its TLS name')
        result = subprocess.run([selected['openssl'], 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
            input=bytes.fromhex('302e020100300506032b657004220420') + seed,
            capture_output=True, check=False, timeout=15)
        prefix = bytes.fromhex('302a300506032b6570032100')
        if result.returncode or not result.stdout.startswith(prefix) or len(result.stdout) != 44:
            raise ValueError('actual source-built Ed25519 public pin derivation refused')
        values = {'configuration.json': base64.b64decode(selected['configuration'], validate=True),
            'issuer-public-key.hex': result.stdout[12:].hex().encode(), 'signing-seed.key': seed.hex().encode(),
            'publisher.key': os.urandom(32).hex().encode(), 'renewal.key': base64.b64decode(selected['renewal'], validate=True)}
        for name, body in values.items():
            descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
        print(json.dumps({'publicKey': values['issuer-public-key.hex'].decode(),
            'configurationSha256': hashlib.sha256(values['configuration.json']).hexdigest(),
            'rootDevice': root.stat().st_dev, 'rootInode': root.stat().st_ino}))
    """, {"root": root, "configuration": base64.b64encode(_scale_bytes(configuration)).decode(),
        "renewal": base64.b64encode(renewal).decode(), "openssl": tools["openssl"],
        "certificate": tools["issuerCertificate"], "hostname": tools["issuerCertificateHost"]}))
    if observed["configurationSha256"] != hashlib.sha256(_scale_bytes(configuration)).hexdigest():
        raise ValueError("actual issuer configuration differs from selected immutable bytes")
    worker_root = selected["workerRoot"] + "/issuer"
    _scale_root(worker, tools["python"], worker_root)
    for name, body in (("configuration.json", _scale_bytes(configuration)), ("issuer-public-key.hex", observed["publicKey"].encode())):
        install_direct_guest_file(worker, tools["python"], worker_root + "/" + name, body)
    return {"configuration": configuration, "configurationSha256": observed["configurationSha256"],
        "publicKey": observed["publicKey"], "workerRoot": worker_root, "resourceObservation": observed}


def _scale_validate_selection(selection, artifacts):
    """Refuse incomplete policy/current-source selections before any setup effect."""
    fields = {"organization", "cases", "bootstrapConfiguration", "storageWorkKeyFile",
        "providerMaterial", "nativeSourceDigest", "originalIssuerTerminal"}
    if set(selection) != fields or len(selection["cases"]) != 3:
        raise ValueError("scale mainflow selection omitted its genuine tuple/resource inputs")
    terminal = selection["originalIssuerTerminal"]
    if (not isinstance(terminal, dict) or set(terminal) != {"sameJournalRefusalObserved", "reference", "result"}
            or terminal["sameJournalRefusalObserved"] is not True):
        raise ValueError("main issuer terminal refusal must precede the separate scale window")
    if not re.fullmatch(r"[0-9a-f]{64}", selection["nativeSourceDigest"]):
        raise ValueError("Native issuer requires the independently selected final source pin")
    identities, roots = set(), set()
    for index, row in enumerate(selection["cases"]):
        expected = {"case", "runId", "maximumLifetime", "attestationCapped", "authorityId",
            "guardNamespaceId", "issuerStore", "physicalStore", "workerRoot", "issuerInstallation",
            "timingProfile", "clockCommitLatencySeconds", "signingKeyId", "bindings", "associationIds",
            "reviewedAuthority", "workerPorts"}
        if set(row) != expected or row["case"] != ("ttl-8", "ttl-120", "cap-120")[index]:
            raise ValueError("selected scale cases differ from the declared complete policy")
        if row["maximumLifetime"] != (8, 120, 120)[index] or row["attestationCapped"] is not (index == 2):
            raise ValueError("selected TTL/cap policy differs")
        if not re.fullmatch(r"[0-9a-f]{32}", row["runId"]):
            raise ValueError("selected scale case run differs")
        identity = tuple(row[name] for name in ("authorityId", "guardNamespaceId", "issuerStore", "physicalStore"))
        if any(any(old[position] == value for old in identities) for position, value in enumerate(identity)):
            raise ValueError("incompatible profiles require genuinely distinct authority/namespace/store originals")
        identities.add(identity)
        for name in ("issuerStore", "workerRoot"):
            path = row[name]
            if (Path(path).parent != Path('/var/lib/hybrid-lease-scale')
                    or not re.fullmatch(r"[a-zA-Z0-9_-]{1,120}", Path(path).name) or path in roots):
                raise ValueError("scale process resource root is not new and confined")
            roots.add(path)
        if len(row["bindings"]) != 16 or len(row["associationIds"]) != 16 or len(set(row["associationIds"])) != 16:
            raise ValueError("scale requires sixteen genuinely distinct bindings and associations")
        if len(row["workerPorts"]) != 4 or len(set(row["workerPorts"])) != 4 or any(type(port) is not int or not 1024 <= port <= 65535 for port in row["workerPorts"]):
            raise ValueError("scale requires four selected distinct unprivileged listeners")
        installation = row["issuerInstallation"]
        if installation["authority"]["authority_id"] != row["authorityId"] or installation["authority"]["guard_namespace_id"] != row["guardNamespaceId"]:
            raise ValueError("issuer installation does not match the selected new namespace")
        if row["timingProfile"]["maximum_lifetime"] != str(row["maximumLifetime"]) or type(row["clockCommitLatencySeconds"]) is not int or row["clockCommitLatencySeconds"] < 1:
            raise ValueError("timing profile must be genuinely validated by the normal issuer/operator")
    return selection


def run_direct_lease_scale_window(client, native, worker, database_machine, tools, database_host, artifacts):
    """Run called genuine scale setup and collect its actual source/process facts.

    The caller runs this after the main issuer's terminal cold-refusal receipt.
    New resources remain retained on every failure. The existing proxy remains
    live, and no legacy resource or binding is reset, adopted or overwritten.
    """
    modules = _scale_modules(tools)
    source = artifacts["buildDerivedSourceDigest"]
    selected = await_direct_review("lease-scale-policy", {
        "actualFinalArtifacts": retain_direct_flow("lease-scale-final-artifacts.json", artifacts),
        "fixtureSources": retain_direct_flow("lease-scale-fixture-sources.json", tools["leaseScaleSources"]),
    }, {"organization", "cases", "bootstrapConfiguration", "storageWorkKeyFile",
        "providerMaterial", "nativeSourceDigest", "originalIssuerTerminal"})
    selection = _scale_validate_selection(selected["selection"], artifacts)
    # The supplied terminal reference is not enough: inspect the actual original
    # result and actual listener absence before any new issuer process starts.
    original = _closed_review_json(direct_selected_bytes(selection["originalIssuerTerminal"]["reference"], 65536))
    if original != selection["originalIssuerTerminal"]["result"]:
        raise ValueError("main issuer terminal reference differs from independently retained actual bytes")
    expected = {"version", "oldPid", "oldStartTicks", "attemptPid", "attemptStartTicks", "exitCode",
        "executableObservedWhileLive", "executableSha256", "logSha256", "logBytes", "retainedResource",
        "retainedHistory", "positiveColdRecovery", "scope"}
    if (set(original) != expected or original["version"] != 1
            or type(original["exitCode"]) is not int or original["exitCode"] == 0
            or original["positiveColdRecovery"] != "unsupported"
            or original["oldPid"] == original["attemptPid"]
            or original["executableSha256"] != artifacts["files"]["authority"]["sha256"]
            or not original["retainedResource"]["journalInode"]
            or not original["retainedHistory"]["clockSessionSha256"]):
        raise ValueError("retained original is not the actual same-journal cold refusal")
    tools = {**tools, "leaseScaleModules": modules, "leaseScaleNativeSourceDigest": selection["nativeSourceDigest"]}
    actual_tools = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib
        from pathlib import Path
        values = {}
        for name in ('node', 'python'):
            with Path(selected[name]).open('rb') as source:
                values[name] = hashlib.file_digest(source, 'sha256').hexdigest()
        print(json.dumps(values))
    """, {name: tools[name] for name in ("node", "python")}))
    tools.update(leaseScaleNodeSha256=actual_tools["node"], leaseScalePythonSha256=actual_tools["python"])
    controls = DirectBootstrapControls(client, tools["curl"], tools["python"],
        direct_root_browser_token(client, tools["curl"], tools["python"], private_guest_command, reuse_session=True),
        private_guest_command, refresh_token=lambda: direct_root_browser_token(client,
            tools["curl"], tools["python"], private_guest_command, reuse_session=True))
    outputs = []
    for case in selection["cases"]:
        outputs.append(_scale_run_actual_case(native, worker, tools, database_host, artifacts,
            controls, selection, case, source))
        if outputs[-1]["outcome"] != "actual_capture_complete":
            break
    report = {"version": 1, "cases": outputs, "selectedPolicy": modules["collector"]["LOCAL_LEASE_SCALE_POLICY"],
        "qualification": None, "scope": "actual called local source/process/issuer captures; reviewed measurement assessment required"}
    retain_direct_flow("lease-scale-window.json", report)
    return _scale_finish_window(report)


def _scale_finish_window(report):
    """Retain the local assessment before refusing failed or unresolved budgets."""
    cases = report["cases"]
    assessments = [row.get("policyAssessment", {"case": row.get("case"), "status": "unknown"}) for row in cases]
    complete = [row.get("case") for row in cases] == ["ttl-8", "ttl-120", "cap-120"]
    statuses = [row.get("status") for row in assessments]
    status = "failed" if "failed" in statuses else "satisfied" if complete and statuses == ["satisfied"] * 3 else "unknown"
    result = {"version": 1, "status": status, "cases": assessments, "rawReport": "lease-scale-window.json",
        "qualification": None, "scope": "local scheduled CPU/latency/evidence completion; no Hosted or fleet headroom qualification"}
    retain_direct_flow("lease-scale-policy-assessment.json", result)
    if status != "satisfied":
        raise RuntimeError("lease-scale local policy " + status + "; raw captures and assessment retained")
    return {**report, "localPolicyAssessment": result}


def _scale_namespace(worker, tools, process, socket_file):
    return json.loads(direct_guest_python(worker, tools["python"], """
        import os, socket, struct
        from pathlib import Path
        process = selected['process']
        directory = Path('/proc') / str(process['pid'])
        before = (directory / 'stat').read_text().rpartition(') ')[2].split()[19]
        if before != process['startTicks'] or directory.stat().st_uid != process['ownerUid']:
            raise ValueError('actual scale namespace owner differs')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(15)
            peer.connect(selected['socket'])
            pid, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid != process['pid'] or uid != process['ownerUid']:
                raise ValueError('actual namespace socket belongs to another process')
            peer.sendall(b'{"version":1,"kind":"namespace-readback"}')
            peer.shutdown(socket.SHUT_WR)
            body = bytearray()
            while block := peer.recv(4096):
                body.extend(block)
                if len(body) > 131072:
                    raise ValueError('actual namespace reply exceeded its bound')
        actual = json.loads(body)
        after = (directory / 'stat').read_text().rpartition(') ')[2].split()[19]
        if (before != after or actual['runnerPid'] != process['pid'] or actual['runnerStartTicks'] != before
                or actual['configurationSha256'] != process['selectedFiles'][process['arguments'][-1]]):
            raise ValueError('namespace readback changed process or configuration')
        print(json.dumps(actual))
    """, {"process": process, "socket": socket_file}, timeout=20))


def _scale_worker_configuration(worker, tools, selection, case, index, label, consumer=None):
    root = case["workerRoot"] + f"/worker-{index}"
    result = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib
        from pathlib import Path
        namespace = {}
        exec(compile(Path(selected['processSource']).read_bytes(), selected['processSource'], 'exec'), namespace)
        raw = namespace['scale_private_bytes'](selected['template']['path'], 1048576)
        if hashlib.sha256(raw).hexdigest() != selected['template']['sha256']:
            raise ValueError('original selected bootstrap configuration changed')
        configuration = json.loads(raw)
        configuration.update(host='127.0.0.1', port=selected['port'], name=selected['name'],
            resourcePersistencePath=selected['state'], acceptanceSocketPath=selected['socket'])
        configuration.pop('queueObservationPath', None)
        configuration.pop('namespaceObservationPath', None)
        if configuration['scriptPath'] != selected['shim']:
            raise ValueError('Worker template differs from actual final artifact')
        guard = configuration['durableObjects']['HYBRID_OBJECT_GUARD']
        if guard['className'] != 'HybridObjectGuard' or guard['useSQLite'] is not True:
            raise ValueError('actual scale requires the persistent physical guard')
        guard['unsafeUniqueKey'] = selected['namespaceId']
        guard.pop('scriptName', None)
        bindings = configuration['bindings']
        bindings.pop('HUB_EXTERNAL_STAGING_CONSUMER', None)
        if selected['consumer'] is not None:
            consumer = selected['consumer']
            bindings['HUB_EXTERNAL_OBJECT_CONSUMER'] = json.dumps(consumer['objectConsumer'], separators=(',', ':'))
            bindings['HUB_LEASE_SCALE_FIXTURE'] = json.dumps(consumer['fixture'], separators=(',', ':'))
            bindings['HUB_LEASE_SCALE_OBSERVE'] = '1'
            bindings['HUB_AUTHORITY_RENEWAL_KEY'] = selected['renewal']
            configuration.setdefault('serviceBindings', {})['HUB_AUTHORITY_ISSUER'] = selected['service']
        else:
            bindings.pop('HUB_EXTERNAL_OBJECT_CONSUMER', None)
            bindings.pop('HUB_LEASE_SCALE_FIXTURE', None)
            bindings.pop('HUB_LEASE_SCALE_OBSERVE', None)
        body = json.dumps(configuration, separators=(',', ':')).encode()
        if len(body) > 1048576:
            raise ValueError('actual configuration exceeds its unchanged input bound')
        namespace['scale_write_private'](selected['output'], body)
        print(json.dumps({'file': selected['output'], 'sha256': hashlib.sha256(body).hexdigest(),
            'configurationDigest': None if selected['consumer'] is None else selected['consumer']['configurationDigest']}))
    """, {"processSource": tools["leaseScaleSources"]["process"]["path"],
        "template": selection["bootstrapConfiguration"], "port": case["workerPorts"][index],
        "name": "lease-scale-" + case["runId"] + f"-{index}", "namespaceId": case["guardNamespaceId"],
        "state": root + "/state", "socket": root + "/control.sock", "shim": tools["shim"],
        "output": root + ("/bootstrap.json" if consumer is None else "/measured.json"),
        "consumer": consumer, "renewal": tools.get("leaseScaleRenewal"), "service": tools.get("leaseScaleService")}))
    return result


def _scale_worker_start(worker, tools, artifacts, root, configuration, case, generation):
    files = {tools["node"]: tools["leaseScaleNodeSha256"], tools["runner"]: artifacts["files"]["runner"]["sha256"],
        tools["workerd"]: artifacts["files"]["workerd"]["sha256"], tools["wasm"]: artifacts["files"]["wasm"]["sha256"],
        tools["shim"]: artifacts["files"]["shim"]["sha256"], configuration["file"]: configuration["sha256"]}
    return _scale_start(worker, tools, tools["leaseScaleModules"], root + "/" + generation,
        [tools["node"], tools["runner"], tools["miniflare"], configuration["file"]], files,
        "worker", case["runId"], {"MINIFLARE_WORKERD_PATH": tools["workerd"],
            "NODE_EXTRA_CA_CERTS": "/etc/ssl/certs/ca-certificates.crt",
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"})


def _scale_run_actual_case(native, worker, tools, database_host, artifacts, controls, selection, case, source):
    modules, python = tools["leaseScaleModules"], tools["python"]
    setup, process_module = modules["setup"], modules["process"]
    run = case["runId"]
    label = "lease-scale-" + case["case"]
    # Actual absence is checked on Native, not inferred from a prior receipt.
    absence = json.loads(direct_guest_python(native, python, """
        from pathlib import Path
        namespace = {'__name__': 'selected_scale_process'}
        exec(compile(Path(selected['source']).read_bytes(), selected['source'], 'exec'), namespace)
        print(json.dumps(namespace['scale_listener_absent'](8444)))
    """, {"source": tools["leaseScaleSources"]["process"]["path"]}))
    retain_direct_flow(label + "-listener-before.json", absence)
    _scale_base(worker, python)
    _scale_root(worker, python, case["workerRoot"])
    labels = [os.urandom(16).hex() for _ in range(4)]
    bootstrap_processes, namespace_readbacks = [], []
    for index in range(4):
        root = case["workerRoot"] + f"/worker-{index}"
        _scale_root(worker, python, root)
        _scale_root(worker, python, root + "/state")
        configuration = _scale_worker_configuration(worker, tools, selection, case, index, labels[index])
        current = _scale_worker_start(worker, tools, artifacts, root, configuration, case, "bootstrap-process")
        # Only transport readiness is polled, never a provider/admission call.
        wait_fixture_tls_response(worker, tools["curl"], python,
            "https://localhost:" + str(case["workerPorts"][index]) + "/_internal/storage/v1/credential-custody",
            "POST", {"409"}, label + f"-bootstrap-{index}", 60)
        namespace = _scale_namespace(worker, tools, current, root + "/control.sock")
        if namespace["namespaceKey"] != case["guardNamespaceId"] or namespace["objectIds"]:
            raise ValueError("new scale namespace is foreign or already used; retained without reset")
        bootstrap_processes.append(current)
        namespace_readbacks.append(namespace)
    namespace_sha = retain_direct_flow(label + "-fresh-namespaces.json", namespace_readbacks)
    reviewed = await_direct_review(label + "-physical-authority", {
        "namespaceReadbacks": namespace_sha, "actualArtifacts": hashlib.sha256(_scale_bytes(artifacts)).hexdigest(),
        "selectedOriginal": retain_direct_flow(label + "-selected-original.json", case),
    }, {"reviewedAuthority", "physicalStore"})["selection"]
    if reviewed["physicalStore"] != case["physicalStore"] or reviewed["reviewedAuthority"] != case["reviewedAuthority"]:
        raise ValueError("independent actual resource review changed the selected immutable case")

    material = read_direct_guest_file(worker, python, selection["providerMaterial"]["path"], 65536)
    if hashlib.sha256(material).hexdigest() != selection["providerMaterial"]["sha256"]:
        raise ValueError("selected actual provider material changed")
    version_root = case["workerRoot"] + "/provider-versions"
    _scale_root(worker, python, version_root)
    value_file = version_root + "/material"
    install_direct_guest_file(worker, python, value_file, material)
    manifest = {reference: value_file for binding in case["bindings"] for reference in binding["versions"].values()}
    if len(manifest) != 80 or any(binding["fingerprint"] != hashlib.sha256(material).hexdigest() for binding in case["bindings"]):
        raise ValueError("genuine scale credential originals are not eighty unique exact material references")
    manifest_file = version_root + "/manifest.json"
    install_direct_guest_file(worker, python, manifest_file, _scale_bytes(manifest))
    del material

    def stage_original(index, operation_id, purpose):
        output = case["workerRoot"] + f"/stage-{index:02d}-" + purpose
        args = [tools["authorityBootstrap"], "--database-url-file", "/var/lib/hybrid-worker/operator/sql.url",
            "stage-credential", "--operation-id", operation_id, "--deployment-id", tools["deploymentId"],
            "--worker-url", tools["workerUrl"], "--storage-work-key-file", selection["storageWorkKeyFile"],
            "--secret-version-manifest", manifest_file, "--retention-seconds", "86400", "--output", output]
        private_guest_command(worker, shlex.join(args), timeout=120)
        body = read_direct_guest_file(worker, python, output + "/credential-stage.json", 262144)
        return {"operationId": operation_id, "purpose": purpose,
            "receiptSha256": hashlib.sha256(body).hexdigest(), "receiptBytes": len(body)}

    reports = setup["bootstrap_scale_bindings"](controls, run, selection["organization"], case["bindings"],
        stage_original, lambda binding: read_operator_binding_pins(worker, tools["postgres"], database_host, binding))
    for index, current in enumerate(bootstrap_processes):
        _scale_stop(worker, tools, current, label + f"-bootstrap-{index}")
    # No unused namespace is reset: the measured processes use these same exact
    # previously observed empty resources, preserving every original file.
    renewal = os.urandom(32).hex().encode()
    issuer = _scale_issuer_resource(native, worker, tools, case, renewal)
    observed_now = int(private_guest_command(native, shlex.join([python, "-c", "import time; print(int(time.time()))"])).strip())
    admission = setup["admit_scale_authority"](controls, run, selection["organization"]["slug"], reports,
        case["reviewedAuthority"], case["associationIds"], observed_now)
    retain_direct_flow(label + "-genuine-binding-authority.json", {"bindings": reports, "authority": admission,
        "browserDecisions": controls.observations})
    export_root = case["workerRoot"] + "/exports"
    _scale_root(worker, python, export_root)
    exports = setup["export_scale_associations"](worker, private_guest_command, tools["authorityBootstrap"],
        "/var/lib/hybrid-worker/operator/sql.url", issuer["workerRoot"] + "/configuration.json",
        issuer["workerRoot"] + "/issuer-public-key.hex", tools["deploymentId"], case["authorityId"],
        [{"associationId": identity, "admittedPrefix": case["reviewedAuthority"]["qualifiedManagedPrefix"]}
            for identity in case["associationIds"]], export_root)
    local_exports = Path("external-direct-flow") / (label + "-exports")
    local_exports.mkdir(mode=0o700, exist_ok=False)
    for index, exported in enumerate(exports):
        destination = local_exports / f"association-{index:02d}"
        destination.mkdir(mode=0o700)
        for name in ("bootstrap.json", "publication.json"):
            process_module["scale_write_private"](destination.resolve() / name,
                read_direct_guest_file(worker, python, exported["directory"] + "/" + name, 1048576))
    projection = setup["project_scale_exports"]([str((local_exports / f"association-{index:02d}").resolve())
        for index in range(16)], run, labels)
    publication = read_direct_guest_file(worker, python, exports[0]["directory"] + "/publication.json", 1048576)
    install_direct_guest_file(native, python, case["issuerStore"] + "/publication.json", publication)
    # This actual packaged command validates policy, private key/clock/resource
    # custody and initial publication. Failure is retained, never auto-repaired.
    initialize_external_issuer(native, python, tools["authority"],
        case["issuerStore"] + "/configuration.json", case["issuerStore"] + "/publication.json")
    return _scale_measure_case(native, worker, tools, artifacts, selection, case, source, labels, issuer, projection)


def _scale_measure_case(native, worker, tools, artifacts, selection, case, source, labels, issuer, projection):
    python, modules = tools["python"], tools["leaseScaleModules"]
    label = "lease-scale-" + case["case"]
    observation_root = case["issuerStore"] + "/observations"
    _scale_root(native, python, observation_root)
    configuration_file = case["issuerStore"] + "/configuration.json"
    observer = {"run_id": case["runId"], "selected_source_sha256": selection["nativeSourceDigest"],
        "executable_sha256": artifacts["files"]["authority"]["sha256"],
        "authority_configuration_sha256": issuer["configurationSha256"],
        "output": observation_root + "/events.jsonl"}
    observation_file = case["issuerStore"] + "/observation.json"
    observation_bytes = _scale_bytes(observer)
    install_direct_guest_file(native, python, observation_file, observation_bytes)
    authority_files = {tools["authority"]: artifacts["files"]["authority"]["sha256"],
        configuration_file: issuer["configurationSha256"],
        observation_file: hashlib.sha256(observation_bytes).hexdigest()}
    issuer_process = _scale_start(native, tools, modules, case["issuerStore"] + "/process",
        [tools["authority"], "serve", "--configuration", configuration_file,
            "--qualification-observation", observation_file], authority_files, "issuer", case["runId"], {})
    retain_direct_flow(label + "-issuer-process.json", issuer_process)
    native_address = private_guest_command(worker, shlex.join([python, "-c",
        "import socket; print(socket.gethostbyname('native'))"])).strip()
    renewal = read_direct_guest_file(native, python, case["issuerStore"] + "/renewal.key", 65536)
    service = issuer_service_binding(native_address, 8443, tools["fleetCaPem"], tools["issuerCertificateHost"])
    tools = {**tools, "leaseScaleRenewal": renewal.decode(), "leaseScaleService": service}
    processes, workers, namespaces = [], [], []
    for index, consumer in enumerate(projection["configurations"]):
        root = case["workerRoot"] + f"/worker-{index}"
        configuration = _scale_worker_configuration(worker, tools, selection, case, index, labels[index], consumer)
        current = _scale_worker_start(worker, tools, artifacts, root, configuration, case, "measured-process")
        wait_fixture_tls_response(worker, tools["curl"], python,
            "https://localhost:" + str(case["workerPorts"][index]) + "/__hub/lease-scale-acquire", "POST", {"409"},
            label + f"-measured-{index}", 60)
        namespace = _scale_namespace(worker, tools, current, root + "/control.sock")
        if namespace["namespaceKey"] != case["guardNamespaceId"] or namespace["objectIds"]:
            raise ValueError("measured process adopted a different or used guard namespace")
        processes.append(current)
        namespaces.append(namespace)
        workers.append({"host": "127.0.0.1", "port": case["workerPorts"][index],
            "isolateLabel": labels[index], "configurationDigest": consumer["configurationDigest"],
            "transport": {"kind": "tls", "certificateFile": tools["leaseScaleCertificateFile"],
                "certificateSha256": tools["leaseScaleCertificateSha256"], "serverName": "localhost"}})
    retain_direct_flow(label + "-measured-worker-processes.json", {"processes": processes, "namespaces": namespaces,
        "configurationContexts": workers, "exportProjection": projection})
    proxy_before = direct_log_position(native, python, "/var/lib/hybrid-native-observations/requests.jsonl")
    runtime_root = case["workerRoot"] + "/workload"
    _scale_root(worker, python, runtime_root)
    runtime = {"root": runtime_root, "run_id": case["runId"], "source_digest": source,
        "workers": workers, "cohort_digests": projection["cohortDigests"],
        "keyFile": selection["storageWorkKeyFile"], "sources": tools["leaseScaleSources"],
        "maximum_lifetime": case["maximumLifetime"], "capped": case["attestationCapped"],
        "issuer": {name: issuer_process[name] for name in ("pid", "startTicks")}, "workerProcesses": processes,
        "issuerProcessSha256": hashlib.sha256(_scale_bytes(issuer_process)).hexdigest()}
    runtime_file = runtime_root + "/selection.json"
    runtime_body = _scale_bytes(runtime)
    install_direct_guest_file(worker, python, runtime_file, runtime_body)
    selected_files = {tools["python"]: tools["leaseScalePythonSha256"], runtime_file: hashlib.sha256(runtime_body).hexdigest(),
        **{row["path"]: row["sha256"] for row in tools["leaseScaleSources"].values()}}
    workload_process = _scale_start(worker, tools, modules, runtime_root + "/process",
        [python, tools["leaseScaleSources"]["runtime"]["path"], runtime_file], selected_files,
        "workload", case["runId"], {})
    retain_direct_flow(label + "-workload-process.json", workload_process)
    deadline = time.monotonic() + 900
    stopped = None
    cpu_records = []
    while time.monotonic() < deadline:
        progress = json.loads(direct_guest_python(worker, python, """
            from pathlib import Path
            root = Path(selected['root'])
            wanted = root / 'stop-request.json'
            terminal = root / 'process/terminal.json'
            import hashlib
            source = Path(selected['processSource']['path'])
            raw = source.read_bytes()
            if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != selected['processSource']['sha256']:
                raise ValueError('selected CPU handshake reader changed')
            namespace = {'__name__': 'aos_scale_cpu_handshake_read'}
            exec(compile(raw, str(source), 'exec'), namespace)
            cpu = root / ('cpu-request-%02d.json' % selected['cpuSequence'])
            print(json.dumps({'stopRequest': json.loads(wanted.read_bytes()) if wanted.exists() else None,
                'cpuRequest': json.loads(namespace['scale_private_bytes'](cpu, 65536)) if cpu.exists() else None,
                'terminal': json.loads(terminal.read_bytes()) if terminal.exists() else None}))
        """, {"root": runtime_root, "cpuSequence": len(cpu_records),
            "processSource": tools["leaseScaleSources"]["process"]}))
        cpu_request = progress["cpuRequest"]
        if cpu_request is not None:
            pins = {"version": 1, "runId": case["runId"], "sourceDigest": source,
                "issuerPid": issuer_process["pid"], "issuerStartTicks": issuer_process["startTicks"],
                "workloadPid": workload_process["pid"], "workloadStartTicks": workload_process["startTicks"],
                "issuerProcessSha256": runtime["issuerProcessSha256"]}
            _scale_validate_cpu_request(cpu_request, pins, cpu_records)
            sample = json.loads(direct_guest_python(native, python, """
                from pathlib import Path
                import hashlib
                source = Path(selected['source']['path'])
                raw = source.read_bytes()
                if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != selected['source']['sha256']:
                    raise ValueError('selected CPU sampler source changed')
                namespace = {'__name__': 'aos_scale_cpu_endpoint'}
                exec(compile(raw, str(source), 'exec'), namespace)
                print(json.dumps(namespace['scale_sample_process_cpu'](selected['process'])))
            """, {"source": tools["leaseScaleSources"]["process"], "process": issuer_process}))
            acknowledgment = {"original": cpu_request, "sample": sample}
            # Both independent raw endpoints are retained by the controller.
            retain_direct_flow(label + f"-cpu-{len(cpu_records):02}.json", acknowledgment)
            direct_guest_python(worker, python, """
                from pathlib import Path
                import hashlib
                source = Path(selected['source']['path'])
                raw = source.read_bytes()
                if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != selected['source']['sha256']:
                    raise ValueError('selected CPU handshake writer changed')
                namespace = {'__name__': 'aos_scale_cpu_acknowledgment'}
                exec(compile(raw, str(source), 'exec'), namespace)
                namespace['scale_publish_private'](selected['path'], selected['value'])
                print(json.dumps({'published': True}))
            """, {"source": tools["leaseScaleSources"]["process"], "value": acknowledgment,
                "path": runtime_root + f"/cpu-ack-{len(cpu_records):02}.json"})
            cpu_records.append(acknowledgment)
        request = progress["stopRequest"]
        if request is not None and stopped is None:
            pins = {"version": 1, "runId": case["runId"], "sourceDigest": source,
                "issuerPid": issuer_process["pid"], "issuerStartTicks": issuer_process["startTicks"],
                "workloadPid": workload_process["pid"], "workloadStartTicks": workload_process["startTicks"]}
            if set(request) != set(pins) | {"requestedUnixNs"} or any(request[name] != value for name, value in pins.items()):
                raise ValueError("private stop request does not belong to the exact two recorded processes")
            stopped = _scale_stop(native, tools, issuer_process, label + "-issuer")
            install_direct_guest_file(worker, python, runtime_root + "/stop-acknowledgment.json",
                _scale_bytes({"original": request, "terminal": stopped}))
        if progress["terminal"] is not None:
            terminal = progress["terminal"]
            retain_direct_flow(label + "-workload-terminal.json", terminal)
            if terminal["pid"] != workload_process["pid"] or terminal["startTicks"] != workload_process["startTicks"] or terminal["exitCode"] != 0 or stopped is None:
                raise ValueError("actual workload failed or issuer stop is unresolved; all originals retained")
            break
        time.sleep(0.1)
    else:
        raise ValueError("actual scale workload has no bounded terminal; no blind cleanup/retry")
    for index, current in enumerate(processes):
        _scale_stop(worker, tools, current, label + f"-measured-{index}")
    proxy_path, proxy_window = retain_direct_log_window(native, python, proxy_before, label + "-proxy.jsonl")
    observations = [row for row in native_control_observations(Path(proxy_path).read_text())
        if row["procedure"] == "/_aos/storage-authority/issuer/v1"]
    proxy_capture = _scale_capture_proxy_bodies(native, tools, observations, label)
    issuer_events = _scale_capture_file(native, python, observation_root + "/events.jsonl", 256 * 1024 * 1024)
    issuer_event_path = Path("external-direct-flow") / (label + "-issuer-events.jsonl")
    retain_direct_flow(issuer_event_path.name, issuer_events)
    log_text = []
    for index, current in enumerate(processes):
        body = _scale_capture_file(worker, python, current["logFile"], 256 * 1024 * 1024)
        retain_direct_flow(label + f"-worker-{index}.log", body)
        log_text.append(body.decode())
    contexts = [{"runId": case["runId"], "sourceDigest": source, "isolateLabel": context["isolateLabel"],
        "configurationDigest": context["configurationDigest"], "cohortDigests": projection["cohortDigests"]} for context in workers]
    dispatches = modules["joins"]["scale_dispatch_events"]("\n".join(log_text), contexts)
    native_selected = {"runId": case["runId"], "selectedSourceSha256": selection["nativeSourceDigest"],
        "executableSha256": issuer_process["executableSha256"], "authorityConfigurationSha256": issuer["configurationSha256"],
        "installationSha256": hashlib.sha256(_scale_bytes(issuer["configuration"]["installation"])).hexdigest(),
        "processPid": issuer_process["pid"], "processStartTicks": issuer_process["startTicks"]}
    details = modules["joins"]["scale_native_request_details"](issuer_event_path.resolve(), native_selected)
    result = json.loads(read_direct_guest_file(worker, python, runtime_root + "/result.json", 1048576))
    wave_names = [row["wave"] for row in result.get("waves", [])] if not case["attestationCapped"] else ["cap-candidate", "cap-expired"]
    waves, wave_references = [], []
    for name in wave_names:
        body = _scale_capture_file(worker, python, runtime_root + "/waves/" + name + ".jsonl", 64 * 1024 * 1024)
        filename = label + "-" + name + ".jsonl"
        digest = retain_direct_flow(filename, body)
        wave_references.append({"wave": name, "file": filename, "sha256": digest, "bytes": len(body)})
        rows = [json.loads(line, object_pairs_hook=_scale_closed) for line in body.splitlines()]
        if len(rows) != 4224:
            raise ValueError("actual retained scale wave omitted an original outcome")
        waves.append((name, rows))
    captures = proxy_capture["bodies"]
    # The selected helper verifies retained signatures and full issuer originals
    # without assigning them new current permission. No dict or callback PASS
    # replaces that executable's actual bounded outputs.
    verified = _scale_verify_actual_replies(native, tools, case, issuer, captures)
    joined = modules["joins"]["join_scale_issuer_calls"](dispatches, captures, details, verified)
    wave_facts = [modules["joins"]["scale_wave_rpc_facts"](rows, name, joined) for name, rows in waves]
    budgets = modules["joins"]["scale_budget_facts"](joined, details, issuer_process["allocatedMillicores"])
    loaded_cpu = modules["joins"]["scale_loaded_cpu_facts"](
        result.get("loadedCpuWaves", []), waves, cpu_records, issuer_process, workload_process)
    required_samples_present = (budgets["latencyBudgetSatisfied"] is not None
        and loaded_cpu["loadedCpuBudgetSatisfied"] is not None
        and budgets["missingSigningCpuSamples"] == 0
        and all(value is not None for value in budgets["queueWaitNs"]))
    receipt = {"outcome": "actual_capture_complete", "case": case["case"], "transport": result,
        "issuer": issuer_process, "issuerTerminal": stopped, "proxyWindow": proxy_window,
        "dispatchAndIssuerCalls": joined, "waves": wave_facts, "budgets": budgets, "loadedCpu": loaded_cpu,
        "requiredMeasurementSamplesPresent": required_samples_present,
        "qualification": None, "scope": "actual local evidence; policy budget failures remain failures, no Hosted/fleet headroom claim"}
    measurement_sha = retain_direct_flow(label + "-measurement.json", receipt)
    wave_inventory_sha = retain_direct_flow(label + "-wave-inventory.json", wave_references)
    # Assess only after every raw report is retained. The previous all-wave
    # aggregate, including unknown outage CPU, remains byte-for-byte evidence.
    publication = projection["configurations"][0]["objectConsumer"]["publications"][0]
    assessment = modules["joins"]["scale_case_policy_assessment"](
        case["case"], waves, contexts, projection["cohortDigests"], joined, details,
        loaded_cpu, result, issuer_process, stopped, publication["attestation"]["valid_until"],
        {"measurement": "sha256:" + measurement_sha, "waves": "sha256:" + wave_inventory_sha,
            "publication": "sha256:" + projection["publicationSha256"]})
    retain_direct_flow(label + "-policy-assessment.json", assessment)
    return {**receipt, "policyAssessment": assessment}



def _scale_validate_cpu_request(request, pins, records):
    """Match one sequential sample request to the two actual process originals."""
    fields = {"sequence", "phase", "wave", "waveOriginalsSha256", "nonce", "requestedUnixNs"}
    if (len(records) >= 32 or set(request) != set(pins) | fields
            or any(request[name] != value for name, value in pins.items())
            or type(request["sequence"]) is not int or request["sequence"] != len(records)
            or request["phase"] != ("end" if len(records) % 2 else "start")
            or not isinstance(request["wave"], str) or not re.fullmatch(r"[a-z0-9-]{1,64}", request["wave"])
            or not isinstance(request["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", request["nonce"])
            or not isinstance(request["waveOriginalsSha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", request["waveOriginalsSha256"])
            or type(request["requestedUnixNs"]) is not int or request["requestedUnixNs"] <= 0):
        raise ValueError("CPU handshake differs from the exact bounded wave/process selection")
    if any(row["original"]["nonce"] == request["nonce"] for row in records):
        raise ValueError("CPU handshake nonce was reused")
    if records and len(records) % 2:
        before = records[-1]["original"]
        if any(request[name] != before[name] for name in ("wave", "waveOriginalsSha256")):
            raise ValueError("CPU endpoint substituted its offered wave")
    elif any(row["original"]["wave"] == request["wave"] for row in records):
        raise ValueError("CPU wave was offered more than once")

def _scale_capture_proxy_bodies(native, tools, observations, label):
    captured, aggregate = [], 0
    root = Path("external-direct-flow")
    for row in observations:
        receipt = {"requestId": row["request_id"], "procedure": row["procedure"],
            "method": row["method"], "status": row["status"], "bodies": {}}
        for direction in ("request", "response"):
            path = row[direction + "_body_file"]
            prefix = "/var/lib/hybrid-native-observations/" + ("client-body/" if direction == "request" else "response-bodies/")
            if not path.startswith(prefix) or ".." in Path(path).parts:
                raise ValueError("actual issuer body escaped selected private proxy custody")
            try:
                body = read_direct_guest_file(native, tools["python"], path, 1048576)
            except RuntimeError:
                receipt["bodies"][direction] = None
                continue
            expected = row[direction + "_body_bytes"]
            if expected is not None and len(body) != expected:
                raise ValueError("captured issuer body differs from its actual proxy byte observation")
            aggregate += len(body)
            if aggregate > 512 * 1024 * 1024:
                raise ValueError("actual issuer raw corpus exceeded its selected bound")
            name = label + "-" + row["request_id"] + "." + direction + ".body"
            digest = retain_direct_flow(name, body)
            receipt["bodies"][direction] = {"file": str(root / name), "sha256": digest, "byteSize": len(body)}
        captured.append(receipt)
    result = {"bodies": captured, "actualRawBytes": aggregate, "qualification": None}
    retain_direct_flow(label + "-private-bodies.json", result)
    return result


def _scale_verify_actual_replies(native, tools, case, issuer, captures):
    reference = tools["leaseScaleReplyCodec"]
    if (set(reference) != {"path", "sha256", "sourceDigest"} or not reference["path"].startswith("/nix/store/")
            or reference["sourceDigest"] != tools["leaseScaleNativeSourceDigest"]):
        raise ValueError("historical codec has no independently selected same-source provenance")
    root = case["issuerStore"] + "/retained-reply-observation"
    _scale_root(native, tools["python"], root)
    pairs = []
    for index, capture in enumerate(captures):
        if capture["status"] != 200:
            continue
        request, reply = capture["bodies"]["request"], capture["bodies"]["response"]
        if request is None or reply is None:
            raise ValueError("positive issuer transport has incomplete actual private bytes")
        bodies = []
        for direction, original in (("request", request), ("reply", reply)):
            body = Path(original["file"]).read_bytes()
            if len(body) != original["byteSize"] or hashlib.sha256(body).hexdigest() != original["sha256"]:
                raise ValueError("actual retained issuer raw bytes changed before codec execution")
            path = root + f"/{index:04d}." + direction
            install_direct_guest_file(native, tools["python"], path, body)
            bodies.append((path, body))
        original_request = _closed_review_json(bodies[0][1])
        pairs.append({"ownerNonce": original_request["nonce"], "requestFile": bodies[0][0],
            "requestSha256": request["sha256"], "requestBytes": request["byteSize"],
            "replyFile": bodies[1][0], "replySha256": reply["sha256"], "replyBytes": reply["byteSize"]})
    if not pairs:
        return []
    selection = {"version": 1, "issuerKeyId": case["signingKeyId"], "issuerPublicKey": issuer["publicKey"], "pairs": pairs}
    path = root + "/selection.json"
    output = root + "/observed.json"
    body = _scale_bytes(selection)
    if len(body) > 1048576:
        raise ValueError("retained reply observation original exceeded its bound")
    install_direct_guest_file(native, tools["python"], path, body)
    execution = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, subprocess
        from pathlib import Path
        executable = Path(selected['codec']['path'])
        with executable.open('rb') as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != selected['codec']['sha256']:
                raise ValueError('selected source-built historical codec changed')
        result = subprocess.run([str(executable), selected['selection'], selected['output']],
            stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=60)
        print(json.dumps({'exitCode': result.returncode, 'stderrBytes': len(result.stderr),
            'stderrSha256': hashlib.sha256(result.stderr).hexdigest(),
            'executableSha256': selected['codec']['sha256']}))
    """, {"codec": reference, "selection": path, "output": output}, timeout=65))
    retain_direct_flow("lease-scale-" + case["case"] + "-codec-execution.json", execution)
    if execution["exitCode"] != 0 or execution["stderrBytes"]:
        raise ValueError("actual historical signature codec refused; raw originals retained")
    observed = read_direct_guest_file(native, tools["python"], output, 4 * 1024 * 1024)
    retain_direct_flow("lease-scale-" + case["case"] + "-verified-historical-replies.json", observed)
    result = json.loads(observed)
    if len(result) != len(pairs):
        raise ValueError("actual codec omitted retained positive replies")
    return result
