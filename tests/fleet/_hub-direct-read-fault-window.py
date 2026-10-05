"""Exercise a real alternate Worker revision and retain distinct fault scopes.

The alternate runner receives one unchanged, still-eligible Native metadata
original. Its installed current-source scheduling policy must refuse before
semantic parsing or provider dispatch. Existing queue timeout and stale commit
receipts keep their own authentication and provider-observation limitations.
"""

import copy
import base64
import hashlib
import json
from pathlib import Path
import re
import time


def revision_worker_configuration(original, fixture):
    """Change only the actually imported module, preserving authority and state."""
    if (set(fixture) != {"source", "distribution", "purpose", "sourceDigest", "scriptVersion", "features"}
            or fixture["purpose"] not in {"comment-only-source-revision", "retained-source-revision"}
            or fixture["features"] != ["do-e2e"]
            or not re.fullmatch(r"[0-9a-f]{64}", fixture["sourceDigest"])
            or fixture["scriptVersion"] != "emulated-" + fixture["sourceDigest"]
            or hashlib.sha256(fixture["source"].encode()).hexdigest() != fixture["sourceDigest"]
            or any(not re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/]+", fixture[name])
                for name in ("source", "distribution"))):
        raise ValueError("Revision fixture lacks its genuine source/distribution selection")
    policy = json.loads(original["bindings"]["HUB_PROVIDER_CAPACITY_POLICY"])
    if (set(policy) != {"version", "deployment_id", "source_digest", "script_version", "maximum_provider_requests"}
            or policy["version"] != 1 or policy["maximum_provider_requests"] != 3
            or policy["deployment_id"] != original["bindings"]["HUB_DEPLOYMENT_ID"]
            or not re.fullmatch(r"[0-9a-f]{64}", policy["source_digest"])
            or policy["script_version"] != "emulated-" + policy["source_digest"]
            or policy["source_digest"] == fixture["sourceDigest"]
            or original["scriptPath"] == fixture["distribution"] + "/shim.mjs"
            or original["resourcePersistencePath"] != "/var/lib/hybrid-worker/state"
            or original["host"] != "127.0.0.1" or original["port"] != 4443):
        raise ValueError("Revision fixture does not preserve an installed current-source C3 policy")
    configuration = copy.deepcopy(original)
    configuration["scriptPath"] = fixture["distribution"] + "/shim.mjs"
    return configuration


def require_revision_source_abi(current_source, alternate_source, purpose):
    """Bind refusal to the same authentication/configuration code before dispatch."""
    current = Path(current_source)
    alternate = Path(alternate_source)
    files = (
        "crates/aos-hub-worker/src/direct_upload/provider_capacity/policy.rs",
        "crates/aos-hub-worker/src/external_object/config.rs",
        "crates/aos-hub-worker/src/external_object/copy/config.rs",
        "crates/aos-hub-worker/src/hybrid_binding.rs",
        # The source-contract and current-reader checks after domain selection
        # must not turn an old unsupported-mode refusal into revision evidence.
        "crates/aos-hub-worker/src/external_object/inspection/runtime.rs",
    )
    digests = {}
    for name in files:
        original = (current / name).read_bytes()
        candidate = (alternate / name).read_bytes()
        if len(original) > 1024 * 1024 or candidate != original:
            raise ValueError("Alternate revision changes the authentication/configuration ABI")
        digests[name] = hashlib.sha256(original).hexdigest()
    for name, start, end in (
            ("crates/aos-hub-worker/src/hybrid.rs", "async fn execute_storage_work(", "    let operation_kind ="),
            ("crates/aos-hub-worker/src/external_object/inspection/runtime.rs",
                "pub(crate) async fn execute(", "    let fresh =")):
        def prefix(root):
            text = (root / name).read_text()
            if len(text.encode()) > 1024 * 1024 or text.count(start) != 1:
                raise ValueError("Alternate revision guard source is absent or ambiguous")
            body = text.split(start, 1)[1]
            if end not in body:
                raise ValueError("Alternate revision guard boundary is absent")
            return body.split(end, 1)[0]
        original = prefix(current)
        if prefix(alternate) != original:
            raise ValueError("Alternate revision changes the pre-dispatch guard")
        digests[name + ":pre-dispatch"] = hashlib.sha256(original.encode()).hexdigest()
    if purpose == "comment-only-source-revision":
        suffix = b"\n// This source snapshot belongs to the fleet revision-refusal fixture.\n"
        original_names = {str(path.relative_to(current)) for path in current.rglob("*")
            if path.is_file() or path.is_symlink()}
        alternate_names = {str(path.relative_to(alternate)) for path in alternate.rglob("*")
            if path.is_file() or path.is_symlink()}
        if original_names != alternate_names:
            raise ValueError("Comment revision changed its source file set")
        for name in original_names:
            original = current / name
            candidate = alternate / name
            if original.is_symlink() or candidate.is_symlink():
                if not (original.is_symlink() and candidate.is_symlink()
                        and original.readlink() == candidate.readlink()):
                    raise ValueError("Comment revision changed a source link")
                continue
            expected = original.read_bytes()
            if name == "crates/aos-hub-worker/src/lib.rs":
                expected += suffix
            if candidate.read_bytes() != expected or bool(original.stat().st_mode & 0o111) != bool(candidate.stat().st_mode & 0o111):
                raise ValueError("Comment revision changed another source body or mode")
    return {"version": 1, "sourceFiles": digests,
        "scope": "Same MAC/current-binding/configuration guards before semantic dispatch; no acceptance"}


def require_revision_refusal(original, received, response, runtime_log, before, after,
                             fixture, installation, provider_rows):
    """Join exact refused bytes, the real handler and unchanged authoritative data."""
    plan = json.loads(original)
    digest = hashlib.sha256(original).hexdigest()
    if (received != original or plan.get("operation") != {"kind": "inspect_metadata", "path": "info/refs"}
            or response != {"status": 503, "body": b"storage work failed"}
            or not re.fullmatch(r"[0-9a-f]{32}", plan.get("plan_id", ""))
            or "storage_work_failed plan=" + plan["plan_id"] + " operation=inspect_metadata"
                not in runtime_log
            or installation["sourceDigest"] != fixture["sourceDigest"]
            or installation["scriptVersion"] != fixture["scriptVersion"]
            or installation["wasmSha256"] == installation["currentWasmSha256"]
            or installation["configurationDelta"] != ["scriptPath"]
            or installation["macVerified"] is not True
            or installation["receivedRequestSha256"] != digest
            or provider_rows):
        raise ValueError("Actual revision refusal is incomplete or reached a provider")
    if (set(before) != set(after) or "index" not in before
            or len(before["index"]) != 1 or len(after["index"]) != 1
            or before["index"][0][:2] != ["fresh", None]
            or after["index"][0][0] != "failed"
            or before["index"][0][2:] != after["index"][0][2:]
            or any(before[name] != after[name] for name in set(before) - {"index"})):
        raise ValueError("Revision refusal changed authoritative index contents")
    return {"version": 1, "outcome": "installed_worker_revision_refused",
        "requestSha256": digest, "replySha256": hashlib.sha256(response["body"]).hexdigest(),
        "alternateSourceDigest": fixture["sourceDigest"],
        "providerRequestsForSelectedKey": 0, "remoteDrain": None,
        "scope": "Actual authenticated metadata handler refusal before source-policy dispatch; no acceptance"}


def called_read_fault_ledger(timeout, stale, revision):
    """Require all called cases without converting their different proof scopes."""
    if (timeout.get("status") != "observed_verification_refusal"
            or stale.get("verdict", {}).get("outcome") != "native_stale_result_refused"
            or stale.get("providerRequests") is not None
            or revision.get("verdict", {}).get("outcome") != "installed_worker_revision_refused"
            or revision.get("restored") is not True):
        raise ValueError("Called fault ledger is missing a real refusal or recorded restoration")
    cases = {
        "provider_timeout": {"receipt": "verification-timeout-assessment.json",
            "scope": "Real conditional queue verification; no Native Stage MAC"},
        "stale_placement": {"receipt": "actual-stale-index-case.private.json",
            "scope": "Real Native index commit fence; provider request count unknown"},
        "worker_revision": {"receipt": "actual-worker-revision-refusal.json",
            "scope": "Real alternate compiled module/current policy and retained metadata original"},
    }
    for name, value in (("provider_timeout", timeout), ("stale_placement", stale), ("worker_revision", revision)):
        path = Path("external-direct-flow") / cases[name]["receipt"]
        body = path.read_bytes()
        if body != json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n":
            raise ValueError("Called refusal receipt changed after assessment")
        cases[name]["sha256"] = hashlib.sha256(body).hexdigest()
        cases[name]["byteSize"] = len(body)
    return {"version": 1, "cases": cases, "remoteDrain": None,
        "scope": "Called fault coverage only; each retained receipt keeps its own authority and effect scope"}


def run_direct_worker_revision_case(native, worker, s3, tools, process, registry, source, artifacts):
    """Hold one current index original across a sequential alternate-module epoch."""
    fixture = tools["readRevisionFixture"]
    original_bytes = read_direct_guest_file(worker, tools["python"], process["configurationFile"], 1024 * 1024)
    original_configuration = _closed_review_json(original_bytes)
    alternate_configuration = revision_worker_configuration(original_configuration, fixture)
    alternate_bytes = json.dumps(alternate_configuration, sort_keys=True, separators=(",", ":")).encode()
    installed = install_direct_guest_file(worker, tools["python"],
        "/var/lib/hybrid-worker/read-revision/configuration.json", alternate_bytes)
    custody = observe_direct_revision_artifacts(worker, tools, fixture, original_configuration)
    # Native's ordinary index child inherits its freshly retained real service
    # environment. The fixed listener retains the original before Worker sees it.
    query = DirectStaleIndexSql(native, tools, label="read-revision")
    literal = lambda value: "'" + value.replace("'", "''") + "'"
    slug = registry["registry"]["slug"]
    selection_query = ("SELECT placement.id, placement.resource_version, binding.id, binding.resource_version, "
        "binding.kind, placement.prefix, binding.object_bucket, binding.object_prefix FROM surface_placements placement "
        "JOIN bindings binding ON binding.id=placement.binding_id JOIN registries registry "
        "ON registry.id=placement.registry_id WHERE registry.slug=" + literal(slug)
        + " AND placement.name=" + literal(registry["placement"]["name"]) + " LIMIT 2")
    rows = query(selection_query)
    if len(rows) != 1 or len(rows[0]) != 8:
        raise ValueError("Revision case lacks one current placement/binding")
    row = rows[0]
    if any(type(value) is not int or not 0 < value < 2**53 for value in row[:4]):
        raise ValueError("Revision case SQL coordinates exceed exact listener geometry")
    if row[4] != "s3" or any(not isinstance(value, str) for value in row[5:]):
        raise ValueError("Revision case does not select its real External S3 binding")
    # Both logical prefixes are composed by the actual keymap. A placement
    # already containing the binding prefix is deliberately not deduplicated.
    physical_key = "/" + row[6] + "/" + "/".join(
        [value.strip("/") for value in (row[7], row[5], "info/refs") if value])
    before = registry_index_observations(query, slug)
    if before["index"][0][:3] != ["fresh", None, source["sourceCommit"]]:
        raise ValueError("Revision case source is not the freshly signed current publication")
    trust = observe_direct_native_trust(native, tools, artifacts, "read-revision")
    trust_bytes = Path("external-direct-flow/native-trust-read-revision.json").read_bytes()
    if hashlib.sha256(trust_bytes).hexdigest() != trust:
        raise ValueError("Revision Native process observation changed")
    controller = managed_fixture_module(tools["staleIndexController"], "read_revision_index")
    listener = tools["staleIndexInstallation"]
    environment = controller.capture_direct_stale_index_environment(native, tools, json.loads(trust_bytes),
        listener["root"] + "/revision.environment")
    common = {"processModuleFile": tools["staleIndexProcess"], "installation": listener}
    selection = {"version": 1, "originHost": "aos.andyl.org", "deployment_id": tools["deploymentId"],
        **dict(zip(("placement_id", "placement_resource_version", "binding_id", "binding_resource_version",
            "binding_kind", "placement_prefix"), row[:6]))}
    controller._guest(native, tools, "control", {**common,
        "request": {"version": 1, "kind": "arm-revision", "selection": selection}})
    root = listener["root"] + "/revision-index"
    controller._guest(native, tools, "launch-index", {"root": root, "registrySlug": slug,
        "executable": tools["hub"], "python": tools["python"], "environment": environment,
        "processModuleFile": tools["staleIndexProcess"]})
    alternate = None
    restored = None
    current_disposed = False
    producer_error = None
    try:
        deadline = time.monotonic() + 35
        while True:
            held = controller._guest(native, tools, "control", {**common,
                "request": {"version": 1, "kind": "status"}})
            if held["state"] == "held":
                break
            if held["state"] != "unused" or time.monotonic() >= deadline:
                raise ValueError("Revision case did not retain a genuine eligible original")
            time.sleep(0.1)
        before_provider = direct_log_position(s3, tools["python"], "/var/lib/hybrid-s3/provider-observations.jsonl")
        before_received = direct_log_position(worker, tools["python"], "/var/lib/hybrid-worker-boundary/requests.jsonl")
        current_stop = stop_direct_worker(worker, tools["python"], process)
        current_disposed = True
        retain_direct_flow("read-revision-current-stop.json", current_stop)
        alternate = start_direct_worker(worker, tools, installed["file"], "read-revision")
        wait_worker_transport(worker, tools["curl"], tools["python"], True,
            observation_label="worker-read-revision")
        released = controller._guest(native, tools, "control", {**common,
            "request": {"version": 1, "kind": "release", "requestSha256": held["requestSha256"]}})
        deadline = time.monotonic() + 95
        while True:
            terminal = controller._guest(native, tools, "index-terminal", {"root": root,
                "processModuleFile": tools["staleIndexProcess"]})
            if terminal is not None:
                break
            if time.monotonic() >= deadline:
                raise ValueError("Revision index terminal missing; no retry or rollback inference")
            time.sleep(0.1)
        if terminal["exitCode"] == 0 or terminal["timedOut"] is not False:
            raise ValueError("Revision index did not reach a genuine bounded refusal")
        evidence = observe_direct_revision_exchange(native, worker, tools, listener, held, alternate,
            custody, before_received, original_configuration)
        provider_file, provider_window = retain_direct_log_window(s3, tools["python"], before_provider,
            "read-revision-provider.private.jsonl")
        provider_rows = [_closed_review_json(line) for line in provider_file.read_bytes().splitlines()]
        selected_rows = [value for value in provider_rows if value["path"] == physical_key]
        after = registry_index_observations(query, slug)
        if query(selection_query) != rows:
            raise ValueError("Revision case current placement/binding changed")
        verdict = require_revision_refusal(evidence["original"], evidence["received"], evidence["response"],
            evidence["runtimeLog"], before, after, fixture, evidence["installation"], selected_rows)
        result = {"version": 1, "verdict": verdict, "fixture": fixture, "custody": custody,
            "held": held, "released": released, "terminal": terminal, "alternateProcess": alternate,
            "exchange": evidence["receipt"], "providerWindow": provider_window,
            "unselectedProviderRows": len(provider_rows) - len(selected_rows), "before": before, "after": after,
            "restored": False, "remoteDrain": None}
        controller._guest(native, tools, "control", {**common,
            "request": {"version": 1, "kind": "finish-revision"}})
    except BaseException as error:
        producer_error = error
        try:
            controller._guest(native, tools, "control", {**common,
                "request": {"version": 1, "kind": "close"}})
        except Exception:
            error.add_note("Revision listener original disposition remains unknown")
        raise
    finally:
        try:
            if alternate is not None:
                retain_direct_flow("read-revision-alternate-stop.json", stop_direct_worker(worker, tools["python"], alternate))
            if current_disposed:
                if read_direct_guest_file(worker, tools["python"], process["configurationFile"], 1024 * 1024) != original_bytes:
                    raise ValueError("Current Worker configuration changed during revision case")
                restored = start_direct_worker(worker, tools, process["configurationFile"], "read-revision-restored")
                wait_worker_transport(worker, tools["curl"], tools["python"], True,
                    observation_label="worker-read-revision-restored")
                retain_direct_flow("read-revision-restored-process.json", restored)
        except Exception:
            if producer_error is None:
                raise
            producer_error.add_note("Recorded revision epoch cleanup/restoration is incomplete")
        if producer_error is not None:
            retain_direct_flow("read-revision-unresolved.json", {"version": 1, "alternate": alternate,
                "restoredProcess": restored, "remoteDrain": None})
    result.update(restored=True, restoredProcess=restored)
    retain_direct_flow("actual-worker-revision-refusal.json", result)
    # A new ordinary command proves the restored owner can rebuild the same
    # immutable index. The failed original is never replayed or re-signed.
    run_direct_revision_restored_index(native, tools, controller, environment, slug, before, query)
    return result, restored


def observe_direct_revision_artifacts(worker, tools, fixture, configuration):
    """Hash actual public modules and bind the compiled digest to a real snapshot."""
    policy = _closed_review_json(configuration["bindings"]["HUB_PROVIDER_CAPACITY_POLICY"].encode())
    if (policy["source_digest"] != hashlib.sha256(tools["workerSourcePath"].encode()).hexdigest()
            or configuration["scriptPath"] != tools["workerDistribution"] + "/shim.mjs"):
        raise ValueError("Revision case current policy/module differs from the selected actual source")
    abi = require_revision_source_abi(tools["workerSourcePath"], fixture["source"], fixture["purpose"])
    result = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, stat, subprocess
        from pathlib import Path

        root = Path('/var/lib/hybrid-worker/read-revision')
        root.mkdir(mode=0o700, exist_ok=True)
        def hashed(path, wasm=False):
            with Path(path).open('rb') as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 512*1024*1024:
                    raise ValueError('Revision artifact exceeds its regular-file bound')
                prefix = source.read(4)
                if wasm and prefix != b'\\x00asm':
                    raise ValueError('Revision artifact is not real Wasm')
                source.seek(0)
                digest = hashlib.file_digest(source, 'sha256').hexdigest()
                after = os.fstat(source.fileno())
            if any(getattr(before, field) != getattr(after, field)
                    for field in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):
                raise ValueError('Revision artifact changed while hashing')
            return {'file':str(path),'sha256':digest,'byteSize':before.st_size}
        files = {'alternateWasm':hashed(selected['fixture']['distribution']+'/index.wasm', True),
            'alternateShim':hashed(selected['fixture']['distribution']+'/shim.mjs'),
            'currentWasm':hashed(selected['currentDistribution']+'/index.wasm', True),
            'currentShim':hashed(selected['currentDistribution']+'/shim.mjs')}
        if files['alternateWasm']['sha256'] == files['currentWasm']['sha256']:
            raise ValueError('Revision negative substituted identical Wasm')
        for label, path in (('source',selected['fixture']['source']),
                            ('distribution',selected['fixture']['distribution'])):
            target = root/(label+'.nar')
            descriptor = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(descriptor,'wb') as output:
                dumped = subprocess.run([selected['nixStore'],'--dump',path],
                    stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.PIPE,
                    timeout=60,check=False)
                output.flush(); os.fsync(output.fileno())
            if dumped.returncode:
                raise ValueError('Revision source/distribution NAR custody failed')
            files[label+'Nar'] = hashed(target)
        # Read the public constant in the installed module, independently of
        # any configured label. Its value is produced by the normal recipe.
        if selected['fixture']['sourceDigest'].encode() not in Path(files['alternateWasm']['file']).read_bytes():
            raise ValueError('Actual alternate Wasm lacks its source-built digest')
        print(json.dumps({'version':1,'files':files,'sourceDigest':selected['fixture']['sourceDigest'],
            'scriptVersion':selected['fixture']['scriptVersion'],'purpose':selected['fixture']['purpose'],
            'scope':'Actual alternate files/source only; never a current acceptance'}))
    """, {"fixture": fixture, "currentDistribution": str(Path(configuration["scriptPath"]).parent),
        "nixStore": tools["nixStore"]}, timeout=150))
    result["abi"] = abi
    retain_direct_flow("read-revision-artifact-custody.json", result)
    return result


def observe_direct_revision_exchange(native, worker, tools, listener, held, process, custody,
                                    before_received, original_configuration):
    """Join the listener original with independent Worker bytes and an actual MAC."""
    root = listener["root"]
    original = read_direct_guest_file(native, tools["python"], root + "/revision-hold/original-request.json", 65536)
    transport = _closed_review_json(read_direct_guest_file(native, tools["python"],
        root + "/revision-hold/original-transport.json", 65536))
    reply = _closed_review_json(read_direct_guest_file(native, tools["python"], root + "/revision-reply.json", 512 * 1024))
    if (hashlib.sha256(original).hexdigest() != held["requestSha256"]
            or reply["requestSha256"] != held["requestSha256"]):
        raise ValueError("Revision listener original/reply changed")
    received_file, received_window = retain_direct_log_window(worker, tools["python"], before_received,
        "read-revision-worker-boundary.private.jsonl")
    raw, completed = direct_storage_completion_receipts(received_file.read_text(), True)
    observations = []
    for value in raw:
        selected = {name: item for name, item in value.items() if name not in {"origin_request_id", "caller"}}
        observations.extend(native_control_observations(json.dumps(selected), "/var/lib/hybrid-worker-boundary"))
    _, captures = capture_direct_native_bodies(worker, tools, observations,
        "/var/lib/hybrid-worker-boundary", "worker-received")
    matches = [item for item in captures["bodies"] if item["bodies"]["request"] is not None
        and item["bodies"]["request"]["sha256"] == held["requestSha256"]]
    if len(matches) != 1 or matches[0]["status"] != 503:
        raise ValueError("Revision case lacks one actual independently received refusal")
    received = Path(matches[0]["bodies"]["request"]["file"]).read_bytes()
    authenticated = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, hmac, os
        from pathlib import Path

        configuration = json.loads(Path(selected['process']['configurationFile']).read_bytes())
        actual_configuration = hashlib.sha256(Path(selected['process']['configurationFile']).read_bytes()).hexdigest()
        original_configuration = selected['originalConfiguration']
        changed = sorted(name for name in set(configuration)|set(original_configuration)
            if configuration.get(name) != original_configuration.get(name))
        if (changed != ['scriptPath']
                or configuration['scriptPath'] != selected['alternateShim']):
            raise ValueError('Actual revision configuration changes authority or state')
        directory = Path('/proc')/str(selected['process']['pid'])
        if ((directory/'stat').read_text().rpartition(') ')[2].split()[19] != selected['process']['startTicks']
                or directory.stat().st_uid != selected['process']['ownerUid']
                or (directory/'cmdline').read_bytes().split(b'\\x00')[:-1]
                    != [os.fsencode(value) for value in selected['process']['arguments']]
                or actual_configuration != selected['process']['configurationSha256']):
            raise ValueError('Revision runner lifetime/configuration changed')
        body=base64.b64decode(selected['body'],validate=True)
        signature=selected['signature']
        actual=hmac.new(configuration['bindings']['HUB_STORAGE_WORK_KEY'].encode(),
            b'aos-storage-work-v1\\x00'+body,hashlib.sha256).hexdigest()
        if not hmac.compare_digest(actual,signature):
            raise ValueError('Retained Native original MAC is invalid')
        print(json.dumps({'macVerified':True,'receivedRequestSha256':hashlib.sha256(body).hexdigest(),
            'configurationDelta':changed}))
    """, {"process": process, "body": base64.b64encode(received).decode(), "signature": transport["signature"],
        "originalConfiguration": original_configuration,
        "alternateShim": str(Path(custody["files"]["alternateShim"]["file"]))}))
    runtime_bytes = read_direct_guest_file(worker, tools["python"], process["logFile"], 16 * 1024 * 1024)
    runtime_reference = {"file": "read-revision-worker-runtime.private.log",
        "sha256": retain_direct_flow("read-revision-worker-runtime.private.log", runtime_bytes)}
    receipt = {"version": 1, "receivedWindow": received_window, "received": matches[0],
        "reply": reply, "runtime": runtime_reference, "authenticated": authenticated,
        "process": process, "remoteDrain": None}
    receipt_sha = retain_direct_flow("read-revision-exchange.private.json", receipt)
    return {"original": original, "received": received,
        "response": {"status": reply["status"], "body": base64.b64decode(reply["bodyBase64"], validate=True)},
        "runtimeLog": runtime_bytes.decode(), "receipt": {"file": "read-revision-exchange.private.json", "sha256": receipt_sha},
        "installation": {**authenticated, "sourceDigest": custody["sourceDigest"],
            "scriptVersion": custody["scriptVersion"],
            "wasmSha256": custody["files"]["alternateWasm"]["sha256"],
            "currentWasmSha256": custody["files"]["currentWasm"]["sha256"]}}


def run_direct_revision_restored_index(native, tools, controller, environment, slug, before, query):
    """Issue a new ordinary command after restoration, never replay the held bytes."""
    root = tools["staleIndexInstallation"]["root"] + "/revision-restored-index"
    controller._guest(native, tools, "launch-index", {"root": root, "registrySlug": slug,
        "executable": tools["hub"], "python": tools["python"], "environment": environment,
        "processModuleFile": tools["staleIndexProcess"]})
    deadline = time.monotonic() + 95
    while True:
        terminal = controller._guest(native, tools, "index-terminal", {"root": root,
            "processModuleFile": tools["staleIndexProcess"]})
        if terminal is not None:
            break
        if time.monotonic() >= deadline:
            raise ValueError("Restored current index terminal is unknown")
        time.sleep(0.1)
    after = registry_index_observations(query, slug)
    retained = {"version": 1, "terminal": terminal, "before": before, "after": after,
        "scope": "New actual ordinary index command on restored current source"}
    retain_direct_flow("read-revision-restored-index.json", retained)
    if terminal["exitCode"] != 0 or terminal["timedOut"] is not False or after != before:
        raise ValueError("Restored current Worker did not preserve the exact signed index")
