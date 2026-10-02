"""Call one same-source audience refusal with exact local process originals.

The installed artifact A remains unchanged. Actual origin B uses the same
selected Worker bytes and local persistence after A exits. Only complete
post-auth loader records can describe a scoped no-dispatch refusal; they do
not establish a source revision mismatch or global provider zero.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import shlex
import time


ROUTE = "/_internal/storage/oci-document-projection"


def require(value, message):
    if not value:
        raise ValueError(message)


def _guest(worker, tools, code, selected):
    require(tools["python"].startswith("/nix/store/")
            and tools["ociProfileProcess"].startswith("/nix/store/"), "profile installed tools absent")
    encoded = base64.b64encode(json.dumps(selected, separators=(",", ":")).encode()).decode()
    program = """
import base64, hashlib, importlib.util, json, os, socket, stat, struct, time
from pathlib import Path
selected = json.loads(base64.b64decode(INPUT))
spec = importlib.util.spec_from_file_location('oci_profile_process', selected['module'])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
""".replace("INPUT", repr(encoded)) + code
    status, stdout, _ = worker.agent.request(
        (shlex.quote(tools["python"]) + " - <<'OCI_PROFILE_GUEST'\n" + program
         + "\nOCI_PROFILE_GUEST\n").encode(), timeout=90)
    require(status == 0 and len(stdout) <= 8 * 1024 * 1024, "profile actual guest command refused")
    return json.loads(stdout)


def guest(worker, tools, code, **selected):
    return _guest(worker, tools, code, {"module": tools["ociProfileProcess"], **selected})


def prepare_profile_listener(worker, tools, prepared):
    """Freeze only the listener original before initial runtime observations."""
    coordinates = prepared["coordinates"]
    root = coordinates["workerRoot"] + "/profile-hold"
    return guest(worker, tools, """
root = Path(selected['root']); root.mkdir(mode=0o700, exist_ok=False)
configuration = {'version':1,'root':str(root),'listenPort':4649,
    'upstreamAPort':4645,'upstreamBPort':4647,'originHost':'localhost:4643'}
retained = helper.retained(root/'configuration.json', json.dumps(configuration,separators=(',',':')).encode())
print(json.dumps({'version':1,'root':str(root),'configuration':retained,
    'arguments':[selected['node'],selected['listener'],retained['file']],
    'socketFile':str(root/'control.sock'),'readyFile':str(root/'listener-ready.json')}))
""", root=root, node=tools["node"], listener=tools["ociProfileListener"])


def listener_control(worker, tools, listener, process, request):
    """Retain one actual private socket command and pin its owning runner."""
    return guest(worker, tools, """
helper.process_identity(selected['process'])
root=Path(selected['listener']['root'])/'controls'; root.mkdir(mode=0o700,exist_ok=True)
sequence=len(list(root.iterdir()))//2
if sequence>=256: raise ValueError('profile control corpus exceeds bound')
raw=json.dumps(selected['request'],separators=(',',':')).encode()+b'\\n'
helper.retained(root/(str(sequence)+'.original.json'),raw)
file=selected['listener']['socketFile']; metadata=Path(file).lstat()
if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid!=os.getuid() or metadata.st_mode&0o077:
    raise ValueError('profile control socket custody differs')
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
    peer.settimeout(5); peer.connect(file)
    pid,uid,_=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if pid!=selected['process']['pid'] or uid!=selected['process']['ownerUid']:
        raise ValueError('profile control peer differs')
    peer.sendall(raw); body=bytearray()
    while not body.endswith(b'\\n'):
        chunk=peer.recv(16385-len(body))
        if not chunk or len(body)+len(chunk)>16384: raise ValueError('profile control response incomplete')
        body.extend(chunk)
helper.process_identity(selected['process'])
helper.retained(root/(str(sequence)+'.reply.json'),bytes(body))
print(json.dumps(json.loads(body)))
""", listener=listener, process=process, request=request)


def await_profile_listener(worker, tools, listener, process):
    """Check actual post-bind readiness and the same private socket process."""
    ready = guest(worker, tools, """
helper.process_identity(selected['process'])
deadline=time.monotonic()+10
while not Path(selected['listener']['readyFile']).exists():
    helper.process_identity(selected['process'])
    if time.monotonic()>=deadline: raise ValueError('profile listener readiness absent')
    time.sleep(.05)
body=helper.private_file(selected['listener']['readyFile'],16384)
value=json.loads(body)
if set(value)!={'version','pid','listenPort','socketFile'} or value['version']!=1 or value['pid']!=selected['process']['pid'] or value['listenPort']!=4649 or value['socketFile']!=selected['listener']['socketFile']:
    raise ValueError('profile listener readiness differs')
helper.process_identity(selected['process']);print(json.dumps(value))
""", listener=listener, process=process)
    listener_control(worker, tools, listener, process, {"version": 1, "kind": "status"})
    return ready


def _bracket(rows, request_sha, outcome):
    require(isinstance(rows, list) and len(rows) == 4, "profile actual bracket incomplete")
    require(all(set(row) == {"version", "scope", "capture_id", "ordinal", "request_sha256", "observed_at", "event"}
                and row["version"] == 1 and row["scope"] == "managed_oci_profile_load"
                and row["request_sha256"] == request_sha and row["ordinal"] == index + 1
                for index, row in enumerate(rows)), "profile actual bracket sequence differs")
    require(re.fullmatch(r"[a-f0-9]{32}", rows[0]["capture_id"])
            and all(row["capture_id"] == rows[0]["capture_id"]
                    and type(row["observed_at"]) is int and row["observed_at"] >= 0
                    for row in rows), "profile actual capture continuity differs")
    events = [row["event"] for row in rows]
    shapes = [
        {"kind", "original", "before"},
        {"kind", "artifact_sha256", "byte_size", "deployment_id", "current_origin",
         "artifact_origin", "source_digest", "script_version", "profile_digest", "verification_now",
         "artifact_issued_at", "artifact_expires_at"},
        {"kind", "outcome", "error"}, {"kind", "outcome", "healthy", "after"},
    ]
    require(all(set(event) == shape for event, shape in zip(events, shapes)),
            "profile actual event shape differs")
    require([event["kind"] for event in events] == ["entry", "artifact", "result", "terminal"]
            and events[2]["outcome"] == events[3]["outcome"] == outcome
            and events[3]["healthy"] is True, "profile actual bracket outcome unknown")
    original = events[0]["original"]
    require(set(original) == {"request_sha256", "document_digest", "nonce", "key",
            "issued_at", "expires_at", "clock_uncertainty_seconds", "source_digest",
            "script_version", "protected_profile_digest"}
            and original["request_sha256"] == request_sha,
            "profile actual entry original differs")
    before, after = events[0]["before"], events[3]["after"]
    counter_fields = {"isolateId", "maximum", "active", "bulkActive", "metadataActive",
                      "peakActive", "metadataAdmissionsDuringBulk", "dispatches"}
    require(all(set(value) == counter_fields and isinstance(value["isolateId"], str)
                and all(type(value[field]) is int and value[field] >= 0
                        for field in counter_fields - {"isolateId"})
                and 1 <= value["maximum"] <= 32
                and value["active"] <= value["maximum"] and value["peakActive"] <= value["maximum"]
                for value in (before, after)), "profile actual counter shape differs")
    require(before["isolateId"] == after["isolateId"]
            and 0 <= before["dispatches"] <= after["dispatches"] < 2**64 - 1,
            "profile actual counter continuity differs")
    return events


def assess_profile_origin_mismatch(original, original_sha, artifact_sha, a_rows, b_rows, observations):
    """Assess actual equal-source loader brackets without a caller zero field."""
    require(set(observations) == {"a", "b"}, "profile A/B observations are not closed")
    for observation in observations.values():
        require(set(observation) == {"origin", "sourceDigest", "scriptVersion", "wasmSha256",
                "runnerSha256", "configurationSha256", "pid"}
                and type(observation["pid"]) is int and observation["pid"] > 1
                and all(re.fullmatch(r"[a-f0-9]{64}", observation[field])
                        for field in ("sourceDigest", "wasmSha256", "runnerSha256", "configurationSha256")),
                "profile actual observation shape differs")
    a = _bracket(a_rows, a_rows[0]["request_sha256"], "accepted")
    b = _bracket(b_rows, original_sha, "refused")
    require(observations["a"]["origin"] == "https://localhost:4643"
            and observations["b"]["origin"] == "https://localhost:4648"
            and observations["a"]["sourceDigest"] == observations["b"]["sourceDigest"]
                == original["issuer"]["source_digest"]
            and observations["a"]["scriptVersion"] == observations["b"]["scriptVersion"]
                == original["issuer"]["script_version"]
            and observations["a"]["wasmSha256"] == observations["b"]["wasmSha256"]
            and observations["a"]["runnerSha256"] == observations["b"]["runnerSha256"]
            and observations["a"]["configurationSha256"] != observations["b"]["configurationSha256"]
            and observations["a"]["pid"] != observations["b"]["pid"],
            "profile actual same-source A/B installation differs")
    require(a[1]["artifact_sha256"] == b[1]["artifact_sha256"] == artifact_sha
            and a[1]["current_origin"] == a[1]["artifact_origin"] == observations["a"]["origin"]
            and b[1]["artifact_origin"] == observations["a"]["origin"]
            and b[1]["current_origin"] == observations["b"]["origin"]
            and a[1]["source_digest"] == b[1]["source_digest"] == original["issuer"]["source_digest"]
            and a[1]["script_version"] == b[1]["script_version"] == original["issuer"]["script_version"]
            and a[1]["profile_digest"] == b[1]["profile_digest"] == original["protected_profile_digest"],
            "profile actual installed artifact/source join differs")
    require(b[1]["artifact_issued_at"] <= b[1]["verification_now"] < b[1]["artifact_expires_at"]
            and a[1]["artifact_issued_at"] == b[1]["artifact_issued_at"]
            and a[1]["artifact_expires_at"] == b[1]["artifact_expires_at"],
            "profile artifact window cannot isolate an origin refusal")
    require(b[0]["original"]["issued_at"] == original["issued_at"]
            and b[0]["original"]["clock_uncertainty_seconds"] == original["clock_uncertainty_seconds"]
            and b[0]["original"]["source_digest"] == original["issuer"]["source_digest"]
            and b[0]["original"]["script_version"] == original["issuer"]["script_version"]
            and b[0]["original"]["protected_profile_digest"] == original["protected_profile_digest"]
            and b[0]["original"]["nonce"] == original["nonce"]
            and b[0]["original"]["key"] == original["key"]
            and b[0]["original"]["document_digest"] == original["descriptor"]["digest"]
            and b[0]["original"]["expires_at"] == original["expires_at"]
            and all(original["issued_at"] <= row["observed_at"]
                    and row["observed_at"] + original["clock_uncertainty_seconds"] < original["expires_at"]
                    for row in b_rows)
            and b[2]["error"] == "OCI SDK acceptance audience, facts or original window differs",
            "profile actual authenticated original/refusal differs")
    require(b[0]["before"]["dispatches"] == b[3]["after"]["dispatches"]
            and b[0]["before"]["active"] == b[3]["after"]["active"] == 0,
            "profile loader bracket contains provider dispatch or active ownership")
    return {"version": 1, "outcome": "same_source_origin_refused_before_sdk_in_loader_bracket",
        "requestSha256": original_sha, "artifactSha256": artifact_sha,
        "sourceDigest": original["issuer"]["source_digest"],
        "scope": "authenticated_physical_key_loader_interval_only"}


def check_profile_original_rows(original, rows, now):
    """Compare retained actual SQL rows to the emitted closed upload original."""
    require(set(rows) == {"upload", "chunk", "placement", "binding"},
            "profile actual SQL row projection differs")
    upload, chunk, placement, binding = (rows[name] for name in ("upload", "chunk", "placement", "binding"))
    admission = original["admission"]
    require(upload["id"] == admission["upload_id"]
            and upload["writer_id"] == upload["token_id"] and upload["token_id"]
            and upload["idempotency_key"].startswith("manifest-hybrid-" + admission["original_digest"] + "-")
            and upload["state"] == "active" and now < upload["expires_at"]
            and upload["expected_digest"] == chunk["digest"] == original["descriptor"]["digest"]
            and upload["expected_size"] == chunk["byte_size"] == admission["byte_size"]
                == original["descriptor"]["size"]
            and chunk["ordinal"] == 0 and chunk["upload_id"] == upload["id"]
            and chunk["staging_object_key"] == admission["staging_object_key"]
            and placement["prefix"] == admission["placement_prefix"]
            and original["key"] == placement["prefix"] + "/" + chunk["staging_object_key"]
            and placement["id"] == upload["staging_placement_id"]
            and placement["resource_version"] == upload["staging_placement_resource_version"]
            and placement["binding_id"] == binding["id"] == upload["staging_binding_id"]
            and binding["write_revision"] == upload["staging_binding_write_revision"],
            "profile actual SQL rows changed from the signed original")
    return {"version": 1, "uploadId": upload["id"], "originalDigest": admission["original_digest"],
            "scope": "current_sql_original_observation_not_actor_authorization"}



def _select_context_records(configuration, namespace, identity, groups, *, prepared,
                            worker_a, configuration_file, namespace_file, artifact_sha256, listener):
    """Select the shared Rust digest only from a complete actual accepted event."""
    selector = configuration["bindings"]["HUB_OCI_PROFILE_LOAD_OBSERVER"]
    if isinstance(selector, str):
        selector = json.loads(selector)
    require(set(selector) == {"version", "capture_id", "placement_prefix", "document_digest"}
            and selector["version"] == 1
            and selector["placement_prefix"] == prepared["coordinates"]["gcPrefix"],
            "profile initial observer selection differs")
    require(set(identity) == {"sourceDigest", "scriptVersion"}
            and namespace["observationScope"] == "oci_sdk_emulator_namespace_readback"
            and namespace["runnerPid"] == worker_a["pid"]
            and namespace["runnerStartTicks"] == worker_a["startTicks"]
            and namespace["buildDerivedSourceDigest"] == identity["sourceDigest"]
            and namespace["buildDerivedScriptVersion"] == identity["scriptVersion"],
            "profile actual Clock/namespace/process join differs")
    candidates = []
    for group in groups.values():
        try:
            events = _bracket(group, group[0]["request_sha256"], "accepted")
        except (ValueError, KeyError, TypeError, IndexError):
            continue
        entry, artifact = events[0]["original"], events[1]
        if (group[0]["capture_id"] == selector["capture_id"]
                and entry["document_digest"] == selector["document_digest"]
                and entry["key"].startswith(selector["placement_prefix"] + "/")
                and artifact["artifact_sha256"] == artifact_sha256
                and artifact["current_origin"] == artifact["artifact_origin"] == "https://localhost:4643"
                and artifact["source_digest"] == entry["source_digest"] == identity["sourceDigest"]
                and artifact["script_version"] == entry["script_version"] == identity["scriptVersion"]
                and artifact["profile_digest"] == entry["protected_profile_digest"]
                and re.fullmatch(r"[a-f0-9]{64}", artifact["profile_digest"])):
            candidates.append(artifact)
    require(candidates, "profile A has no matching complete accepted artifact event")
    artifact = candidates[-1]
    require(all(value["profile_digest"] == artifact["profile_digest"] for value in candidates),
            "profile A accepted artifacts disagree")
    observation = {"origin": artifact["current_origin"], "sourceDigest": identity["sourceDigest"],
        "scriptVersion": identity["scriptVersion"], "wasmSha256": namespace["wasmSha256"],
        "runnerSha256": namespace["runnerSha256"],
        "configurationSha256": namespace["configurationSha256"], "pid": worker_a["pid"]}
    return {"version": 1, "root": listener["root"] + "/lifecycle", "workerA": worker_a,
        "configurationAFile": configuration_file, "namespaceAFile": namespace_file,
        "artifactSha256": artifact_sha256, "observationA": observation,
        "selection": {**selector, "protected_profile_digest": artifact["profile_digest"],
            "source_digest": identity["sourceDigest"], "script_version": identity["scriptVersion"]}}


def select_profile_context(worker, *, tools, prepared, processes, namespace_file,
                           artifact_sha256, source_identity_file, listener):
    """Join private A files and actual loader records without reconstructing a digest.

    The identity file comes from the existing authenticated Clock verifier.
    This observation utility does not independently authenticate that verifier
    or authorize a provider operation. Its actual file hashes remain retained.
    """
    selected = guest(worker, tools, """
runner=selected['runner']; helper.process_identity(runner)
config_body=helper.private_file(selected['configurationFile'],helper.MAX_CONFIG)
namespace_body=helper.private_file(selected['namespaceFile'],32768)
identity_body=helper.private_file(selected['identityFile'],4096)
namespace=json.loads(namespace_body)
configuration=json.loads(config_body)
selector=configuration['bindings']['HUB_OCI_PROFILE_LOAD_OBSERVER']
if isinstance(selector,str): selector=json.loads(selector)
if hashlib.sha256(config_body).hexdigest()!=namespace['configurationSha256']:
    raise ValueError('profile actual namespace/configuration bytes differ')
helper.process_identity(runner)
print(json.dumps({'configuration':configuration,'namespace':namespace,
    'identity':json.loads(identity_body),'groups':helper.records(runner['logFile'],selector['capture_id'])}))
""", runner=processes["worker"], configurationFile=prepared["configurationFile"],
        namespaceFile=namespace_file, identityFile=source_identity_file)
    return _select_context_records(**selected, prepared=prepared, worker_a=processes["worker"],
        configuration_file=prepared["configurationFile"], namespace_file=namespace_file,
        artifact_sha256=artifact_sha256, listener=listener)


def run_profile_origin_mismatch(worker, *, tools, context, listener, listener_process,
                                root_mutation, check_original, observe_worker, transition, retain):
    """Call the one-shot original, actual A/B lifetimes and mandatory A restore.

    ``root_mutation`` is the ordinary producer's retained tag PUT. Its real HTTP
    deadline must be at most sixty seconds. ``check_original`` performs the
    selected read-only SQL join before stopping A; it returns retained rows, not
    an approval flag. ``observe_worker`` performs real TLS, protected Clock and
    independent namespace observations, returning their private file references.
    ``transition`` records actual process/log epochs for the whole-window
    collector. Its return value grants no authority and is never interpreted.
    """
    fields = {"version", "root", "workerA", "configurationAFile", "namespaceAFile",
              "artifactSha256", "observationA", "selection"}
    require(set(context) == fields and context["version"] == 1, "profile context is not closed")
    selected = context["selection"]
    require(set(selected) == {"version", "capture_id", "placement_prefix", "document_digest",
            "protected_profile_digest", "source_digest", "script_version"}, "profile selection is not closed")
    require(context["root"] == listener["root"] + "/lifecycle", "profile lifecycle root differs")
    capture_a = guest(worker, tools, """
Path(selected['root']).mkdir(mode=0o700,exist_ok=False)
capture=helper.capture_from_namespace(selected['root']+'/capture-A',selected['runner'],
    selected['namespaceFile'],selected['configurationFile'])
original=json.loads(helper.private_file(capture['configuration']['file'],helper.MAX_CONFIG))
candidate=helper.configuration_b(original)
configuration=helper.retained(Path(selected['root'])/'configuration-B.json',
    json.dumps(candidate,separators=(',',':')).encode())
print(json.dumps({'capture':capture,'configurationB':configuration,
    'records':helper.records(selected['runner']['logFile'],selected['captureId'])}))
""", root=context["root"], runner=context["workerA"], namespaceFile=context["namespaceAFile"],
        configurationFile=context["configurationAFile"], captureId=selected["capture_id"])
    a_rows = []
    for group in capture_a["records"].values():
        try:
            events = _bracket(group, group[0]["request_sha256"], "accepted")
            if events[1]["artifact_sha256"] == context["artifactSha256"]:
                a_rows = group
        except (ValueError, KeyError, TypeError):
            continue
    require(a_rows, "profile original A has no complete actual accepted loader bracket")
    control = lambda request: listener_control(worker, tools, listener, listener_process, request)
    require(control({"version": 1, "kind": "arm", "selection": selected})["state"] == "armed",
            "profile original hold did not arm")
    executor = ThreadPoolExecutor(max_workers=1)
    mutation = executor.submit(root_mutation)
    worker_b = capture_b = None
    auxiliary = {"version": 1, "scope": "separate_B_loader_negative_subwindow"}
    stopped_a = False
    attempted_b = False
    outcome = {"version": 1, "outcome": "unknown", "scope": "same_source_origin_loader_refusal"}
    restoration = None
    try:
        deadline = time.monotonic() + 20
        while True:
            status = control({"version": 1, "kind": "status"})
            if status["state"] == "held":
                break
            require(status["state"] == "armed" and not mutation.done() and time.monotonic() < deadline,
                    "profile genuine original rendezvous missing")
            time.sleep(0.2)
        original = guest(worker, tools, """
body=helper.private_file(selected['held']['originalFile'],16384)
if hashlib.sha256(body).hexdigest()!=selected['held']['requestSha256']:
    raise ValueError('profile held original bytes changed')
print(json.dumps(json.loads(body)))
""", held=status["original"])
        cutoff = original["expires_at"] - original["clock_uncertainty_seconds"]
        require(time.time() < cutoff, "profile actual original already expired")
        sql = check_original(original, status["original"])
        require(isinstance(sql, dict) and set(sql) == {"file", "sha256", "rows"}
                and re.fullmatch(r"[a-f0-9]{64}", sql["sha256"]), "profile actual SQL rows absent")
        check_profile_original_rows(original, sql["rows"], time.time())
        retain("profile-original-sql.json", sql)
        transition("before-A-stop", {"process": context["workerA"], "capture": capture_a["capture"]})
        stopped = guest(worker, tools, "print(json.dumps(helper.stop_runner(selected['capture'],selected['deadline'])))",
            capture=capture_a["capture"], deadline=cutoff)
        stopped_a = True
        retain("profile-A-stop.json", stopped)
        auxiliary["AExit"] = stopped
        attempted_b = True
        worker_b = guest(worker, tools, "print(json.dumps(helper.launch_runner(selected['capture'],selected['root'],selected['configurationFile'],'B')))",
            capture=capture_a["capture"], root=context["root"], configurationFile=capture_a["configurationB"]["file"])
        retain("profile-B-start.json", worker_b)
        auxiliary["BProcess"] = worker_b
        transition("B-started", {"process": worker_b})
        observed_b = observe_worker(worker_b, "https://localhost:4648", capture_a["configurationB"]["file"])
        capture_b = guest(worker, tools, "print(json.dumps(helper.capture_from_namespace(selected['root']+'/capture-B',selected['runner'],selected['namespaceFile'],selected['configurationFile'])))",
            root=context["root"], runner=worker_b, namespaceFile=observed_b["namespaceFile"],
            configurationFile=capture_a["configurationB"]["file"])
        auxiliary["BCapture"] = capture_b
        auxiliary["BObservation"] = observed_b
        auxiliary["original"] = status["original"]
        require(time.time() < cutoff, "profile actual B readiness missed original cutoff")
        released = control({"version": 1, "kind": "release",
            "requestSha256": status["original"]["requestSha256"], "nonce": original["nonce"]})
        require(released["state"] == "released", "profile exact original release refused")
        deadline = min(time.monotonic() + 30, time.monotonic() + max(0, cutoff - time.time()))
        while True:
            current = control({"version": 1, "kind": "status"})
            if current["state"] == "terminal":
                break
            require(current["state"] == "released" and time.monotonic() < deadline,
                    "profile actual response terminal missing")
            time.sleep(0.2)
        auxiliary["response"] = current["response"]
        require(current["response"]["status"] == 409 and current["response"]["selected"] is True,
                "profile actual Worker response is not the loader refusal")
        groups = guest(worker, tools, "print(json.dumps(helper.records(selected['file'],selected['captureId'])))",
            file=worker_b["logFile"], captureId=selected["capture_id"])
        rows = groups.get(status["original"]["requestSha256"], [])
        outcome = assess_profile_origin_mismatch(original, status["original"]["requestSha256"],
            context["artifactSha256"], a_rows, rows, {"a": context["observationA"], "b": observed_b["observation"]})
        retain("profile-actual-loader.json", {"original": status["original"], "a": a_rows, "b": rows,
            "observations": {"a":context["observationA"],"b":observed_b}})
    except Exception as error:
        outcome = {"version": 1, "outcome": "unknown", "reason": type(error).__name__,
            "scope": "same_source_origin_loader_refusal"}
        retain("profile-unknown.json", outcome)
    finally:
        # The real normal producer must terminate before A resumes. Cancelling a
        # Python Future would not establish that its HTTP/Worker original ended.
        producer_terminal = False
        try:
            mutation.result(timeout=65)
            producer_terminal = True
            outcome = {"version": 1, "outcome": "unknown", "reason": "producer_reported_success_after_refusal"}
        except Exception as error:
            producer_terminal = mutation.done()
            retain("profile-producer-terminal.json", {"version": 1, "exceptionType": type(error).__name__})
        executor.shutdown(wait=False)
        if worker_b:
            if capture_b is None:
                capture_b = guest(worker, tools, """
child=helper.workerd_child(selected['runner'],selected['expected'])
print(json.dumps({'version':1,'runner':selected['runner'],'workerd':child}))
""", runner=worker_b, expected=capture_a["capture"]["workerd"]["executableSha256"])
            transition("before-B-stop", {"process": worker_b, "capture": capture_b})
            stopped = guest(worker, tools, "print(json.dumps(helper.stop_runner(selected['capture'],time.time()+10)))",
                capture=capture_b)
            retain("profile-B-stop.json", stopped)
            auxiliary["BExit"] = stopped
        require(not attempted_b or worker_b is not None,
                "profile B spawn acknowledgement unknown; A restoration withheld")
        require(producer_terminal, "profile ordinary producer remains pending; A restoration withheld")
        if stopped_a:
            # A can return only after the actual B runner and workerd exit. The
            # launch helper also rechecks byte-exact A config/env/argv custody.
            restoration = guest(worker, tools, "print(json.dumps(helper.launch_runner(selected['capture'],selected['root'],selected['configurationFile'],'A-restored')))",
                capture=capture_a["capture"], root=context["root"], configurationFile=context["configurationAFile"])
            restored = observe_worker(restoration, "https://localhost:4643", context["configurationAFile"])
            transition("A-restored", {"process": restoration, "observations": restored})
            retain("profile-A-restored.json", {"process": restoration, "observations": restored})
    if not stopped_a:
        guest(worker, tools, "helper.process_identity(selected['runner']);print(json.dumps(selected['runner']))", runner=context["workerA"])
        restoration = context["workerA"]
    require(restoration is not None, "profile actual A restoration absent")
    retain("profile-B-negative-subwindow.json", auxiliary)
    return {**outcome, "restoredWorker": restoration, "auxiliaryWindow": auxiliary}
