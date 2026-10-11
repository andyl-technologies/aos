"""Call the Managed inventory, review, root-race and deletion workflow.

The normal fleet controller includes this module beside its pair, transport and
private runner helpers. Captured StorageWork originals require the selected
current compiled codec before becoming join inputs. Missing SDK brackets,
current SQL observations, codec receipts or stored positives stop the workflow.
Nothing here installs provider authority or substitutes OCI purpose for Delete.
"""

import hashlib
import json
from pathlib import Path
import re
import time


def managed_gc_require(condition, message):
    if not condition:
        raise ValueError(message)


def managed_gc_label(value):
    managed_gc_require(isinstance(value, str) and re.fullmatch(r"[a-z0-9-]{1,128}", value),
                       "Managed GC private observation label differs")
    return value


def require_managed_gc_current_tuple(prepared, processes, tools, boundaries):
    """Check the supplied current selection before creating additional inputs."""
    selected, coordinates = prepared["captureSelection"], prepared["coordinates"]
    provenance, codec = boundaries["codecProvenance"], boundaries["codecSelection"]
    managed_gc_require(set(processes) == {"native", "worker", "nativeProxy", "workerProxy"}
                       and selected["run"] == coordinates["runId"] == boundaries["run"]
                       and tools["deploymentId"] == coordinates["deploymentId"]
                       and type(provenance["version"]) is int and provenance["version"] == 1
                       and selected["sourceDigest"] == provenance["workerSourceDigest"]
                       and provenance["nativeExecutableSha256"]
                           == processes["native"]["executableSha256"]
                       and codec["runtimeCodecRevision"] == provenance["runtimeCodecRevision"]
                       and re.fullmatch(r"[0-9a-f]{40}", provenance["runtimeCodecRevision"])
                       and all(re.fullmatch(r"[0-9a-f]{64}", provenance[field]) for field in (
                           "nativeExecutableSha256", "workerSourceDigest",
                           "sourceArchiveSha256", "codecSourceSha256"))
                       and all(reference["path"].startswith("/")
                               and re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])
                               for reference in (codec["observerExecutable"], codec["runtimeProvenance"])),
                       "Managed reviewed codec selection does not match its original process/source tuple")


def capture_managed_gc_sql(native, tools, prepared, query, label):
    """Retain the actual bounded SELECT output on the selected Native guest."""
    managed_gc_label(label)
    managed_gc_require(query.startswith("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;")
                       and len(query.encode()) <= 32 * 1024,
                       "Managed GC SQL requires the confined read-only builder")
    coordinates = prepared["coordinates"]
    root = coordinates["nativeRoot"] + "/gc-observations/" + label
    selected = {"query": query, "root": root,
                "databaseUrlFile": prepared["nativeFiles"]["database"],
                "psql": tools["postgres"] + "/psql", "database": coordinates["database"]}
    managed_gc_require(selected["psql"].startswith("/nix/store/")
                       and selected["databaseUrlFile"].startswith(coordinates["nativeRoot"] + "/"),
                       "Managed SQL tool or database file escaped the original pair")
    observed = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, stat, subprocess, urllib.parse
        from pathlib import Path

        os.umask(0o077)
        root = Path(selected['root'])
        root.parent.mkdir(mode=0o700, exist_ok=True)
        root.mkdir(mode=0o700, exist_ok=False)
        database = Path(selected['databaseUrlFile'])
        metadata = database.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077 or metadata.st_size > 4096):
            raise ValueError('Managed database URL file lost private custody')
        database_url = database.read_text().strip()
        parsed = urllib.parse.urlsplit(database_url)
        if (parsed.scheme != 'postgresql' or parsed.password is not None
                or set(urllib.parse.parse_qs(parsed.query)) - {'host'}):
            raise ValueError('Fresh Managed database URL must not carry credential material')
        environment = dict(os.environ)
        path = root/'rows.private.json'
        descriptor = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            # libpq does not expand a URL coming from the PGDATABASE default.
            # The fresh pair has no password; keep its URL out of public output.
            process = subprocess.run([selected['psql'], '-X', '-qAt', '-d', database_url,
                '-v', 'ON_ERROR_STOP=1',
                '-c', selected['query']], stdout=output, stderr=subprocess.PIPE,
                env=environment, timeout=25, check=False)
            output.flush()
            os.fsync(output.fileno())
        errors = root/'stderr.private'
        descriptor = os.open(errors, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(process.stderr)
            output.flush()
            os.fsync(output.fileno())
        if process.returncode or not 0 < path.stat().st_size <= 512*1024:
            raise ValueError('Actual Managed read-only SQL observation failed or exceeded bound')
        body = path.read_bytes()
        rows = body.splitlines()
        if len(rows) != 1:
            raise ValueError('Actual Managed SQL projection is not one retained JSON result')
        projected = json.loads(rows[0])
        if (set(projected) != {'database','value'}
                or projected['database'] != selected['database']):
            raise ValueError('Managed SQL response belongs to a different actual database')
        print(json.dumps({'value':projected['value'], 'receipt':{
            'version':1, 'path':str(path), 'sha256':hashlib.sha256(body).hexdigest(),
            'byteSize':len(body), 'querySha256':hashlib.sha256(selected['query'].encode()).hexdigest(),
            'database':projected['database'],
            'stderrSha256':hashlib.sha256(process.stderr).hexdigest(), 'exitCode':process.returncode}}))
    """, selected, timeout=35))
    receipt = observed["receipt"]
    managed_gc_require(receipt["path"] == root + "/rows.private.json"
                       and receipt["exitCode"] == 0 and 0 < receipt["byteSize"] <= 512 * 1024
                       and receipt["database"] == coordinates["database"]
                       and receipt["querySha256"] == hashlib.sha256(query.encode()).hexdigest(),
                       "Actual Managed SQL receipt differs from the offered read-only query")
    retain_direct_flow(label + "-sql.json", observed)
    return observed["value"]


def managed_gc_sdk_records(text):
    """Parse actual scoped private console records without manufacturing an entry."""
    managed_gc_require(isinstance(text, str) and len(text.encode()) <= 8 * 1024 * 1024,
                       "Managed private Worker log window is missing or oversized")
    records = []
    marker = "managed_gc_sdk_observer "
    for line in text.splitlines():
        if marker in line:
            records.append(json.loads(line.split(marker, 1)[1]))
    managed_gc_require(len(records) <= 4096, "Managed SDK record window exceeded bound")
    return records


def managed_gc_expected_requests(exchanges, replay_claims=()):
    """Project selectors from exact decoded captures and actually stored replay claims."""
    expected = set()
    for exchange in exchanges:
        plan = exchange["plan"]
        operation = plan["operation"]
        if plan["binding_kind"] != "deployment_r2":
            raise ValueError("Managed window captured another binding kind")
        key = plan["placement_prefix"] + "/" + operation["path"] if "path" in operation else None
        if operation["kind"] == "hash_oci_range":
            expected.add(("managed_inventory_range", key, plan["plan_id"]))
        elif operation["kind"] == "delete_if_matches":
            expected.add(("managed_gc_guard", key, operation["claim_id"]))
    for key, claim in replay_claims:
        expected.add(("managed_gc_guard", key, claim["claim_id"]))
    managed_gc_require(0 < len(expected) <= 64,
                       "Managed scoped request selectors are missing or exceed the bound")
    return [{"scope": scope, "key": key, "subject_id": subject}
            for scope, key, subject in sorted(expected)]


def validated_managed_storage_exchanges(window, prepared, tools, boundaries, label):
    """Require complete actual capture coverage and current compiled body validation.

    Non-execute controls retain their original body and authenticated handler
    references. They cannot become StorageWork evidence through this adapter.
    Structural decoding does not replace the later current action SQL join.
    """
    managed_gc_label(label)
    managed_gc_require(type(window.get("version")) is int and window["version"] == 1
                       and window.get("nativeBulkBytes") is None,
                       "Managed transport window differs or supplies an inferred byte total")
    boundary = window["storageBoundary"]
    pins = boundary["captureProvenance"]
    selected = prepared["captureSelection"]
    provenance = boundaries["codecProvenance"]
    codec = boundaries["codecSelection"]
    managed_gc_require(pins["run"] == selected["run"] == prepared["coordinates"]["runId"]
                       and pins["sourceDigest"] == selected["sourceDigest"]
                       == provenance["workerSourceDigest"]
                       and pins["deploymentId"] == tools["deploymentId"]
                       and pins["nativeExecutableSha256"] == provenance["nativeExecutableSha256"],
                       "Managed capture source, deployment or executable differs from the current tuple")
    captures = boundary["captures"]
    completions = boundary["authenticatedCompletions"]
    count = boundary["actualNativeRequests"]
    managed_gc_require(type(count) is int and 0 <= count <= 4096
                       and isinstance(captures, list) and isinstance(completions, list)
                       and len(captures) == len(completions) == count
                       and type(boundary["capturedWorkerRequests"]) is int
                       and boundary["capturedWorkerRequests"] == count
                       and not boundary["unresolvedNativeRequestIds"]
                       and not boundary["receivedWithoutOriginal"],
                       "Managed actual Native transport window is incomplete or exceeds its bound")
    captured_ids = [capture["requestId"] for capture in captures]
    completed_ids = [completion["requestId"] for completion in completions]
    native_ids = [completion["nativeRequestId"] for completion in completions]
    managed_gc_require(all(re.fullmatch(r"[0-9a-f]{32}", value)
                           for value in captured_ids + completed_ids + native_ids)
                       and len(set(captured_ids)) == len(set(completed_ids)) == len(set(native_ids)) == count
                       and set(captured_ids) == set(completed_ids),
                       "Managed actual handler or transport identity is absent or ambiguous")
    by_id = {completion["requestId"]: completion for completion in completions}

    exchanges = []
    captured_bytes = 0
    for capture in captures:
        completion = by_id[capture["requestId"]]
        request, reply = capture["bodies"]["request"], capture["bodies"]["response"]
        managed_gc_require((completion["requestSha256"], completion["replySha256"],
                            completion["requestBytes"], completion["replyBytes"]) == (
                                request["sha256"], reply["sha256"],
                                int(request["byteSize"]), int(reply["byteSize"])),
                           "Managed handler completion differs from the captured body originals")
        sizes = (request["byteSize"], reply["byteSize"])
        managed_gc_require(all(type(size) is int and 0 <= size <= 8 * 1024 * 1024 for size in sizes),
                           "Managed captured body count is invalid or exceeds the selected bound")
        captured_bytes += sum(sizes)
        managed_gc_require(captured_bytes <= 16 * 1024 * 1024,
                           "Managed scoped metadata capture window exceeded its aggregate bound")
        if capture["procedure"] != "/_internal/storage/v1/execute":
            control = capture["controlSelection"]
            original = control["originalRequest"]
            managed_gc_require("storageWorkSelection" not in capture
                               and control["sourceDigest"] == pins["sourceDigest"]
                               and control["deploymentId"] == pins["deploymentId"]
                               and completion["compiledSource"] == pins["sourceDigest"]
                               and completion["route"] == capture["procedure"]
                               and (original["sha256"], int(original["byteSize"])) == (
                                   request["sha256"], int(request["byteSize"])),
                               "Managed non-execute control lacks its exact original/source join")
            continue

        decoded = classify_managed_storage_capture(capture, boundary, label, codec, provenance)
        receipt, plan = decoded["validationReceipt"], decoded["plan"]
        managed_gc_require(type(decoded["version"]) is int and decoded["version"] == 1
                           and decoded["nativeBulkBytes"] is None
                           and decoded["handlerCompletion"] == completion
                           and type(receipt["exitCode"]) is int
                           and receipt["exitCode"] == 0
                           and receipt["sourceDigest"] == pins["sourceDigest"]
                           and receipt["codecRevision"] == provenance["runtimeCodecRevision"]
                           and receipt["codecSourceSha256"] == provenance["codecSourceSha256"]
                           and receipt["executableSha256"] == codec["observerExecutable"]["sha256"]
                           and receipt["provenanceSha256"] == codec["runtimeProvenance"]["sha256"]
                           and (receipt["requestSha256"], receipt["replySha256"],
                                receipt["requestBytes"], receipt["replyBytes"]) == (
                                    request["sha256"], reply["sha256"],
                                    str(request["byteSize"]), str(reply["byteSize"])),
                           "Managed current codec receipt differs from the actual selected exchange")
        managed_gc_require(plan["deployment_id"] == pins["deploymentId"]
                           and plan["binding_kind"] == "deployment_r2"
                           and plan["placement_prefix"] == prepared["coordinates"]["gcPrefix"]
                           and plan["operation"]["kind"] == completion["wireOperation"]
                           and hashlib.sha256(plan["plan_id"].encode()).hexdigest()
                               == completion["planIdSha256"],
                           "Managed decoded plan escaped the selected placement or actual handler")
        exchanges.append(decoded)
    return exchanges


class ManagedGcWindowObserver:
    """Bind existing private socket observations to actual captured request windows."""

    def __init__(self, native, worker, tools, prepared, processes, boundaries, collector):
        self.native, self.worker, self.tools = native, worker, tools
        self.prepared, self.processes, self.boundaries = prepared, processes, boundaries
        self.collector = collector
        self.sequence = 0
        self.backing_identity = None
        self.exchanges = []
        self.windows = []
        self.replay_claims = []

    def label(self, kind):
        self.sequence += 1
        managed_gc_require(self.sequence <= 4096, "Managed observation count exceeded bound")
        return "managed-gc-" + kind + "-" + str(self.sequence)

    def snapshot(self, keys, claim_ids):
        observed = read_managed_runner_command(self.worker, self.tools, self.prepared,
            self.processes, {"version": 1, "kind": "managed-gc-snapshot",
                             "keys": keys, "claimIds": claim_ids}, self.label("snapshot"))
        value = observed["value"]
        if self.backing_identity is None:
            self.backing_identity = value["backingIdentity"]
        managed_gc_require(value["backingIdentity"] == self.backing_identity,
                           "Managed snapshot changed its retained backing identity")
        retain_direct_flow(self.label("snapshot-receipt") + ".json", observed)
        return value

    def begin(self):
        self.replay_claims = []
        return begin_managed_storage_window(self.native, self.worker, self.tools, self.prepared,
            self.processes, self.boundaries, self.label("begin"))

    begin_transport = begin

    def finish_transport(self, token):
        managed_gc_require(isinstance(token, dict) and isinstance(token.get("label"), str),
                           "Managed window is missing its original begin label")
        window = finish_managed_storage_window(self.native, self.worker, self.tools, self.prepared,
            self.processes, self.boundaries, token, token["label"])
        exchanges = validated_managed_storage_exchanges(window, self.prepared, self.tools,
                                                         self.boundaries, self.label("codec"))
        managed_gc_require(len(self.exchanges) + len(exchanges) <= 4096 and len(self.windows) < 32,
                           "Managed retained workflow windows or exchanges exceeded their bound")
        window = {**window, "validatedExchanges": exchanges}
        self.exchanges.extend(exchanges)
        self.windows.append(window)
        return {"coverage": "complete_native_storage_requests", "requests": [
            {"operation": exchange["plan"]["operation"]["kind"],
             "key": (exchange["plan"]["placement_prefix"] + "/"
                     + exchange["plan"]["operation"]["path"])
                    if "path" in exchange["plan"]["operation"] else None,
             "planId": exchange["plan"]["plan_id"]} for exchange in exchanges],
            "captureReferences": window["storageBoundary"]["captures"]}

    def finish(self, token):
        self.finish_transport(token)
        window = self.windows[-1]
        managed_gc_require(self.backing_identity is not None,
                           "Managed SDK window has no actual prior R2 snapshot identity")
        # Only the current window supplies selectors; old successes cannot fill
        # missing entries after a restart, failed capture or unknown reply.
        exchanges = window["validatedExchanges"]
        expected = managed_gc_expected_requests(exchanges, self.replay_claims)
        result = self.collector.collect(managed_gc_sdk_records(window["workerLogText"]),
            self.prepared["coordinates"]["runId"], self.backing_identity, expected)
        retain_direct_flow(self.label("sdk") + ".json", {"window": window, "scopedSdk": result})
        return result

    def replay_positive_guard(self, key, receipt):
        claim = receipt["claim"]
        managed_gc_require(receipt["outcome"]["kind"] == "deleted",
                           "Managed physical replay requires an actual retained Deleted receipt")
        digest = hashlib.sha256(json.dumps(receipt, separators=(",", ":"),
                                           ensure_ascii=False).encode()).hexdigest()
        observed = read_managed_runner_command(self.worker, self.tools, self.prepared,
            self.processes, {"version": 1, "kind": "managed-gc-positive-replay", "key": key,
                             "claimId": claim["claim_id"], "receiptSha256": digest},
            self.label("replay"))
        self.replay_claims.append((key, claim))
        retain_direct_flow(self.label("replay-receipt") + ".json", observed)
        return observed["value"]


def await_managed_gc_inventory(native, tools, prepared, setup, sql, gc, observer, original_pins):
    """Wait for normal bounded maintenance; never mark inventory or capability valid."""
    deadline = time.monotonic() + 300
    while True:
        projected = capture_managed_gc_sql(native, tools, prepared,
            sql.current_projection_sql(gc, setup, prepared["coordinates"], original_pins),
            observer.label("inventory"))
        sql.exact_current_projection({"pins": projected["pins"]}, gc, original_pins)
        if projected["inventory"] and projected["capability"]:
            current = sql.exact_current_projection(projected, gc, original_pins)
            return projected, current
        managed_gc_require(time.monotonic() < deadline,
                           "Actual Managed inventory or independent Delete probe did not become current")
        time.sleep(2)


def await_managed_gc_delete_capability(native, tools, prepared, setup, sql, gc, observer, pins):
    """Retain the actual initial probe without classifying it as GC business work."""
    deadline = time.monotonic() + 300
    while True:
        projected = capture_managed_gc_sql(native, tools, prepared,
            sql.capability_projection_sql(gc, setup, prepared["coordinates"], pins),
            observer.label("capability"))
        sql.exact_current_projection({"pins": projected["pins"]}, gc, pins)
        if projected["capability"]:
            return projected, sql.exact_managed_capability(projected, gc, pins)
        managed_gc_require(time.monotonic() < deadline,
                           "Independent Managed Delete probe did not establish its current SQL capability")
        time.sleep(2)


def run_managed_gc_window(native, worker, client, database_machine, tools, prepared,
                          processes, boundaries, controls, setup, container_source,
                          publication, producer_coordinates, refresh_token):
    """Execute genuine root-change refusal, positive GC and both replay paths."""
    managed_gc_require(isinstance(boundaries.get("codecSelection"), dict)
                       and boundaries["codecSelection"]
                       and isinstance(boundaries.get("codecProvenance"), dict)
                       and boundaries["codecProvenance"],
                       "Managed GC requires the reviewed current codec tuple before new inputs")
    require_managed_gc_current_tuple(prepared, processes, tools, boundaries)
    gc = managed_fixture_module(tools["managedGcHelper"], "managed_gc_window_helper")
    sql = managed_fixture_module(tools["managedGcSql"], "managed_gc_window_sql")
    collector = managed_fixture_module(tools["managedGcCollector"], "managed_gc_window_collector")
    producer = managed_fixture_module(tools["managedContainerProducer"], "managed_gc_window_producer")
    managed_gc_require(publication["containerPublication"]["verification"] == "verified"
                       and publication["signedSource"]["sourceCommit"],
                       "Managed GC lacks its actual completed signed container publication")
    registry = {"registrySlug": setup["registry"]["slug"]}
    observer = ManagedGcWindowObserver(native, worker, tools, prepared, processes, boundaries, collector)
    pins = sql.exact_current_projection(capture_managed_gc_sql(native, tools, prepared,
        sql.current_projection_sql(gc, setup, prepared["coordinates"]), observer.label("pins")), gc)
    # The independent reserved-key capability probe has its own PutProbe and
    # DeleteProbe operations. Complete it before the inventory/GC codec window;
    # its real SQL row remains a prerequisite, never an invented admission.
    capability, pins = await_managed_gc_delete_capability(native, tools, prepared, setup,
                                                          sql, gc, observer, pins)
    policy = gc.set_fixture_retention(controls, registry, observer.label("retention"))

    token = observer.begin()
    candidate = producer.prepare_unrooted_root(client, tools, producer_coordinates,
        setup["registry"], container_source, refresh_token)
    initial, current = await_managed_gc_inventory(native, tools, prepared, setup,
                                                  sql, gc, observer, pins)
    # Snapshot addresses are selected from the actual completed inventory below;
    # the request supplies explicit reviewed action IDs once planning returns.
    rooted = [container_source["finalized"]["index_digest"]]
    rejected, rejected_actions = gc.review_managed_gc(controls, registry, policy["resourceVersion"],
        [candidate["digest"]], rooted, observer.label("root-review"))
    before_root = observer.snapshot([action["placementPrefix"] + "/" + action["objectKey"]
        for action in rejected_actions], [action["actionId"] for action in rejected_actions])
    inventory_window = observer.finish(token)
    gc.refuse_root_change(controls, rejected, rejected_actions,
        lambda: producer.root_candidate(client, tools, producer_coordinates,
            setup["registry"], candidate, refresh_token), observer, retain_direct_flow,
        observer.label("root-refusal"))

    token = observer.begin()
    positive = producer.upload_managed_unrooted_blob(client, tools, producer_coordinates,
                                                    setup["registry"], refresh_token)
    refreshed, current = await_managed_gc_inventory(native, tools, prepared, setup,
                                                    sql, gc, observer, current)
    planned, actions = gc.review_managed_gc(controls, registry, policy["resourceVersion"],
        [positive["digest"]], rooted + [candidate["digest"]], observer.label("positive-review"))
    observer.snapshot([action["placementPrefix"] + "/" + action["objectKey"] for action in actions],
                      [action["actionId"] for action in actions])
    positive_inventory_window = observer.finish(token)

    def read_evidence(run_id):
        rows = capture_managed_gc_sql(native, tools, prepared,
            sql.action_projection_sql(gc, run_id, prepared["coordinates"]["database"]),
            observer.label("actions"))
        managed_gc_require(isinstance(rows, list) and 0 < len(rows) <= 32,
                           "Managed SQL actions are missing or exceed selected bound")
        selected = []
        for row in rows:
            matches = [exchange for exchange in observer.exchanges
                if exchange["plan"]["operation"]["kind"] == "delete_if_matches"
                and exchange["plan"]["operation"]["claim_id"] == row["id"]]
            managed_gc_require(len(matches) == 1, "Managed action has no unique actual typed exchange")
            selected.append({"action": row, **matches[0]})
        return selected

    completed = gc.run_managed_gc(controls, registry, planned, actions, observer,
                                  read_evidence, retain_direct_flow, observer.label("positive"))
    return {"registry": setup["registry"], "pins": pins, "retention": policy,
            "initialDeleteCapability": capability,
            "unrootedIndex": candidate, "rootChangedReview": rejected,
            "initialInventory": initial, "inventorySdk": inventory_window,
            "initialProviderSnapshot": before_root, "positiveBlob": positive,
            "positiveInventory": refreshed, "positiveInventorySdk": positive_inventory_window,
            "completed": completed, "transportWindows": observer.windows,
            "scope": "actual selected Managed emulator joins; no Hosted provider qualification"}
