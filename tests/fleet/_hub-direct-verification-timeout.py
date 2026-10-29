"""Run the first real verification read through the confined response hold.

The complete publisher window includes its normal writes. The failed read is
selected afterwards from the actual internal Worker projection, Native SQL and
the independently retained provider response. There is no Native Stage MAC in
this queue path, and a local socket close never establishes remote drain.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit


VERIFICATION_MARKER = "direct_verification_fault_observation "
VERIFICATION_SELECTOR = "external_object::stage::tests::observation::actual_verification_hold_observation"


def verification_observer_records(text):
    """Retain exact emitted JSON suffixes for the shared typed consumer."""
    records = []
    for line in text.splitlines():
        position = line.find(VERIFICATION_MARKER)
        if position < 0:
            continue
        if line.find(VERIFICATION_MARKER, position + len(VERIFICATION_MARKER)) >= 0:
            raise ValueError("Verification observer marker repeats in one record")
        body = line[position + len(VERIFICATION_MARKER):].encode()
        if not 0 < len(body) <= 65536 or len(records) >= 32:
            raise ValueError("Verification observer record budget exceeded")
        # Decoding is only an early syntax check. Canonical private production
        # types and same-journal closure validation belong to the Rust consumer.
        json.loads(body)
        records.append(body)
    if not records:
        raise ValueError("Actual verification observer records are absent")
    return records


def consume_verification_records(worker, tools, text, label):
    """Execute the same-source private Worker consumer on exact captured bytes."""
    if label not in {"held", "terminal"}:
        raise ValueError("Verification consumer label differs")
    records = verification_observer_records(text)
    root = "/var/lib/hybrid-worker/verification-timeout/" + label
    references = []
    for sequence, body in enumerate(records):
        reference = install_direct_guest_file(worker, tools["python"],
            root + "/record-%02d.json" % sequence, body)
        references.append({"path": reference["file"], "sha256": reference["sha256"],
            "byteSize": str(reference["byteSize"])})
    selected = {"version": 1, "records": references, "output": root + "/projection.json"}
    input_file = root + "/input.json"
    install_direct_guest_file(worker, tools["python"], input_file,
        json.dumps(selected, separators=(",", ":")).encode())
    result = json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        root=Path(selected['root'])
        provenance=json.loads(Path(selected['provenance']).read_bytes())
        executable=Path(selected['helper'])
        body=executable.read_bytes()
        if (set(provenance)!={'version','commonSourceStorePath','workerFilteredSourceStorePath',
                'testExecutableSha256','testExecutableBytes'} or provenance['version']!=1
                or provenance['commonSourceStorePath']!=selected['commonSource']
                or provenance['workerFilteredSourceStorePath']!=selected['workerSource']
                or provenance['testExecutableSha256']!=hashlib.sha256(body).hexdigest()
                or provenance['testExecutableBytes']!=str(len(body))
                or not 0<len(body)<=512*1024*1024):
            raise ValueError('Verification consumer differs from the selected final source/ELF')
        environment=dict(os.environ)
        environment['AOS_PROVIDER_HOLD_STAGE_OBSERVATION_INPUT']=selected['input']
        with (root/'stdout.private').open('xb') as stdout, (root/'stderr.private').open('xb') as stderr:
            process=subprocess.run([str(executable),selected['selector'],'--exact','--ignored','--nocapture'],
                env=environment,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=10,check=False)
            stdout.flush(); os.fsync(stdout.fileno()); stderr.flush(); os.fsync(stderr.fileno())
        if process.returncode:
            raise ValueError('Typed verification observation consumer refused; raw records retained')
        path=root/'projection.json'; encoded=path.read_bytes()
        if not 0<len(encoded)<=2*1024*1024:
            raise ValueError('Typed verification projection exceeds its bound')
        print(json.dumps({'value':json.loads(encoded),'receipt':{'file':str(path),
            'sha256':hashlib.sha256(encoded).hexdigest(),'byteSize':str(len(encoded)),
            'executableSha256':provenance['testExecutableSha256']}}))
    """, {"root": root, "input": input_file, "selector": VERIFICATION_SELECTOR,
        "helper": tools["verificationObservationHelper"],
        "provenance": tools["verificationObservationHelperProvenance"],
        "commonSource": tools["commonSourceStorePath"], "workerSource": tools["workerSourcePath"]}, timeout=15))
    retain_direct_flow("verification-timeout-" + label + "-typed.json", result)
    return result


def verification_sql_query(projection):
    """Select the actual admitted session, frozen Complete and current pins."""
    job = projection["job"]
    admission, complete = job["admission"], job["complete"]
    session, operation = admission["sessionId"], complete["operationId"]
    if any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value)
           for value in (session, operation)):
        raise ValueError("Verification SQL original identity differs")
    placement_id = str(job["placementId"])
    if not re.fullmatch(r"[1-9][0-9]{0,18}", placement_id):
        raise ValueError("Verification SQL placement identity differs")
    return f"""
        BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
        SET LOCAL statement_timeout = '5s'; SET LOCAL lock_timeout = '2s';
        SELECT json_build_object('observedUnixMillis', floor(extract(epoch FROM clock_timestamp())*1000)::bigint,
            'database', current_database(), 'session', row_to_json(session),
            'complete', row_to_json(complete), 'frozen', row_to_json(frozen),
            'placement', row_to_json(placement), 'binding', row_to_json(binding),
            'publication', row_to_json(publication), 'registry', row_to_json(registry), 'completionReceipts',
            (SELECT count(*) FROM direct_upload_completion_receipts receipt
             WHERE receipt.session_id=session.session_id AND receipt.deployment_id=session.deployment_id))::text
        FROM direct_upload_sessions session
        JOIN direct_upload_completion_intents complete ON complete.session_id=session.session_id
            AND complete.deployment_id=session.deployment_id
        JOIN direct_upload_session_placements frozen ON frozen.session_id=session.session_id
            AND frozen.deployment_id=session.deployment_id AND frozen.placement_id={placement_id}
        JOIN surface_placements placement ON placement.id=frozen.placement_id
        JOIN (SELECT binding.id, binding.resource_version, writer.current_write_revision
              FROM bindings binding JOIN binding_write_state writer ON writer.binding_id=binding.id)
            binding ON binding.id=frozen.binding_id
        JOIN registry_publications publication ON publication.publication_id=session.publication_id
        JOIN registries registry ON registry.id=publication.registry_id
        WHERE session.session_id='{session}' AND complete.operation_id='{operation}';
        COMMIT;
    """


def capture_verification_sql(native, tools, projection, label):
    """Retain one actual read-only Native snapshot without changing admission."""
    if label not in {"held", "terminal"}:
        raise ValueError("Verification SQL label differs")
    query = verification_sql_query(projection)
    root = "/var/lib/hybrid-native-observations/verification-timeout/" + label
    result = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        os.umask(0o077)
        root=Path(selected['root']); root.mkdir(mode=0o700,parents=True,exist_ok=False)
        url=Path(selected['url']).read_text().strip()
        with (root/'rows.private.jsonl').open('xb') as output, (root/'stderr.private').open('xb') as stderr:
            process=subprocess.run([selected['psql'],'-X','-qAt','-d',url,'-v','ON_ERROR_STOP=1',
                '-c',selected['query']],stdin=subprocess.DEVNULL,stdout=output,stderr=stderr,timeout=8,check=False)
            output.flush(); os.fsync(output.fileno()); stderr.flush(); os.fsync(stderr.fileno())
        path=root/'rows.private.jsonl'; encoded=path.read_bytes()
        if process.returncode or not 0<len(encoded)<=512*1024 or len(encoded.splitlines())!=1:
            raise ValueError('Actual verification SQL snapshot failed or is ambiguous; evidence retained')
        print(json.dumps({'value':json.loads(encoded),'receipt':{'file':str(path),
            'sha256':hashlib.sha256(encoded).hexdigest(),'byteSize':str(len(encoded)),
            'querySha256':hashlib.sha256(selected['query'].encode()).hexdigest()}}))
    """, {"root": root, "query": query, "url": tools["nativeDatabaseUrlFile"],
        "psql": tools["postgres"] + "/psql"}, timeout=12))
    retain_direct_flow("verification-timeout-" + label + "-sql.json", result)
    return result


def check_verification_sql(row, projection, *, require_live):
    """Compare real Native originals and current pins to the typed Worker job."""
    job = projection["job"]
    admission, complete = job["admission"], job["complete"]
    session, intent, frozen = row["session"], row["complete"], row["frozen"]
    placements = [pin for pin in admission["placements"] if str(pin["placementId"]) == str(job["placementId"])]
    if len(placements) != 1:
        raise ValueError("Verification admission has no unique selected placement")
    pin = placements[0]
    fields = {"placement_id": "placementId", "placement_resource_version": "placementResourceVersion",
        "write_spec_version": "writeSpecVersion", "binding_id": "bindingId",
        "binding_resource_version": "bindingResourceVersion", "binding_write_revision": "bindingWriteRevision"}
    if (json.loads(session["admission_json"]) != admission or json.loads(intent["intent_json"]) != complete
            or json.loads(frozen["placement_json"]) != pin
            or session["deployment_id"] != projection["work"]["deployment_id"]
            or session["principal_id"] != admission["principalId"]
            or session["session_id"] != admission["sessionId"]
            or session["logical_fingerprint"] != admission["logicalFingerprint"]
            or session["source_sha256"] != projection["selection"]["expectedSourceSha256"]
            or str(session["declared_size"]) != projection["selection"]["expectedSourceBytes"]
            or intent["operation_id"] != complete["operationId"]
            or str(intent["expected_resource_version"]) != str(complete["expectedResourceVersion"])
            or any(str(frozen[column]) != str(pin[field]) for column, field in fields.items())
            or str(row["placement"]["resource_version"]) != str(pin["placementResourceVersion"])
            or str(row["placement"]["write_spec_version"]) != str(pin["writeSpecVersion"])
            or str(row["binding"]["resource_version"]) != str(pin["bindingResourceVersion"])
            or str(row["binding"]["current_write_revision"]) != str(pin["bindingWriteRevision"])):
        raise ValueError("Actual verification SQL original or current physical pins differ")
    if require_live and int(row["observedUnixMillis"]) >= 1000 * min(
            int(projection["work"]["expires_at"]), int(admission["expiresAt"])):
        raise ValueError("Verification SQL snapshot missed the original work cutoff")
    return pin


def check_verification_publication(row, projection, registry, prepared):
    """Bind the held job to this new registry and its actual signed source."""
    target = projection["job"]["admission"]["intent"]["target"]
    if (row["registry"]["stable_id"] != registry["registry"]["stableId"]
            or row["registry"]["slug"] != registry["registry"]["slug"]
            or row["publication"]["default_commit"] != prepared["source"]["sourceCommit"]
            or row["session"]["target_kind"] != "publication_object"
            or row["session"]["object_path"] != prepared["original"]["relativePath"]
            or target["kind"] != "publication_object"
            or target["publicationId"] != row["publication"]["publication_id"]
            or row["session"]["publication_id"] != row["publication"]["publication_id"]):
        raise ValueError("Held verification belongs to another publication, registry or signed source")


def capture_verification_hold_events(s3, tools):
    """Retain every bounded response-owner event, including its actual times."""
    root = tools["providerHoldInstallation"]["root"]
    result = json.loads(direct_guest_python(s3, tools["python"], """
        import hashlib, os, stat
        from pathlib import Path

        paths=sorted(Path(selected['root']).glob('event-*.json'))
        if not 0<len(paths)<=32:
            raise ValueError('Provider hold event inventory is missing or exceeds bound')
        rows=[]
        for sequence,path in enumerate(paths):
            if path.name!='event-%03d.json'%sequence:
                raise ValueError('Provider hold event sequence is incomplete')
            descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(descriptor,'rb') as source:
                metadata=os.fstat(source.fileno())
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode&0o077
                        or metadata.st_uid!=os.getuid() or not 0<metadata.st_size<=65536):
                    raise ValueError('Provider hold event custody differs')
                body=source.read(65537)
                if len(body)!=metadata.st_size:
                    raise ValueError('Provider hold event changed during capture')
            value=json.loads(body)
            if value['sequence']!=sequence or value['version']!=1:
                raise ValueError('Provider hold event original sequence differs')
            rows.append({'value':value,'file':str(path),'sha256':hashlib.sha256(body).hexdigest(),
                'byteSize':str(len(body))})
        print(json.dumps({'version':1,'events':rows}))
    """, {"root": root}))
    retain_direct_flow("verification-timeout-provider-events.json", result)
    return result


def run_direct_verification_timeout(client, native, worker, s3, tools, controls,
                                    credentials, process):
    """Run one ordinary publisher and require its actual held verification failure."""
    prepared = tools["providerTimeoutSource"]
    registry = controls.create_external_registry(credentials["organization"], credentials["binding"],
        "read-timeout", [prepared["source"]["trustKey"]], "primary",
        credentials["binding"]["spec"]["s3"]["prefix"] + "/read-timeout",
        credentials["currentSqlPins"]["currentWriteRevision"], False)
    retain_direct_flow("verification-timeout-registry.json", registry)
    token = direct_root_browser_token(client, tools["curl"], tools["python"], private_guest_command,
        reuse_session=True)
    positions = {
        "worker": (worker, direct_log_position(worker, tools["python"], process["logFile"])),
        "provider": (s3, direct_log_position(s3, tools["python"], "/var/lib/hybrid-s3/provider-observations.jsonl")),
        "native": (native, direct_log_position(native, tools["python"], "/var/lib/hybrid-native-observations/requests.jsonl")),
        "native-storage": (native, direct_log_position(native, tools["python"], "/var/lib/hybrid-native-outbound/requests.jsonl")),
        "worker-storage": (worker, direct_log_position(worker, tools["python"], "/var/lib/hybrid-worker-boundary/requests.jsonl")),
    }
    before_namespace = direct_namespace_readback(worker, tools["python"], process, namespace_kind="external_copy")
    observe_direct_boundary_lifetimes(native, worker, tools, "verification-timeout-start")
    observer = tools["providerTimeoutObserver"]
    bucket = credentials["binding"]["spec"]["s3"]["bucket"]
    ceiling = int(direct_guest_python(s3, tools["python"],
        "import time; print(time.time_ns()//1000000+35000)", {}))
    arm = {"version": 1, "kind": "arm_first_response",
        "selection": {"version": 1, "host": "s3.fleet.test",
            "targetPrefix": "/" + bucket + "/" + observer["stagingPrefix"] + "/"},
        "expectedSourceBodySha256": observer["expectedSourceSha256"],
        "expectedSourceBodyBytes": observer["expectedSourceBytes"],
        "selectionContextSha256": hashlib.sha256(json.dumps(prepared, sort_keys=True).encode()).hexdigest(),
        "holdUntilUnixMillis": ceiling}
    armed = direct_provider_hold_command(s3, tools, tools["providerHoldInstallation"], arm)
    retain_direct_flow("verification-timeout-arm.json", {"request": arm, "reply": armed})
    captures = {}
    result = {"version": 1, "status": "unknown", "remoteDrain": None, "nativeBulkBytes": None}
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            publisher = pool.submit(publish_direct_verification_source, client, tools,
                registry["registry"]["slug"], prepared, token)
            deadline = time.monotonic() + 35
            while True:
                state = direct_provider_hold_command(s3, tools, tools["providerHoldInstallation"],
                    {"version": 1, "kind": "state"})
                if state["firstResponse"] is not None:
                    break
                if publisher.done() or time.monotonic() >= deadline:
                    raise RuntimeError("First ordinary verification response was not held within fixture ceiling")
                time.sleep(0.05)
            held_log, held_window = retain_direct_log_window(worker, tools["python"], positions["worker"][1],
                "verification-timeout-held-worker.log")
            typed = consume_verification_records(worker, tools, held_log.read_text(), "held")
            attempts = [attempt for attempt in typed["value"]["attempts"] if attempt["prepared"] is not None]
            if len(attempts) != 1:
                raise RuntimeError("Held response lacks one actual prepared verification attempt")
            actual = attempts[0]
            sql = capture_verification_sql(native, tools, actual["projection"], "held")
            check_verification_sql(sql["value"], actual["projection"], require_live=True)
            check_verification_publication(sql["value"], actual["projection"], registry, prepared)
            result.update(heldWindow=held_window, typedHeld=typed, sqlHeld=sql, state=state)
            result["publisher"] = publisher.result(timeout=200)
    finally:
        for name, (machine, before) in positions.items():
            path, receipt = retain_direct_log_window(machine, tools["python"], before,
                "verification-timeout-outer-" + name + ".log")
            captures[name] = {"path": str(path), "receipt": receipt}
        result["outerWindows"] = captures
        result["namespaceBefore"] = before_namespace
        result["namespaceAfter"] = direct_namespace_readback(worker, tools["python"], process,
            namespace_kind="external_copy")
        result["boundaryLifetimes"] = observe_direct_boundary_lifetimes(native, worker, tools,
            "verification-timeout-finish")
        retain_direct_flow("verification-timeout-outer-window.json", result)

    terminal = consume_verification_records(worker, tools,
        Path(captures["worker"]["path"]).read_text(), "terminal")
    result["typedTerminal"] = terminal
    attempt_id = actual["projection"]["attemptId"]
    selected = [attempt for attempt in terminal["value"]["attempts"]
        if attempt["projection"]["attemptId"] == attempt_id]
    if len(selected) != 1 or not selected[0]["completeObservation"] or selected[0]["terminal"]["status"] != "error":
        retain_direct_flow("verification-timeout-assessment.json", result)
        raise RuntimeError("Actual held verification has no complete error terminal")
    response_reference = state["firstResponse"]
    provider_bytes = read_direct_guest_file(s3, tools["python"], response_reference["path"], 65536)
    if (hashlib.sha256(provider_bytes).hexdigest() != response_reference["sha256"]
            or str(len(provider_bytes)) != str(response_reference["byteSize"])):
        raise ValueError("Held provider receipt changed after selection")
    provider = json.loads(provider_bytes)
    expected = actual["prepared"]
    target = urlsplit(expected["providerUrl"])
    if (provider["identity"]["target"] != target.path
            or provider["identity"]["ifMatch"] != expected["requiredHeaders"][0]["value"]
            or provider["response"]["versionId"] != expected["closure"].get("provider_version")
            or provider["response"]["status"] != 200 or not provider["upstreamComplete"]
            or provider["response"]["sha256"] != observer["expectedSourceSha256"]
            or provider["response"]["byteSize"] != observer["expectedSourceBytes"]
            or int(actual["projection"]["work"]["expires_at"]) * 1000 > ceiling):
        retain_direct_flow("verification-timeout-assessment.json", result)
        raise RuntimeError("Actual held provider response differs from the original verification source/cutoff")
    request_reference = provider["requestFile"]
    request_bytes = read_direct_guest_file(s3, tools["python"], request_reference["path"], 65536)
    request = json.loads(request_bytes)
    if (hashlib.sha256(request_bytes).hexdigest() != request_reference["sha256"]
            or str(len(request_bytes)) != str(request_reference["byteSize"])
            or request["method"] != "GET"
            or request["target"] != target.path + ("?" + target.query if target.query else "")):
        raise ValueError("Held raw signed provider request differs from the real prepared read")
    final_state = direct_provider_hold_command(s3, tools, tools["providerHoldInstallation"],
        {"version": 1, "kind": "state"})
    if not final_state["observationsComplete"] or final_state["firstResponse"] != response_reference:
        raise ValueError("Provider hold observation inventory is incomplete or changed")
    result["providerFinalState"] = final_state
    events = capture_verification_hold_events(s3, tools)
    held_events = [row["value"] for row in events["events"]
        if row["value"]["kind"] == "response_held"
        and row["value"].get("receiptFile") == response_reference]
    request_events = [row["value"] for row in events["events"]
        if row["value"]["kind"] == "first_request_received"
        and row["value"].get("requestFile") == request_reference]
    if len(held_events) != 1 or len(request_events) != 1:
        raise ValueError("Actual held response and provider request event are not exclusive")
    original = actual["projection"]["work"]
    requested_ms = int(request_events[0]["unixMillis"])
    if (not 1000 * int(original["issued_at"]) <= requested_ms < 1000 * int(original["expires_at"])
            or held_events[0]["downstreamOfferedBytes"] != "0"
            or held_events[0]["remoteDrain"] is not None
            or int(held_events[0]["holdUntilUnixMillis"]) != ceiling):
        raise ValueError("Provider request missed actual work eligibility or fixture custody differs")
    result["providerEvents"] = events
    final_sql = capture_verification_sql(native, tools, actual["projection"], "terminal")
    check_verification_sql(final_sql["value"], actual["projection"], require_live=False)
    check_verification_publication(final_sql["value"], actual["projection"], registry, prepared)
    result.update(sqlTerminal=final_sql, actualProviderResponse=provider)
    if (final_sql["value"]["session"]["state"] == "committed"
            or final_sql["value"]["completionReceipts"] != 0
            or final_sql["value"]["publication"]["state"] == "ready"):
        retain_direct_flow("verification-timeout-assessment.json", result)
        raise RuntimeError("Failed verification committed an authoritative publication")
    result["status"] = "observed_verification_refusal"
    retain_direct_flow("verification-timeout-assessment.json", result)
    return result
