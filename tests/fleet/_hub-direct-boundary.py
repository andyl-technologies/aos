"""Capture independent actual provider and Native body-classification inputs.

Provider logs exclude query strings and authorization headers. Their private
pathnames are committed in the public projection. Native body files remain
owner-private; only exact hashes, measured lengths and verified control joins
enter the numeric ledger. Missing classification never becomes zero bulk.
"""

import collections
import hashlib
import json
from pathlib import Path
import re


PROVIDER_BOUNDARY_FIELDS = frozenset((
    "method", "caller", "path", "status", "request_http_bytes", "request_body_bytes",
    "transfer_encoding", "response_http_bytes", "response_body_bytes", "etag",
    "content_md5", "elapsed_seconds",
    "operation",
))

NATIVE_CAPTURE_COUNT_LIMIT = 4096
NATIVE_CAPTURE_CORPUS_LIMIT = 512 * 1024 * 1024


def provider_boundary_observations(text, callers):
    """Project actual query-free provider receipts under exact observed callers."""
    if set(callers) != {"client", "worker", "native", "provider"}:
        raise ValueError("provider caller projection lacks a selected machine")
    addresses = {address: name for name, address in callers.items()}
    if len(addresses) != len(callers):
        raise ValueError("provider caller addresses are not independent")
    receipts = []
    for line in text.splitlines():
        if len(line.encode()) > 4096:
            raise ValueError("provider receipt exceeds its bound")
        raw = _direct_runtime_closed_json(line)
        if not isinstance(raw, dict) or set(raw) != PROVIDER_BOUNDARY_FIELDS:
            raise ValueError("provider receipt differs from its closed schema")
        if raw["method"] not in {"GET", "HEAD", "POST", "PUT", "DELETE"}:
            raise ValueError("provider receipt contains an unknown method")
        if raw["operation"] not in {"object", "multipart_session", "multipart_begin"}:
            raise ValueError("provider query classification changed")
        if (not isinstance(raw["path"], str) or not raw["path"].startswith("/")
                or "?" in raw["path"] or len(raw["path"].encode()) > 2048):
            raise ValueError("provider receipt is not a bounded query-free path")
        receipt = {
            "method": raw["method"], "caller": addresses.get(raw["caller"], "unknown"),
            "operation": raw["operation"],
            "pathSha256": hashlib.sha256(raw["path"].encode()).hexdigest(),
            "etagSha256": hashlib.sha256(raw["etag"].encode()).hexdigest(),
            "contentMd5Sha256": hashlib.sha256(raw["content_md5"].encode()).hexdigest(),
        }
        elapsed = raw["elapsed_seconds"]
        if (not isinstance(elapsed, str) or len(elapsed) > 24
                or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,9})?", elapsed)):
            raise ValueError("provider elapsed time is not a finite bounded decimal")
        receipt["elapsedSeconds"] = elapsed
        for name in ("status", "request_http_bytes", "response_http_bytes", "response_body_bytes"):
            receipt[name] = _direct_runtime_integer(raw[name], wire=True)
        body = raw["request_body_bytes"]
        receipt["request_body_bytes"] = (
            None if body == "-" and raw["transfer_encoding"] else
            0 if body == "-" else _direct_runtime_integer(body, wire=True)
        )
        if not 100 <= receipt["status"] <= 599:
            raise ValueError("provider receipt has an invalid status")
        if (receipt["request_body_bytes"] is not None
                and receipt["request_body_bytes"] > receipt["request_http_bytes"]
                or receipt["response_body_bytes"] > receipt["response_http_bytes"]):
            raise ValueError("provider receipt bodies exceed actual HTTP counts")
        receipts.append(receipt)
    if not receipts:
        raise ValueError("actual provider boundary receipts are absent")
    groups = {}
    for receipt in receipts:
        group = groups.setdefault((receipt["caller"], receipt["method"]), {
            "caller": receipt["caller"], "method": receipt["method"], "calls": 0,
            "knownRequestBodyBytes": 0, "unknownRequestBodies": 0, "responseBodyBytes": 0,
        })
        group["calls"] += 1
        group["unknownRequestBodies"] += receipt["request_body_bytes"] is None
        group["knownRequestBodyBytes"] += receipt["request_body_bytes"] or 0
        group["responseBodyBytes"] += receipt["response_body_bytes"]
    return {"version": 1, "receipts": receipts, "groups": list(groups.values()),
        "unknownCallers": sum(receipt["caller"] == "unknown" for receipt in receipts),
        "nativeProviderCalls": sum(receipt["caller"] == "native" for receipt in receipts),
        "nativeBulkBytes": None,
        "scope": "actual independent provider HTTP bytes; physical-original classification remains required"}


def observe_direct_provider_callers(s3, tools):
    """Resolve selected machine names in the actual provider VM namespace."""
    callers = json.loads(direct_guest_python(s3, tools["python"], """
        import socket
        print(json.dumps({name: socket.gethostbyname(name) for name in ('client', 'worker', 'native')}
            | {'provider': '127.0.0.1'}))
    """, {}))
    retain_direct_flow("actual-provider-caller-addresses.json", callers)
    return callers


def capture_direct_native_bodies(native, tools, observations,
                                body_root="/var/lib/hybrid-native-observations",
                                capture_label="native"):
    """Retain exact actual private files and resolve lengths from measured bytes."""
    if (body_root, capture_label) not in {
            ("/var/lib/hybrid-native-observations", "native"),
            ("/var/lib/hybrid-native-outbound", "native-original"),
            ("/var/lib/hybrid-worker-boundary", "worker-received")}:
        raise ValueError("body capture root or role differs from the selected fixture")
    if len(observations) > NATIVE_CAPTURE_COUNT_LIMIT:
        raise ValueError("Native observation corpus exceeds its selected capture count")
    captures, measured, incomplete = [], [], []
    corpus_bytes = 0
    for observation in observations:
        identifier = observation["request_id"]
        captured = {"requestId": identifier, "procedure": observation["procedure"],
            "phase": observation["phase"], "status": observation["status"],
            "method": observation["method"], "responseContentType": observation["response_content_type"],
            "responseContentEncoding": observation["response_content_encoding"], "bodies": {}}
        actual = dict(observation)
        for direction in ("request", "response"):
            path = observation[direction + "_body_file"]
            if direction == "request" and not path:
                if observation["request_transfer_encoding"] or observation["request_body_bytes"] not in {None, 0}:
                    raise ValueError("Native request body is missing despite an observed framing declaration")
                body = b""
            else:
                prefix = body_root + "/" + (
                    "client-body/" if direction == "request" else "response-bodies/"
                )
                if not path.startswith(prefix) or ".." in path.split("/"):
                    raise ValueError("Native private body file escaped its selected observation directory")
                try:
                    body = read_direct_guest_file(native, tools["python"], path, WORKER_CONTROL_REPLY_LIMIT)
                except Exception as error:
                    # Failed HTTP replies are not necessarily stored by nginx.
                    # Preserve that absence; it cannot support classification.
                    captured["bodies"][direction] = None
                    incomplete.append({"requestId": identifier, "direction": direction,
                        "failureClass": type(error).__name__})
                    continue
            expected = observation[direction + "_body_bytes"]
            if expected is not None and len(body) != expected:
                raise ValueError("Native captured body differs from its actual HTTP receipt")
            corpus_bytes += len(body)
            if corpus_bytes > NATIVE_CAPTURE_CORPUS_LIMIT:
                raise ValueError("Native private body corpus exceeds its selected observation bound")
            actual[direction + "_body_bytes"] = len(body)
            filename = capture_label + "-" + identifier + "." + direction + ".body"
            digest = retain_direct_flow(filename, body)
            captured["bodies"][direction] = {"file": str(Path("external-direct-flow") / filename),
                "sha256": digest, "byteSize": len(body)}
        captures.append(captured)
        measured.append(actual)
    receipt = {"version": 1, "bodies": captures,
        "incompleteCaptures": incomplete,
        "capturedCorpusBytes": corpus_bytes,
        "maximumCorpusBytes": NATIVE_CAPTURE_CORPUS_LIMIT,
        "maximumCaptures": NATIVE_CAPTURE_COUNT_LIMIT,
        "maximumBodyBytes": WORKER_CONTROL_REPLY_LIMIT,
        "observerOverhead": "private request buffering and response storage enabled equally for baseline and loaded probes",
        "rawBodies": "retained owner-private; not included in public numeric evidence",
        "scope": "actual Native request and response files; codec classification is independent"}
    retain_direct_flow("actual-" + capture_label + "-private-body-receipts.json", receipt)
    return measured, receipt


def join_direct_native_control_bodies(body_receipts, events):
    """Join exact actual Native bodies to positively decoded closed Worker controls."""
    requests, replies = collections.defaultdict(list), collections.defaultdict(list)
    production = {_direct_runtime_original(event["object"])[:2] for event in events
        if event["scope"] == "production_queue"}
    for event in events:
        if event["kind"] == "control_request":
            requests[event["control"]["signedBodyDigest"]].append(event)
        elif event["kind"] == "control_reply" and event["outcome"] == "positive":
            replies[event["control"]["replyBodyDigest"]].append(event)
    joined, unresolved = [], []
    for capture in body_receipts["bodies"]:
        if capture["phase"] not in DIRECT_NATIVE_PHASES:
            continue
        request = capture["bodies"]["request"]
        reply = capture["bodies"]["response"]
        if request is None or reply is None:
            unresolved.append(capture["requestId"])
            continue
        offers, verified = requests[request["sha256"]], replies[reply["sha256"]]
        pairs = [(offer, finish) for offer in offers for finish in verified
            if offer["control"]["requestDigest"] == finish["control"]["requestDigest"]
            and offer["control"]["signedBodyDigest"] == finish["control"]["signedBodyDigest"]
            and int(offer["bytes"]) == request["byteSize"]
            and int(finish["bytes"]) == reply["byteSize"]]
        # Repeated exact authenticated exchanges describe the same closed bytes.
        # Retain ambiguity if their original/session classification differs.
        distinct = {}
        for offer, finish in pairs:
            key = json.dumps({"offer": offer["control"], "finish": finish["control"],
                "requestBytes": offer["bytes"], "replyBytes": finish["bytes"]}, sort_keys=True)
            distinct.setdefault(key, (offer, finish))
        pairs = list(distinct.values())
        if capture["status"] != 200 or len(pairs) != 1 or capture["responseContentEncoding"]:
            unresolved.append(capture["requestId"])
            continue
        offer, finish = pairs[0]
        sessions = finish["control"]["sessions"] or offer["control"]["sessions"]
        originals = {(session["sessionDigest"], session["originalDigest"]) for session in sessions}
        if not originals or not originals <= production:
            unresolved.append(capture["requestId"])
            continue
        joined.append({"requestId": capture["requestId"], "step": offer["control"]["step"],
            "publicRequestSha256": offer["control"]["publicBodyDigest"],
            "requestSha256": request["sha256"], "replySha256": reply["sha256"],
            "requestBytes": request["byteSize"], "replyBytes": reply["byteSize"],
            "sessions": sessions, "classification": "closed_authenticated_logical_metadata",
            "scope": "exact bytes independently matched to actual successful typed Worker verification"})
    return {"version": 1, "joined": joined, "unresolvedDirectRequestIds": unresolved,
        "nativeBulkBytes": None,
        "scope": "verified logical metadata joins; remaining Native/provider classification required"}


def capture_direct_native_originals(native, tools, publications):
    """Read genuine retained A/B admissions once through Native's SQL metadata path."""
    identifiers = sorted(publication["publication_id"] for publication in publications.values())
    if len(identifiers) != 2 or any(not re.fullmatch(r"[0-9a-f]{32}", value) for value in identifiers):
        raise ValueError("Native original observation requires both actual publication identities")
    output = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os, re, subprocess
        from pathlib import Path

        if not re.fullmatch(r'[a-z0-9-]{1,128}', selected['deploymentId']):
            raise ValueError('selected deployment is not a bounded SQL identity')
        if any(not re.fullmatch(r'[0-9a-f]{32}', value) for value in selected['publicationIds']):
            raise ValueError('selected publication is not an actual SQL identity')
        root = Path('/var/lib/hybrid-native-observations/originals')
        root.mkdir(mode=0o700, exist_ok=False)
        path = root / 'admissions.jsonl'
        query = "BEGIN TRANSACTION READ ONLY; SELECT json_build_object('sessionId', session_id, "
        query += "'publicationId', publication_id, 'state', state, 'admission', admission_json::json)::text "
        query += "FROM direct_upload_sessions WHERE deployment_id = '" + selected['deploymentId'] + "' "
        query += "AND publication_id IN (" + ','.join("'" + value + "'" for value in selected['publicationIds'])
        query += ") ORDER BY session_id; COMMIT;"
        environment = dict(os.environ)
        environment['PGDATABASE'] = Path(selected['databaseUrlFile']).read_text().strip()
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            result = subprocess.run([selected['psql'], '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', query],
                stdout=output, stderr=subprocess.PIPE, env=environment, timeout=120, check=False)
            output.flush()
            os.fsync(output.fileno())
        with path.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        print(json.dumps({'version': 1, 'path': str(path), 'sha256': digest, 'byteSize': path.stat().st_size,
            'exitCode': result.returncode, 'stderrSha256': hashlib.sha256(result.stderr).hexdigest(),
            'publicationIds': selected['publicationIds'],
            'scope': 'one readonly Native SQL metadata snapshot; no provider material or object bytes'}))
    """, {"deploymentId": tools["deploymentId"], "publicationIds": identifiers,
            "databaseUrlFile": tools["nativeDatabaseUrlFile"], "psql": tools["postgres"] + "/psql"}, timeout=150))
    retain_direct_flow("actual-native-original-query.json", output)
    assert output["exitCode"] == 0, output
    position = direct_log_position(native, tools["python"], output["path"])
    path, receipt = retain_direct_log_window(native, tools["python"], {**position, "byteSize": 0},
        "actual-native-originals-private.jsonl")
    if receipt["sha256"] != output["sha256"]:
        raise ValueError("actual retained Native originals changed during observation")
    return path, receipt


def direct_provider_original_mapping(path, publications, bucket, events):
    """Commit exact provider paths from actual retained authenticated admissions."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", bucket):
        raise ValueError("selected actual provider bucket is malformed")
    expected = {(publication["publication_id"], item["path"]): item
        for publication in publications.values() for item in publication["objects"]}
    production = {_direct_runtime_original(event["object"]) for event in events
        if event["scope"] == "production_queue"}
    production_coordinates = {event[:4] + event[5:] for event in production}
    mappings, found = [], set()
    with path.open() as source:
        for line in source:
            if len(line.encode()) > DIRECT_CONTROL_BODY_LIMIT:
                raise ValueError("retained admission exceeded its production codec bound")
            row = _direct_runtime_closed_json(line)
            if set(row) != {"sessionId", "publicationId", "state", "admission"} or row["state"] != "committed":
                raise ValueError("retained actual SQL original is incomplete or changed")
            admission = row["admission"]
            target, intent = admission["intent"]["target"], admission["intent"]
            if (target["kind"] != "publication_object" or target["publicationId"] != row["publicationId"]
                    or admission["sessionId"] != row["sessionId"]):
                raise ValueError("retained admission differs from the actual publication owner")
            key = (row["publicationId"], target["path"])
            actual = expected.get(key)
            if (actual is None or intent["expectedSha256"] != actual["sha256"]
                    or int(intent["byteSize"]) != int(actual["byte_size"])):
                raise ValueError("provider original differs from the genuine final publication inventory")
            session = hashlib.sha256(admission["sessionId"].encode()).hexdigest()
            original = hashlib.sha256(admission["logicalFingerprint"].encode()).hexdigest()
            client_operation = hashlib.sha256(intent["clientOperationId"].encode()).hexdigest()
            for placement in admission["placements"]:
                placement_id = int(placement["placementId"])
                if placement_id < 1:
                    raise ValueError("retained placement identity is invalid")
                stage = placement["stagingPrefix"] + "/" + session + "/" + str(placement_id) + "/payload"
                final = placement["finalKey"]
                placement_digest = hashlib.sha256(str(placement_id).encode()).hexdigest()
                if (session, original, client_operation, placement_digest,
                        intent["dependencyPhase"], intent["byteSize"]) not in production_coordinates:
                    raise ValueError("retained provider original lacks genuine production queue evidence")
                mappings.append({"sessionDigest": session, "originalDigest": original,
                    "clientOperationDigest": client_operation,
                    "publicationId": row["publicationId"], "objectPathSha256": hashlib.sha256(target["path"].encode()).hexdigest(),
                    "placementId": str(placement_id), "dependencyPhase": intent["dependencyPhase"],
                    "placementDigest": placement_digest,
                    "expectedSha256": intent["expectedSha256"], "byteSize": intent["byteSize"],
                    "stagePathSha256": hashlib.sha256(("/" + bucket + "/" + stage).encode()).hexdigest(),
                    "finalPathSha256": hashlib.sha256(("/" + bucket + "/" + final).encode()).hexdigest(),
                    "physicalKeyDerivation": "actual core direct_staging_key and retained placement.final_key"})
            found.add(key)
    if found != set(expected):
        raise ValueError("actual retained originals do not cover both complete publications")
    report = {"version": 1, "originals": mappings,
        "scope": "genuine retained SQL admissions matched to both final inventories and production originals; key mapping only"}
    retain_direct_flow("actual-provider-original-path-commitments.json", report)
    return report


def classify_direct_provider_object_receipts(boundary, mapping):
    """Classify known physical paths without converting incomplete traffic to zero."""
    paths = {}
    for original in mapping["originals"]:
        for name in ("stage", "final"):
            path_digest = original[name + "PathSha256"]
            item = {**original, "location": name}
            if path_digest in paths and paths[path_digest] != item:
                raise ValueError("provider path has ambiguous actual original ownership")
            paths[path_digest] = item
    classified, unresolved = [], []
    for index, receipt in enumerate(boundary["receipts"]):
        original = paths.get(receipt["pathSha256"])
        if original is None or receipt["caller"] not in {"client", "worker"}:
            unresolved.append(index)
            continue
        request_bytes = receipt["request_body_bytes"]
        status, method = receipt["status"], receipt["method"]
        object_bytes, metadata_bytes = None, None
        if method == "PUT" and request_bytes is not None:
            object_bytes = request_bytes
            metadata_bytes = receipt["response_body_bytes"]
        elif (method == "GET" and receipt["operation"] == "object"
                and status in {200, 206} and request_bytes == 0):
            object_bytes = receipt["response_body_bytes"]
            metadata_bytes = 0
        elif method == "GET" and receipt["operation"] == "multipart_session" and request_bytes == 0:
            object_bytes = 0
            metadata_bytes = receipt["response_body_bytes"]
        elif method == "HEAD" and request_bytes == 0 and receipt["response_body_bytes"] == 0:
            object_bytes, metadata_bytes = 0, 0
        elif (method in {"POST", "DELETE"} and receipt["operation"] != "object"
                and request_bytes is not None and request_bytes <= DIRECT_CONTROL_BODY_LIMIT):
            object_bytes = 0
            metadata_bytes = request_bytes + receipt["response_body_bytes"]
        elif status >= 400 and request_bytes == 0 and receipt["response_body_bytes"] <= DIRECT_CONTROL_BODY_LIMIT:
            object_bytes = 0
            metadata_bytes = receipt["response_body_bytes"]
        if object_bytes is None or metadata_bytes > DIRECT_CONTROL_BODY_LIMIT:
            unresolved.append(index)
            continue
        classified.append({"receiptIndex": index, "caller": receipt["caller"],
            "method": method, "status": status, "location": original["location"],
            "operation": receipt["operation"],
            "sessionDigest": original["sessionDigest"], "originalDigest": original["originalDigest"],
            "placementDigest": original["placementDigest"], "publicationId": original["publicationId"],
            "dependencyPhase": original["dependencyPhase"], "objectTransferBytes": object_bytes,
            "boundedProviderProtocolMetadataBytes": metadata_bytes,
            "classification": "exact retained physical original with observed ordinary S3 method/status"})
    report = {"version": 1, "classified": classified, "unresolvedReceiptIndexes": unresolved,
        "nativeProviderCalls": boundary["nativeProviderCalls"], "unknownCallers": boundary["unknownCallers"],
        "nativeBulkBytes": None,
        "scope": "actual provider object/control classification; Native body codec proof remains independent"}
    retain_direct_flow("actual-provider-object-classification.json", report)
    return report


def summarize_direct_provider_throughput(boundary, classification, mapping, corpus, interval):
    """Report retry-inclusive transfer rates over one actual loaded wall interval."""
    fields = {"clock", "startedNanoseconds", "finishedNanoseconds", "elapsedNanoseconds"}
    if not isinstance(interval, dict) or set(interval) != fields or interval["clock"] != "controller_monotonic":
        raise ValueError("publication throughput lacks its actual monotonic interval")
    started, finished, elapsed = (
        _direct_runtime_integer(interval[name], wire=True)
        for name in ("startedNanoseconds", "finishedNanoseconds", "elapsedNanoseconds")
    )
    if started == 0 or finished <= started or elapsed != finished - started:
        raise ValueError("publication throughput has a missing or zero elapsed interval")
    if (classification["unresolvedReceiptIndexes"] or classification["unknownCallers"]
            or classification["nativeProviderCalls"]
            or len(classification["classified"]) != len(boundary["receipts"])):
        raise ValueError("publication throughput has incomplete provider classification")

    bulk = {hashlib.sha256(item["path"].encode()).hexdigest(): item for item in corpus["large_objects"]}
    metadata = {hashlib.sha256(f"web/packages/direct-qualification-{number:05d}.json".encode()).hexdigest()
        for number in range(corpus["metadata_objects"])}
    if not bulk or not metadata or len(bulk) != len(corpus["large_objects"]) or set(bulk) & metadata:
        raise ValueError("publication throughput corpus identities are incomplete or ambiguous")
    originals, selected = {}, {"bulk": set(), "metadata": set()}
    for original in mapping["originals"]:
        path = original["objectPathSha256"]
        category = "bulk" if path in bulk else "metadata" if path in metadata else "signed_surface_other"
        size = _direct_runtime_integer(original["byteSize"], wire=True)
        if category == "bulk" and (size != bulk[path]["byte_size"]
                or original["expectedSha256"] != bulk[path]["sha256"]
                or original["dependencyPhase"] != "content"):
            raise ValueError("bulk throughput original differs from the actual source corpus")
        if category == "metadata" and (size == 0 or original["dependencyPhase"] != "visibility"):
            raise ValueError("metadata throughput original changed its Visibility dependency")
        coordinate = (original["sessionDigest"], original["originalDigest"], original["placementDigest"])
        if coordinate in originals:
            raise ValueError("publication throughput original ownership is duplicated")
        originals[coordinate] = {"category": category, "byteSize": size,
            "uploadedBytes": 0, "readBytes": 0}
        if category in selected:
            if path in selected[category]:
                raise ValueError("one source corpus path belongs to multiple throughput originals")
            selected[category].add(path)
    if selected != {"bulk": set(bulk), "metadata": metadata}:
        raise ValueError("publication throughput does not cover the complete source corpus")

    classes = {name: {"positiveClientUploadBytes": 0, "positiveWorkerReadBytes": 0,
        "positiveClientUploadRequests": 0, "positiveWorkerReadRequests": 0}
        for name in ("bulk", "metadata", "signed_surface_other")}
    seen = set()
    for item in classification["classified"]:
        index = item["receiptIndex"]
        if type(index) is not int or not 0 <= index < len(boundary["receipts"]) or index in seen:
            raise ValueError("publication throughput provider receipt is duplicated or missing")
        seen.add(index)
        receipt = boundary["receipts"][index]
        if any(item[name] != receipt[name] for name in ("caller", "method", "status")):
            raise ValueError("publication throughput classification differs from its provider receipt")
        coordinate = (item["sessionDigest"], item["originalDigest"], item["placementDigest"])
        if coordinate not in originals:
            raise ValueError("publication throughput receipt has no retained original")
        original = originals[coordinate]
        observed = classes[original["category"]]
        transferred = _direct_runtime_integer(item["objectTransferBytes"])
        if not 200 <= item["status"] < 300:
            continue
        if item["caller"] == "client" and item["method"] == "PUT" and item["location"] == "stage":
            if item["objectTransferBytes"] != receipt["request_body_bytes"]:
                raise ValueError("publication throughput upload differs from actual provider bytes")
            observed["positiveClientUploadBytes"] += transferred
            observed["positiveClientUploadRequests"] += 1
            original["uploadedBytes"] += transferred
        elif item["caller"] == "worker" and item["method"] == "GET" and item["operation"] == "object":
            if item["objectTransferBytes"] != receipt["response_body_bytes"]:
                raise ValueError("publication throughput read differs from actual provider bytes")
            observed["positiveWorkerReadBytes"] += transferred
            observed["positiveWorkerReadRequests"] += 1
            original["readBytes"] += transferred
    if seen != set(range(len(boundary["receipts"]))):
        raise ValueError("publication throughput provider receipts are incomplete")
    for original in originals.values():
        if (original["uploadedBytes"] < original["byteSize"]
                or original["readBytes"] < original["byteSize"]):
            raise ValueError("publication throughput has incomplete positive original byte coverage")
    for category, observed in classes.items():
        if category != "signed_surface_other" and (
                observed["positiveClientUploadBytes"] == 0 or observed["positiveWorkerReadBytes"] == 0):
            raise ValueError("publication throughput has no positive class transfer observations")
        observed["clientUploadBytesPerSecond"] = observed["positiveClientUploadBytes"] * 1_000_000_000 / elapsed
        observed["workerReadBytesPerSecond"] = observed["positiveWorkerReadBytes"] * 1_000_000_000 / elapsed
    return {"version": 1, "interval": interval, "classes": classes,
        "sourceObjects": {name: len(paths) for name, paths in selected.items()},
        "scope": "actual successful provider transfer bytes divided by one shared loaded interval spanning the retained log window; retries, source preparation, sparse recovery, other signed objects and observer capture overhead included; not unique goodput or per-request service rate"}
