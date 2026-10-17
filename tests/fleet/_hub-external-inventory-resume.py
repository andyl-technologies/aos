"""Retain current schema-12 partial inventory before an owned Native restart.

These observations establish the selected SQL checkpoint and portable byte
count. They do not grant a provider read or reconstruct a past permission.
Raw progress and collector claims remain in the caller's private SQL custody.
"""

import hashlib
import json
import re


MAX_PROGRESS_BYTES = 16 * 1024


def _closed(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate inventory progress field")
        result[key] = value
    return result


def _integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError("inventory progress numeric field differs")
    return value


def require_partial_inventory(row, expected, observed_unix_seconds):
    """Check real private SQL progress against its current generation fences.

    The source-owned controller validates the stored encoding on resume. This
    fixture independently checks the selected nonterminal byte offset and SQL
    joins; it does not turn the retained closure into new read authority.
    """
    generation = row["generation"]
    current = row["current"]
    if (generation["state"] != "collecting" or generation["active_slot"] != 1
            or generation["placement_id"] != expected["placementId"]
            or generation["registry_id"] != expected["registryId"]
            or current["registry_stable_id"] != expected["registryStableId"]
            or current["placement_prefix"] != expected["placementPrefix"]
            or generation["collector_lease_expires_at"] <= observed_unix_seconds
            or not generation["collector_id"] or not generation["collector_claim_token"]
            or not re.fullmatch(r"ociinv-[0-9a-f]{32}", generation["id"])):
        raise ValueError("inventory lacks the selected live nonterminal generation")
    for name in ("resource_version", "placement_resource_version", "placement_write_spec_version",
            "placement_observation_version", "binding_resource_version", "binding_write_revision"):
        _integer(generation[name], 1)
    if generation["captured_mutation_epoch"] != current["mutation_epoch"]:
        raise ValueError("inventory current registry mutation fence changed")
    for name in ("placement_resource_version", "placement_write_spec_version",
            "placement_observation_version", "binding_id", "binding_resource_version",
            "binding_write_revision"):
        if generation[name] != current[name]:
            raise ValueError("inventory current placement/binding fence changed")

    encoded = row["progressHex"]
    if (not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-f]+", encoded)
            or len(encoded) % 2 or len(encoded) > 2 * MAX_PROGRESS_BYTES):
        raise ValueError("inventory progress cell is missing or excessive")
    raw = bytes.fromhex(encoded)
    progress = json.loads(raw, object_pairs_hook=_closed)
    if set(progress) != {"version", "generation_id", "next_provider_cursor", "object"}:
        raise ValueError("inventory progress outer fields differ")
    if progress["version"] != 1 or progress["generation_id"] != generation["id"]:
        raise ValueError("inventory progress belongs to another generation")
    obj = progress["object"]
    required = {"placement_id", "checkpoint_ordinal", "provider_cursor", "object_key",
        "object_digest", "expected_size", "strong_etag", "next_offset", "sha_version",
        "sha_words", "sha_total_bytes", "sha_tail_hex"}
    if not required.issubset(obj) or set(obj) - required - {"provider_version", "guarded_source"}:
        raise ValueError("inventory progress object fields differ")
    if (obj["placement_id"] != generation["placement_id"]
            or obj["checkpoint_ordinal"] != generation["checkpoint_ordinal"]
            or obj["provider_cursor"] != generation["provider_cursor"]
            or obj["object_key"] != expected["objectKey"]
            or obj["object_digest"] != expected["objectDigest"]
            or obj["expected_size"] != expected["objectBytes"]):
        raise ValueError("inventory progress does not bind the selected object/checkpoint")
    offset = _integer(obj["next_offset"], 1)
    if offset >= _integer(obj["expected_size"], 1) or obj["sha_total_bytes"] != offset:
        raise ValueError("inventory progress is terminal or its byte count differs")
    if (obj["sha_version"] != 1 or not isinstance(obj["sha_words"], list)
            or len(obj["sha_words"]) != 8
            or any(type(word) is not int or not 0 <= word <= 0xffffffff for word in obj["sha_words"])
            or not isinstance(obj["sha_tail_hex"], str)
            or not re.fullmatch(r"[0-9a-f]*", obj["sha_tail_hex"])
            or len(obj["sha_tail_hex"]) != 2 * (offset % 64)):
        raise ValueError("inventory portable hash geometry differs")
    # Retain the entire raw row privately. Public projections contain no claim,
    # conditional tag, guarded closure or provider cursor.
    return {"generationId": generation["id"], "generationResourceVersion": generation["resource_version"],
        "checkpointOrdinal": generation["checkpoint_ordinal"], "nextOffset": offset,
        "expectedSize": obj["expected_size"], "progressSha256": hashlib.sha256(raw).hexdigest(),
        "progressBytes": len(raw), "scope": "current SQL partial checkpoint; provider authority remains separate"}


def observe_partial_inventory(read_sql, expected, label, observed_unix_seconds):
    """Read one bounded real generation and its current SQL fences atomically."""
    placement = _integer(expected["placementId"], 1)
    registry = _integer(expected["registryId"], 1)
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,95}", label):
        raise ValueError("inventory observation label differs")
    query = (
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
        "SELECT (SELECT json_build_object('generation', row_to_json(g), 'progressHex', encode(g.object_progress,'hex'), "
        "'current', json_build_object('registry_stable_id',r.stable_id,'placement_prefix',p.prefix,"
        "'placement_resource_version',p.resource_version,'placement_write_spec_version',p.write_spec_version,"
        "'placement_observation_version',o.observation_version,'binding_id',b.id,"
        "'binding_resource_version',b.resource_version,'binding_write_revision',w.current_write_revision,"
        "'mutation_epoch',s.mutation_epoch)) "
        "FROM oci_provider_inventory_generations g "
        "JOIN registries r ON r.id=g.registry_id "
        "JOIN oci_registry_state s ON s.registry_id=r.id "
        "JOIN surface_placements p ON p.id=g.placement_id AND p.registry_id=r.id "
        "JOIN surface_placement_observations o ON o.placement_id=p.id "
        "JOIN bindings b ON b.id=p.binding_id "
        "JOIN binding_write_state w ON w.binding_id=b.id "
        "WHERE g.registry_id=" + str(registry) + " AND g.placement_id=" + str(placement) + " "
        "AND g.state='collecting' AND g.active_slot=1 AND g.object_progress IS NOT NULL); COMMIT;"
    )
    observed = read_sql(query, label)
    if set(observed) != {"value", "receipt"} or not observed["receipt"]:
        raise ValueError("inventory observation lacks private current SQL custody")
    # Absence is a retained SQL observation while the real controller is busy.
    # A malformed or mismatched present row still refuses immediately.
    current_time = observed_unix_seconds() if callable(observed_unix_seconds) else observed_unix_seconds
    _integer(current_time, 1)
    summary = None if observed["value"] is None else require_partial_inventory(
        observed["value"], expected, current_time)
    return {"summary": summary, "privateSql": observed, "observedUnixSeconds": current_time}


def _read_provider_reference(reference, read_private, root, maximum):
    if (not isinstance(reference, dict) or set(reference) != {"path", "sha256", "byteSize"}
            or not isinstance(reference["path"], str)
            or not reference["path"].startswith(root + "/")
            or any(part in {"", ".", ".."} for part in reference["path"].split("/")[1:])
            or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])
            or not re.fullmatch(r"[1-9][0-9]*", reference["byteSize"])
            or int(reference["byteSize"]) > maximum):
        raise ValueError("inventory provider reference differs from its selected private custody")
    raw = read_private(reference["path"], maximum)
    if (not isinstance(raw, bytes) or len(raw) != int(reference["byteSize"])
            or hashlib.sha256(raw).hexdigest() != reference["sha256"]):
        raise ValueError("inventory provider reference changed")
    return raw


def require_inventory_provider_checkpoint(state, observed, expected, read_private, provider_root):
    """Join actual offered continuation headers to a retained live SQL checkpoint.

    The prefix observation proves proxy offering only. A real saved SQL hash
    state proves the earlier interval was incorporated by the current collector;
    neither is substituted for the later guarded Hash or complete source digest.
    """
    fields = {"version", "targetPrefix", "selected", "prefixReceipt", "recorderHealthy",
        "terminal", "pendingLocalHold", "providerSettlement", "continuationReceipts",
        "firstRangeReceipt", "awaitingFirstRange", "holdUntilUnixMillis", "fixtureCutoffUnixMillis"}
    if (set(state) != fields or state["version"] != 1
            or state["targetPrefix"] != expected["providerPrefix"]
            or state["selected"] is not True or state["recorderHealthy"] is not True
            or state["pendingLocalHold"] is not True or state["terminal"] is not None
            or state["providerSettlement"] is not None or state["continuationReceipts"] != []
            or state["firstRangeReceipt"] is None or state["awaitingFirstRange"] is not False
            or observed["summary"] is None or observed["summary"]["nextOffset"] != 8388608):
        raise ValueError("inventory lacks one pending physical continuation and matching saved interval")
    row = observed["privateSql"]["value"]
    progress = json.loads(bytes.fromhex(row["progressHex"]), object_pairs_hook=_closed)
    receipt = json.loads(_read_provider_reference(state["prefixReceipt"], read_private,
        provider_root, 16384), object_pairs_hook=_closed)
    if (set(receipt) != {"version", "scope", "identity", "requestReceipt", "headersReceipt",
            "prefixFile", "downstreamOfferedBytes", "upstreamComplete", "workerConsumedBytes", "remoteDrain"}
            or receipt["version"] != 1 or receipt["scope"] != "actual_provider_partial_response_offering"
            or receipt["downstreamOfferedBytes"] != "65536" or receipt["upstreamComplete"] is not False
            or receipt["workerConsumedBytes"] is not None or receipt["remoteDrain"] is not None):
        raise ValueError("inventory prefix receipt is not an actual bounded offering")
    identity = receipt["identity"]
    source_key = expected["providerPrefix"] + expected["objectKey"]
    if (set(identity) != {"method", "targetSha256", "host", "ifMatch", "range", "signatureVerification"}
            or identity["method"] != "GET" or identity["host"] != "s3.fleet.test"
            or identity["signatureVerification"] is not None
            or identity["targetSha256"] != hashlib.sha256(source_key.encode()).hexdigest()
            or identity["ifMatch"] != progress["object"]["strong_etag"]):
        raise ValueError("inventory physical request differs from its saved selected source")
    interval = re.fullmatch(r"bytes=8388608-([1-9][0-9]*)", identity["range"])
    if interval is None or not 8388608 + 65536 <= int(interval[1]) + 1 <= expected["objectBytes"]:
        raise ValueError("inventory physical range does not cover the selected continuation")
    request = json.loads(_read_provider_reference(receipt["requestReceipt"], read_private,
        provider_root, 4096), object_pairs_hook=_closed)
    if request != {key: identity[key] for key in ("method", "targetSha256", "host", "range", "ifMatch")}:
        raise ValueError("inventory retained conditional headers changed")
    headers = json.loads(_read_provider_reference(receipt["headersReceipt"], read_private,
        provider_root, 4096), object_pairs_hook=_closed)
    if headers != {"status": 206, "contentLength": str(int(interval[1]) - 8388608 + 1),
            "contentRange": "bytes 8388608-" + interval[1] + "/" + str(expected["objectBytes"])}:
        raise ValueError("inventory real provider reply differs from the saved range")
    first = json.loads(_read_provider_reference(state["firstRangeReceipt"], read_private,
        provider_root, 16384), object_pairs_hook=_closed)
    first_identity = {**identity, "range": "bytes=0-8388607"}
    if (first["identity"] != first_identity or first["status"] != 206
            or first["contentLength"] != "8388608"
            or first["contentRange"] != "bytes 0-8388607/" + str(expected["objectBytes"])
            or first["responseBytes"] != "8388608" or first["upstreamComplete"] is not True
            or first["responseSha256"] != expected["firstRangeSha256"]):
        raise ValueError("inventory first interval is not retained from the actual immutable source")
    prefix = _read_provider_reference(receipt["prefixFile"], read_private, provider_root, 65536)
    if len(prefix) != 65536:
        raise ValueError("inventory offered prefix has another byte count")
    return {"sql": observed, "provider": state, "range": identity["range"],
        "prefixSha256": hashlib.sha256(prefix).hexdigest(), "proxyOfferedBytes": 65536,
        "nativeConsumedContinuationBytes": None, "remoteDrain": None}


def require_inventory_resumed_range(state, checkpoint, expected, read_private, provider_root,
                                    launch_boundary_unix_millis):
    """Check an actual later range and its bytes against the immutable source.

    The proxy records full provider responses independently of the SQL hash.
    These observations do not authenticate the request or prove Worker drain.
    """
    if (state.get("recorderHealthy") is not True or state.get("selected") is not True
            or state.get("providerSettlement") is not None
            or state.get("targetPrefix") != expected["providerPrefix"]
            or state.get("firstRangeReceipt") != checkpoint["provider"]["firstRangeReceipt"]
            or not state.get("continuationReceipts")):
        raise ValueError("inventory continuation lacks its original physical selection")
    first = json.loads(_read_provider_reference(state["firstRangeReceipt"], read_private,
        provider_root, 16384), object_pairs_hook=_closed)
    if (first["identity"]["range"] != "bytes=0-8388607" or first["responseBytes"] != "8388608"
            or first["responseSha256"] != expected["firstRangeSha256"] or first["upstreamComplete"] is not True):
        raise ValueError("inventory first interval differs from the immutable source")
    end = 8388608 + expected["secondRangeBytes"] - 1
    progress = json.loads(bytes.fromhex(checkpoint["sql"]["privateSql"]["value"]["progressHex"]))
    _integer(launch_boundary_unix_millis, 1)
    matched, earlier = [], []
    for reference in state["continuationReceipts"]:
        reply = json.loads(_read_provider_reference(reference, read_private,
            provider_root, 16384), object_pairs_hook=_closed)
        if (not isinstance(reply["startedUnixMillis"], str)
                or re.fullmatch(r"[1-9][0-9]*", reply["startedUnixMillis"]) is None):
            raise ValueError("inventory continuation lacks its actual start time")
        if int(reply["startedUnixMillis"]) < launch_boundary_unix_millis:
            earlier.append(reference)
            continue
        if (reply["identity"]["range"] != "bytes=8388608-" + str(end)
                or reply["identity"]["targetSha256"] != hashlib.sha256(
                    (expected["providerPrefix"] + expected["objectKey"]).encode()).hexdigest()
                or reply["identity"]["ifMatch"] != progress["object"]["strong_etag"]
                or reply["status"] != 206 or reply["contentRange"] !=
                    "bytes 8388608-" + str(end) + "/" + str(expected["objectBytes"])
                or reply["responseBytes"] != str(expected["secondRangeBytes"])
                or reply["contentLength"] != reply["responseBytes"]
                or reply["responseSha256"] != expected["secondRangeSha256"]
                or reply["upstreamComplete"] is not True):
            raise ValueError("inventory resumed physical interval differs from the source/checkpoint")
        matched.append({"receipt": reference, "responseSha256": reply["responseSha256"],
            "responseBytes": reply["responseBytes"], "range": reply["identity"]["range"]})
    if not matched:
        return None
    return {"firstRangeReceipt": state["firstRangeReceipt"], "resumedRanges": matched,
        "earlierRanges": earlier, "newEpochLaunchBoundaryUnixMillis": launch_boundary_unix_millis,
        "requestAuthentication": None, "workerConsumedBytes": None, "remoteDrain": None}


def observe_completed_inventory(read_sql, expected, partial, label):
    """Reopen the actual completed generation/head and source hash after restart."""
    generation_id = partial["summary"]["generationId"]
    if (re.fullmatch(r"ociinv-[0-9a-f]{32}", generation_id) is None
            or re.fullmatch(r"oci/blobs/sha256/[0-9a-f]{64}", expected["objectKey"]) is None):
        raise ValueError("completed inventory generation differs")
    query = ("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
        "SELECT (SELECT json_build_object('generation',row_to_json(g),'head',row_to_json(h),"
        "'entry',row_to_json(e)) FROM oci_provider_inventory_generations g "
        "LEFT JOIN oci_provider_inventory_heads h ON h.generation_id=g.id AND h.placement_id=g.placement_id "
        "LEFT JOIN oci_provider_inventory_entries e ON e.generation_id=g.id AND e.object_key='"
        + expected["objectKey"] + "' WHERE g.id='" + generation_id + "'); COMMIT;")
    observed = read_sql(query, label)
    if set(observed) != {"value", "receipt"} or not observed["receipt"]:
        raise ValueError("completed inventory lacks retained current SQL custody")
    row = observed["value"]
    if row is None or row["generation"]["state"] in {"collecting", "sealing"}:
        return {"summary": None, "privateSql": observed}
    generation, head, entry = row["generation"], row["head"], row["entry"]
    if (generation["state"] != "complete" or generation["active_slot"] is not None
            or generation["object_progress"] is not None or generation["provider_cursor"] is not None
            or generation["id"] != generation_id
            or generation["resource_version"] <= partial["summary"]["generationResourceVersion"]
            or generation["checkpoint_ordinal"] <= partial["summary"]["checkpointOrdinal"]
            or not head or head["generation_id"] != generation_id
            or head["placement_id"] != expected["placementId"] or head["registry_id"] != expected["registryId"]
            or not entry or entry["object_key"] != expected["objectKey"]
            or entry["object_digest"] != expected["objectDigest"]
            or entry["observed_hash"] != expected["objectDigest"]
            or entry["byte_size"] != expected["objectBytes"]
            or entry["strong_etag"] != json.loads(bytes.fromhex(partial["privateSql"]["value"]["progressHex"]))["object"]["strong_etag"]):
        raise ValueError("inventory restart did not complete and clear its exact saved source generation")
    original = partial["privateSql"]["value"]["generation"]
    for name in ("collector_id", "registry_id", "placement_id", "captured_mutation_epoch",
            "placement_resource_version", "placement_write_spec_version", "placement_observation_version",
            "binding_id", "binding_resource_version", "binding_write_revision"):
        if generation[name] != original[name]:
            raise ValueError("completed inventory changed its saved source/collector fences")
    return {"summary": {"generationId": generation_id,
        "generationResourceVersion": generation["resource_version"],
        "checkpointOrdinal": generation["checkpoint_ordinal"], "sourceHash": entry["observed_hash"],
        "objectBytes": entry["byte_size"], "progressCleared": True}, "privateSql": observed}


def require_inventory_restart_fence(observed, partial):
    """Require a current live SQL collector fence after the actual owner restart."""
    if observed["summary"] is None:
        return None
    old = partial["privateSql"]["value"]["generation"]
    new = observed["privateSql"]["value"]["generation"]
    for name in ("id", "collector_id", "registry_id", "placement_id", "captured_mutation_epoch",
            "placement_resource_version", "placement_write_spec_version", "placement_observation_version",
            "binding_id", "binding_resource_version", "binding_write_revision"):
        if new[name] != old[name]:
            raise ValueError("inventory restarted collector changed its source fences")
    if (new["resource_version"] < old["resource_version"]
            or new["collector_lease_expires_at"] <= old["collector_lease_expires_at"]
            or observed["summary"]["nextOffset"] < partial["summary"]["nextOffset"]):
        return None
    # The production claim seed can repeat within one minute. Its current
    # nonempty token is checked by the live-row validator, not by inequality.
    return observed


def require_inventory_restart_exchange(window, process, checkpoint, expected, source_digest,
                                       codec_source_sha256, read_body):
    """Select an authenticated checked Hash reply from the exclusive new epoch.

    The existing transport, Native execute and shared codec consumers establish
    their own independent joins. This selection binds their exact raw plan and
    result to the retained durable state; timestamps do not substitute for it.
    """
    observed = window["processObservations"]["native"]
    if any(observed[name] != process[name] for name in ("pid", "startTicks", "executableSha256")):
        raise ValueError("inventory Hash observation belongs to another Native epoch")
    decoded = window["nativeOutboundDecoded"]
    if not decoded or decoded.get("complete") is not True:
        raise ValueError("inventory new epoch has incomplete typed body observations")
    bodies = {row["requestId"]: row for row in window["storageBoundary"]["nativeOriginalBodies"]["bodies"]}
    codecs = {row["requestId"]: row for row in decoded["observations"]}
    transports = {row["nativeRequestId"]: row for row in window["nativeAuthenticatedTransports"]["joined"]}
    progress = json.loads(bytes.fromhex(checkpoint["sql"]["privateSql"]["value"]["progressHex"]))["object"]
    generation = checkpoint["sql"]["privateSql"]["value"]["generation"]
    saved_state = {"version": progress["sha_version"], "words": progress["sha_words"],
        "total_bytes": progress["sha_total_bytes"], "tail_hex": progress["sha_tail_hex"]}
    end = progress["next_offset"] + expected["secondRangeBytes"] - 1
    for joined in window["nativeExecuteObservations"]["joined"]:
        attempt = joined["attempt"]
        if attempt["operation"] != "hash_oci_range" or attempt["outcome"] != "typed_result_checked":
            continue
        identity = joined["nativeRequestId"]
        codec, transport, body = codecs.get(identity), transports.get(identity), bodies.get(identity)
        if not codec or not transport or not body or joined["fullReplyConsumed"] is not True:
            continue
        request, reply = (body["bodies"][name] for name in ("request", "response"))
        if (codec["sourceDigest"] != source_digest or codec["codecSourceSha256"] != codec_source_sha256
                or codec["operation"] != "hash_oci_range"
                or codec["requestSha256"] != request["sha256"] or codec["replySha256"] != reply["sha256"]
                or transport["requestSha256"] != request["sha256"] or transport["replySha256"] != reply["sha256"]
                or transport["transportCallIdSha256"] != hashlib.sha256(joined["transportCallId"].encode()).hexdigest()
                or attempt["offeredRequestSha256"] != request["sha256"]
                or attempt["exposedReplySha256"] != reply["sha256"]):
            raise ValueError("inventory authenticated typed Hash custody differs")
        def reopen(reference):
            raw = read_body(reference)
            if len(raw) != int(reference["byteSize"]) or hashlib.sha256(raw).hexdigest() != reference["sha256"]:
                raise ValueError("inventory retained Hash body changed")
            return json.loads(raw, object_pairs_hook=_closed)
        plan, result = reopen(request), reopen(reply)
        operation = plan["operation"]
        if operation.get("kind") != "hash_oci_range" or operation.get("path") != expected["objectKey"]:
            continue
        if operation.get("start") != progress["next_offset"]:
            continue
        for name in ("placement_id", "placement_resource_version", "binding_id", "binding_resource_version"):
            if plan[name] != generation[name] or result[name] != plan[name]:
                raise ValueError("inventory new Hash changes its current source selection")
        if (plan["placement_prefix"] != expected["placementPrefix"]
                or result["plan_id"] != plan["plan_id"]
                or operation["end"] != end or operation["total"] != expected["objectBytes"]
                or operation["strong_etag"] != progress["strong_etag"]
                or operation.get("expected_provider_version") != progress.get("provider_version")
                or operation["sha256_state"] != saved_state
                or operation.get("guarded_source") != progress.get("guarded_source")
                or operation.get("guarded_source") is None):
            raise ValueError("inventory new Hash does not resume its retained exact guarded state")
        outcome = result["outcome"]
        source = outcome["source"]
        if (outcome["kind"] != "oci_range_hashed" or outcome["start"] != progress["next_offset"]
                or outcome["end"] != end or outcome["guarded_source"] != operation["guarded_source"]
                or source["key"] != expected["placementPrefix"].strip("/") + "/" + expected["objectKey"]
                or source["size"] != expected["objectBytes"] or source["etag"] != progress["strong_etag"]
                or source.get("provider_version") != progress.get("provider_version")
                or result["source_bytes"] != expected["secondRangeBytes"]
                or outcome["sha256_state"]["total_bytes"] != end + 1):
            raise ValueError("inventory new Hash reply does not finish the exact continuation")
        return {"nativeRequestId": identity, "request": request, "reply": reply,
            "transport": transport, "execute": joined, "codec": codec,
            "scope": "actual new Native epoch authenticated checked guarded Hash continuation"}
    raise ValueError("inventory lacks a checked continuation from the actual restarted Native owner")
