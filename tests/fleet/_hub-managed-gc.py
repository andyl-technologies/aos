"""Join genuine Managed R2 inventory and GC with independent observations.

The normal fleet controller supplies actual API, SELECT-only SQL, transport
captures, same-R2 SDK observations and persisted provider/guard reads. This
module neither installs provider authority nor calls R2 DELETE. OCI-only SDK
acceptance is a separate prerequisite and never substitutes for a Delete probe.

The observer contract is a complete bounded set of scoped request brackets
and ``calls`` with unique
``callId``, ``method``, ``key`` and actual ``result``. Independent snapshots name
the same ``backingIdentity`` and contain ``objects[key]`` plus
``guards[key]`` (``deleteReceipts``, ``pendingDelete``, ``pendingMutation``).
Those values come from pinned mf.getR2Bucket and persisted Durable Object KV,
not initialized Worker counters. The helper validates joins; it does not attest
the provenance of a caller-created dictionary.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import time


spec = importlib.util.spec_from_file_location(
    "managed_gc_inventory", Path(__file__).with_name("_hub-inventory-gc.py"))
inventory_gc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory_gc)
require = inventory_gc.require


def prepare_managed_registry(controls, organization, name, trust_keys, prefix, label):
    """Create, scan and promote a real explicit deployment_r2 placement."""
    require(trust_keys and all(isinstance(key, str) and key for key in trust_keys),
            "managed registry requires actual publisher trust anchors")
    require(isinstance(prefix, str) and 0 < len(prefix.encode()) <= 512
            and all(part not in {"", ".", ".."} for part in prefix.split("/")),
            "managed fixture prefix is not an exact nonempty placement prefix")
    binding = controls.call("BindingService", "GetBinding", {
        "binding": {"instanceDefault": True},
    })["binding"]
    require("deploymentR2" in binding["spec"] and binding["ownerScopeKey"] == "instance",
            "actual default binding is not deployment-owned R2")
    registry = controls.reviewed("RegistryService", "PlanCreateRegistry", "CreateRegistry", {
        "orgSlug": organization["slug"], "projectPath": "", "name": name,
        "visibility": "private", "trustKeys": trust_keys, "expectedResourceVersion": "",
    }, label + "-registry")["registry"]
    surface = {"registrySlug": registry["slug"]}
    existing = controls.call("TopologyService", "ListPlacements", {
        "surface": surface, "pageSize": 2,
    })
    require(not existing.get("placements") and not existing.get("nextPageToken"),
            "new registry already has placements; do not silently replace topology")
    placement_name = "managed-gc"
    controls.reviewed("TopologyService", "PlanCreatePlacement", "CreatePlacement", {
        "surface": surface, "name": placement_name, "bindingId": binding["stableId"],
        "prefix": prefix, "kind": "complete", "desiredState": "active",
        "desiredReadEnabled": True, "readOrder": "0", "requiresConditionalWrites": True,
        "expectedResourceVersion": "",
    }, label + "-placement")
    placement = controls.call("TopologyService", "GetPlacement", {
        "surface": surface, "name": placement_name,
    })["placement"]
    scan = controls.reviewed("TopologyService", "PlanScanPlacement", "ScanPlacement", {
        "surface": surface, "placementName": placement_name,
        "expectedResourceVersion": placement["resourceVersion"],
    }, label + "-scan")["operation"]
    scan_result = controls.wait_operation(scan["operationId"], {"succeeded"})
    placement = controls.call("TopologyService", "GetPlacement", {
        "surface": surface, "name": placement_name,
    })["placement"]
    require(placement["prefix"] == prefix and placement["observation"]["state"] == "ready"
            and placement["observation"]["completeness"] == "complete",
            "actual managed scan did not establish the selected namespace")
    controls.reviewed("TopologyService", "PlanPromotePlacement", "PromotePlacement", {
        "surface": surface, "placementName": placement_name,
        "expectedResourceVersion": placement["resourceVersion"],
    }, label + "-promote")
    deadline = time.monotonic() + 120
    while True:
        authority = controls.call("TopologyService", "GetWriteAuthority", {
            "surface": surface,
        })["authority"]
        if authority["reconciliationState"] == "ready":
            break
        require(authority["reconciliationState"] != "failed" and time.monotonic() < deadline,
                "managed writer reconciliation did not complete")
        time.sleep(0.5)
    require(authority["desiredPlacementName"] == placement_name
            and authority["observedPlacementName"] == placement_name
            and authority["desiredGeneration"] == authority["observedGeneration"]
            and authority["desiredBindingWriteRevision"] == authority["observedBindingWriteRevision"],
            "actual managed writer selected another placement or revision")
    placement = controls.call("TopologyService", "GetPlacement", {
        "surface": surface, "name": placement_name,
    })["placement"]
    require(placement["status"]["observedWriter"] is True
            and placement["status"]["effectiveWriteEnabled"] is True,
            "actual managed placement is not the effective writer")
    return {"registry": registry, "binding": binding, "placement": placement,
            "authority": authority, "scan": scan_result}


def set_fixture_retention(controls, registry, label):
    """Set real retention policy without dropping mandatory live roots."""
    current = controls.call("ContainerService", "GetContainerRetentionPolicy", {
        "registry": registry,
    })["policy"]
    return controls.reviewed("ContainerService", "PlanSetContainerRetentionPolicy",
                             "SetContainerRetentionPolicy", {
        "registry": registry, "expectedResourceVersion": current["resourceVersion"],
        "policy": {"registry": registry, "untaggedGracePeriodSecs": "0",
                   "deletedTagHistoryPeriodSecs": "0", "recentManualTagRevisions": 0,
                   "retainReferrers": True},
    }, label + "-retention")["policy"]


def managed_capability_sql(binding_id):
    """Read one separately probed current Managed Delete capability."""
    require(type(binding_id) is int and binding_id > 0, "binding SQL selector differs")
    return f"""
        SELECT capability.*, binding.kind, writer.current_write_revision
        FROM oci_conditional_delete_capabilities capability
        JOIN bindings binding ON binding.id = capability.binding_id
        JOIN binding_write_state writer ON writer.binding_id = binding.id
        WHERE binding.id = {binding_id} AND binding.kind = 'deployment_r2'
          AND capability.binding_resource_version = binding.resource_version
          AND capability.binding_write_revision = writer.current_write_revision
          AND capability.state = 'valid'
          AND capability.delete_credential_purpose IS NULL
          AND capability.delete_credential_generation IS NULL
        LIMIT 1
    """


def require_managed_inventory(inventory, capability, pins):
    """Require current hashed inventory and genuine credential-free Delete proof."""
    require(inventory["state"] == "complete" and inventory["object_count"] > 0
            and inventory["page_count"] > 0 and inventory["hash_count"] == inventory["object_count"]
            and inventory["nonversioned_count"] == 0
            and re.fullmatch(r"sha256:[0-9a-f]{64}", inventory["inventory_digest"] or ""),
            "managed inventory is incomplete, unhashed or lacks actual R2 upload versions")
    for field in ("registry_id", "placement_id", "captured_mutation_epoch",
                  "placement_resource_version", "placement_write_spec_version",
                  "placement_observation_version", "binding_id", "binding_resource_version",
                  "binding_write_revision"):
        require(inventory[field] == pins[field], "managed inventory pin differs: " + field)
    require(capability["kind"] == "deployment_r2" and capability["state"] == "valid"
            and capability["delete_credential_purpose"] is None
            and capability["delete_credential_generation"] is None
            and capability["binding_id"] == pins["binding_id"]
            and capability["binding_resource_version"] == pins["binding_resource_version"]
            and capability["binding_write_revision"] == pins["binding_write_revision"]
            and capability["current_write_revision"] == pins["binding_write_revision"]
            and capability["capability_fingerprint"] and capability["resource_version"] > 0,
            "OCI acceptance or External credential is not a Managed Delete capability")


def action_evidence_sql(run_id):
    """Read at most 128 genuine frozen actions and acknowledged SQL evidence."""
    require(isinstance(run_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", run_id),
            "run SQL selector differs")
    return f"""
        SELECT action.*, snapshot.placement_prefix, snapshot.placement_resource_version,
               snapshot.placement_write_spec_version, snapshot.placement_observation_version,
               snapshot.binding_id, snapshot.binding_resource_version,
               snapshot.binding_write_revision, snapshot.delete_credential_purpose,
               snapshot.delete_credential_generation, snapshot.delete_capability_fingerprint,
               snapshot.delete_capability_resource_version, snapshot.inventory_digest,
               evidence.response_idempotency_key, evidence.outcome AS deletion_outcome,
               evidence.conditional_etag, evidence.provider_request_id,
               evidence.evidence_digest, evidence.confirmed_at AS evidence_confirmed_at
        FROM oci_gc_placement_actions action
        JOIN oci_gc_placement_snapshots snapshot
          ON snapshot.run_id = action.run_id AND snapshot.placement_id = action.placement_id
        JOIN oci_gc_deletion_evidence evidence ON evidence.action_id = action.id
        WHERE action.run_id = '{run_id}'
        ORDER BY action.id LIMIT 128
    """


def complete_calls(window):
    """Require closed actual scoped requests, not a preinitialized zero counter."""
    require(window["coverage"] == "scoped_requests_complete" and isinstance(window["calls"], list)
            and len(window["calls"]) <= 4096
            and re.fullmatch(r"[0-9a-f]{64}", window["backingIdentity"] or ""),
            "managed SDK observation is missing or exceeds its fixture bound")
    require(len(json.dumps(window, separators=(",", ":")).encode()) <= 1024 * 1024,
            "SDK metadata window exceeds its byte bound")
    brackets = window["brackets"]
    require(isinstance(brackets, list) and 0 < len(brackets) <= 64
            and all(bracket["scope"] in {"managed_gc_guard", "managed_inventory_range"}
                    and re.fullmatch(r"[0-9a-f]{32}", bracket["requestId"])
                    and type(bracket["invoked"]) is int and 0 <= bracket["invoked"] <= 32
                    for bracket in brackets)
            and len({bracket["requestId"] for bracket in brackets}) == len(brackets),
            "SDK coverage lacks actual closed matching request brackets")
    for bracket in brackets:
        selected = [call for call in window["calls"] if call["requestId"] == bracket["requestId"]]
        require(len(selected) == bracket["invoked"]
                and all(call["scope"] == bracket["scope"] and call["key"] == bracket["key"]
                        and call["subjectId"] == bracket["subjectId"] for call in selected),
                "SDK bracket call identities or retained subject differ")
    require(all(call["requestId"] in {bracket["requestId"] for bracket in brackets}
                for call in window["calls"]), "SDK call has no closed request bracket")
    ids = [call["callId"] for call in window["calls"]]
    require(all(isinstance(identity, str) and identity for identity in ids)
            and len(ids) == len(set(ids)), "SDK call identities are absent or duplicated")
    sequences = [call["sequence"] for call in window["calls"]]
    require(all(type(sequence) is int and sequence > 0 for sequence in sequences)
            and len(sequences) == len(set(sequences)), "SDK call ordering is absent or duplicated")
    return window["calls"]


def review_managed_gc(controls, registry, policy_version, expected_candidates, retained_roots, label):
    """Review actual reachability and compare exact candidates with published roots."""
    require(expected_candidates and len(expected_candidates) <= 32
            and not set(expected_candidates).intersection(retained_roots),
            "fixture candidates overlap retained roots or exceed the bound")
    planned = inventory_gc.reviewed_gc(controls, registry, policy_version, label + "-plan")
    run_id = planned["run"]["runId"]
    candidates = controls.call("ContainerService", "ListContainerGcCandidates", {
        "registry": registry, "runId": run_id, "pageSize": 128,
    })
    actions = controls.call("ContainerService", "ListContainerGcPlacementActions", {
        "registry": registry, "runId": run_id, "pageSize": 128,
    })
    require(not candidates.get("nextPageToken") and not actions.get("nextPageToken"),
            "fixture review exceeds one bounded page; do not skip candidates or placements")
    actual = [candidate["digest"] for candidate in candidates.get("candidates", [])]
    require(len(actual) == len(set(actual)) and set(actual) == set(expected_candidates)
            and not set(actual).intersection(retained_roots)
            and len(actual) == int(planned["run"]["candidateObjectCount"]),
            "actual retained-root closure or unrooted candidates differ")
    selected = actions.get("actions", [])
    require(0 < len(selected) <= 32 and len(selected) == int(planned["run"]["placementActionCount"])
            and all(action["digest"] in expected_candidates for action in selected),
            "actual review has missing, extra or unbounded physical actions")
    return planned, selected


def refuse_root_change(controls, planned, actions, mutate_root, observer, retain, label):
    """Exercise a real Distribution root mutation after review, before Apply."""
    keys = {action["placementPrefix"] + "/" + action["objectKey"] for action in actions}
    require(0 < len(keys) <= 32, "root-change review has no bounded physical targets")
    token = observer.begin_transport()
    mutation = mutate_root()
    start = len(controls.observations)
    try:
        inventory_gc.apply_reviewed_gc(controls, planned, label + "-apply")
    except RuntimeError:
        pass
    else:
        raise ValueError("changed rooted GC review unexpectedly applied")
    exchanges = controls.observations[start:]
    require(len(exchanges) == 1 and exchanges[0]["outcome"] == "received"
            and exchanges[0]["http_status"] in {400, 403, 404, 409, 412},
            "root-change refusal lacks an actual authoritative API response")
    window = observer.finish_transport(token)
    require(window["coverage"] == "complete_native_storage_requests"
            and isinstance(window["requests"], list) and len(window["requests"]) <= 4096
            and len(json.dumps(window, separators=(",", ":")).encode()) <= 1024 * 1024,
            "root-change refusal lacks actual complete Native storage transport observation")
    require(not any(request["operation"] == "delete_if_matches" and request["key"] in keys
                    for request in window["requests"]),
            "root-change refusal dispatched a guarded deletion plan")
    retain(label, {"plan": planned, "rootMutation": mutation,
                   "controls": exchanges, "transportWindow": window})


def run_managed_gc(controls, registry, planned, actions, observer, read_evidence, retain, label):
    """Apply genuine GC, join each positive, then replay the exact same Apply.

    `read_evidence` returns the bounded SQL projection and captured offered plan
    and consumed result for each action, after the compiled general observer
    checks their actual transport bytes. Missing source/classifier/SQL joins
    must stop the caller; this helper never supplies default proof or counters.
    """
    keys = [action["placementPrefix"] + "/" + action["objectKey"] for action in actions]
    ids = [action["actionId"] for action in actions]
    require(0 < len(keys) <= 32 and len(keys) == len(set(keys)) and len(ids) == len(set(ids)),
            "managed fixture action addresses are absent, duplicate or exceed the bound")
    before = observer.snapshot(keys, ids)
    token = observer.begin()
    apply_key = label + "-apply"
    applied = inventory_gc.apply_reviewed_gc(controls, planned, apply_key)
    deadline = time.monotonic() + 240
    while True:
        completed = controls.call("ContainerService", "GetContainerGcRun", {
            "registry": registry, "runId": planned["run"]["runId"],
        })
        if completed["run"]["state"] == "complete":
            break
        require(completed["run"]["state"] not in {"failed", "blocked"}
                and time.monotonic() < deadline, "actual managed GC did not complete")
        time.sleep(1)
    window = observer.finish(token)
    after = observer.snapshot(keys, ids)
    evidence = read_evidence(planned["run"]["runId"])
    require(len(evidence) == len(ids) and {row["action"]["id"] for row in evidence} == set(ids)
            and int(completed["run"]["deletedObjectCount"]) == int(planned["run"]["candidateObjectCount"]),
            "actual SQL GC completion or captured action set differs")
    joins = [join_managed_deletion(row["action"], row["plan"], row["result"], window, before, after)
             for row in evidence]
    positive_evidence = {"plan": planned, "applied": applied, "completed": completed,
                         "before": before, "after": after, "sdkWindow": window,
                         "evidence": evidence, "joins": joins}
    positive_receipt = retain(label + "-positive", positive_evidence)
    replay = inventory_gc.apply_reviewed_gc(controls, planned, apply_key)
    # API idempotency may return without reaching any physical guard. A distinct
    # private same-guard replay must use the exact actually retained positive
    # claim; it is not permission to submit a missing or changed claim.
    replay_token = observer.begin()
    replay_replies = []
    for key, action_id in zip(keys, ids):
        receipt = after["guards"][key]["deleteReceipts"][action_id]
        replay_replies.append(observer.replay_positive_guard(key, receipt))
    replay_window = observer.finish(replay_token)
    replay_snapshot = observer.snapshot(keys, ids)
    require(replay["operation"]["operationId"] == applied["operation"]["operationId"],
            "exact Apply replay created another operation")
    require_no_redispatch(replay_window, after, replay_snapshot, keys)
    retain(label + "-replay", {"applied": replay, "physicalGuardReplies": replay_replies,
                                "sdkWindow": replay_window, "snapshot": replay_snapshot})
    return {**completed, "actualPositiveEvidence": {"retainedReference": {"file": "external-direct-flow/" + label + "-positive",
            "sha256": positive_receipt, "byteSize": len(json.dumps(positive_evidence,
                sort_keys=True, separators=(",", ":")).encode()) + 1},
        "observations": positive_evidence}}


def join_managed_deletion(action, plan, result, window, before, after):
    """Join an exact SQL action, consumed result, SDK delete and durable receipt.

    The plan/result must also pass the same-source compiled general storage
    observer's authentication and typed body checks. This structural join does
    not replace that observer or establish Native body forwarding measurements.
    """
    calls = complete_calls(window)
    require(before["backingIdentity"] == after["backingIdentity"] == window["backingIdentity"],
            "SDK and persisted-provider observations name different durable stores")
    require(action["state"] == "confirmed_absent" and action["inventory_entry_present"] == 1
            and action["deletion_outcome"] == "deleted"
            and action["delete_credential_purpose"] is None
            and action["delete_credential_generation"] is None,
            "positive managed deletion is not a real present-entry acknowledged action")
    expected = {"claim_id": action["id"], "expected_etag": action["expected_strong_etag"],
                "expected_size": action["expected_size"], "expected_hash": action["expected_hash"],
                "expected_provider_version": action["expected_provider_version"]}
    require(expected["expected_provider_version"] not in {None, "", "null"}
            and expected["expected_etag"] and not expected["expected_etag"].startswith("W/"),
            "frozen Managed claim lacks a real upload version or strong ETag")
    operation = plan["operation"]
    require(plan["binding_kind"] == "deployment_r2"
            and not plan.get("credential_references") and plan.get("binding_snapshot_revision") is None
            and operation["kind"] == "delete_if_matches"
            and operation["path"] == action["object_key"]
            and operation.get("delete_binding_write_revision") is None
            and all(operation[field] == value for field, value in expected.items()),
            "offered DeleteIfMatches differs from the genuine frozen action")
    for field in ("placement_id", "placement_resource_version", "binding_id", "binding_resource_version"):
        require(plan[field] == result[field] == action[field], "consumed current/frozen pin differs: " + field)
    require(plan["placement_prefix"] == action["placement_prefix"]
            and result["plan_id"] == plan["plan_id"]
            and result["source_bytes"] == 0
            and result["outcome"] == {"kind": "object_deleted", "etag": expected["expected_etag"]}
            and action["conditional_etag"] == expected["expected_etag"],
            "consumed reply does not confirm the exact guarded deletion")
    key = action["placement_prefix"] + "/" + action["object_key"]
    identity = before["objects"][key]
    require(identity is not None and identity["version"] == expected["expected_provider_version"]
            and identity["etag"] == expected["expected_etag"] and identity["size"] == expected["expected_size"]
            and after["objects"][key] is None,
            "independent provider state did not change from the exact reviewed incarnation to absence")
    selected_brackets = [bracket for bracket in window["brackets"]
                         if bracket["scope"] == "managed_gc_guard" and bracket["key"] == key
                         and bracket["subjectId"] == action["id"]]
    require(selected_brackets, "actual positive has no matching GC guard request")
    calls = [call for call in calls if call["scope"] == "managed_gc_guard"
             and call["subjectId"] == action["id"] and call["key"] == key]
    deletes = [call for call in calls if call["method"] == "delete"]
    require(len(deletes) == 1 and deletes[0]["result"] == {"kind": "resolved"},
            "actual same-R2 SDK DELETE did not resolve exactly once")
    heads = [call for call in calls if call["method"] == "head" and call["key"] == key
             and call["result"] == identity]
    require(any(head["sequence"] < deletes[0]["sequence"] for head in heads),
            "SDK delete has no preceding exact guarded metadata observation")
    guard = after["guards"][key]
    require(guard["guardName"] == plan["deployment_id"] + ":" + hashlib.sha256(key.encode()).hexdigest(),
            "persisted receipt belongs to another physical-key guard")
    receipt = guard["deleteReceipts"][action["id"]]
    require(receipt == {"claim": expected, "outcome": {
        "kind": "deleted", "etag": expected["expected_etag"]}}
        and guard["pendingDelete"] is None and guard["pendingMutation"] is None,
        "persisted same-key receipt is missing, changed or still unresolved")
    canonical = {"actionId": action["id"], "responseIdempotencyKey": action["response_idempotency_key"],
                 "outcome": "deleted", "conditionalEtag": action["conditional_etag"],
                 "providerRequestId": action["provider_request_id"],
                 "confirmedAt": action["evidence_confirmed_at"]}
    digest = hashlib.sha256(json.dumps(canonical, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    require(action["evidence_digest"] == "sha256:" + digest,
            "SQL success digest differs from its actual acknowledged evidence")
    return {"actionId": action["id"], "key": key, "sdkDeleteCallId": deletes[0]["callId"],
            "r2UploadVersion": identity["version"], "guardReceipt": receipt,
            "sqlEvidenceDigest": action["evidence_digest"]}


def require_no_redispatch(window, original_snapshot, replay_snapshot, keys):
    """Require actual replay to preserve provider state and positive guard bytes."""
    calls = complete_calls(window)
    require(window["backingIdentity"] == original_snapshot["backingIdentity"]
            == replay_snapshot["backingIdentity"], "replay changed the durable R2 backing store")
    require(not any(call["key"] in keys for call in calls),
            "positive physical guard replay redispatched an SDK call")
    for key in keys:
        receipts = original_snapshot["guards"][key]["deleteReceipts"]
        require(receipts and all(receipt is not None for receipt in receipts.values()),
                "physical replay has no actual retained positives")
        for claim_id in receipts:
            require(any(bracket["scope"] == "managed_gc_guard" and bracket["key"] == key
                        and bracket["subjectId"] == claim_id and bracket["invoked"] == 0
                        for bracket in window["brackets"]),
                    "zero replay lacks an actual healthy matching positive guard request")
    for key in keys:
        require(original_snapshot["objects"][key] == replay_snapshot["objects"][key]
                and original_snapshot["guards"][key] == replay_snapshot["guards"][key],
                "replay changed provider incarnation or durable positive/unknown state")
