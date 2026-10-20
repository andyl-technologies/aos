"""Exercise selected authoritative OCI inventory and genuine conditional GC.

This additive helper is invoked by the normal fleet controller only after its
runtime tuple and independent Delete contract have been reviewed. SQL is read
through the existing SELECT-only operator. Provider evidence comes from the
independent observation window, not upload outcomes or initialized counters.
It does not launch an issuer, sign controls, stage secrets or clear journals.
"""

import copy
import hashlib
import re
import time


def require(condition, message):
    """Reject incomplete or unrelated evidence rather than infer a result."""
    if not condition:
        raise ValueError(message)


def current_inventory_sql(registry_id, placement_id):
    """Return a bounded SELECT for the actual current complete inventory head."""
    require(type(registry_id) is int and registry_id > 0
            and type(placement_id) is int and placement_id > 0, "SQL selector IDs differ")
    return f"""
        SELECT generation.id, generation.state, generation.object_count,
               generation.checkpoint_ordinal AS page_count, generation.inventory_digest,
               generation.registry_id, generation.placement_id,
               generation.captured_mutation_epoch,
               generation.placement_resource_version,
               generation.placement_write_spec_version,
               generation.placement_observation_version,
               generation.binding_id, generation.binding_resource_version,
               generation.binding_write_revision,
               (SELECT COUNT(*) FROM oci_provider_inventory_entries entry
                WHERE entry.generation_id = generation.id AND entry.observed_hash IS NOT NULL) AS hash_count,
               (SELECT COUNT(*) FROM oci_provider_inventory_entries entry
                WHERE entry.generation_id = generation.id
                  AND (entry.provider_version IS NULL OR entry.provider_version IN ('', 'null'))) AS nonversioned_count
        FROM oci_provider_inventory_heads head
        JOIN oci_provider_inventory_generations generation ON generation.id = head.generation_id
        JOIN surface_placements placement ON placement.id = head.placement_id
        JOIN surface_placement_observations observation ON observation.placement_id = placement.id
        JOIN bindings binding ON binding.id = placement.binding_id
        JOIN binding_write_state writer ON writer.binding_id = binding.id
        JOIN oci_registry_state registry_state ON registry_state.registry_id = head.registry_id
        WHERE head.registry_id = {registry_id} AND head.placement_id = {placement_id}
          AND generation.state = 'complete'
          AND generation.captured_mutation_epoch = registry_state.mutation_epoch
          AND generation.placement_resource_version = placement.resource_version
          AND generation.placement_write_spec_version = placement.write_spec_version
          AND generation.placement_observation_version = observation.observation_version
          AND generation.binding_resource_version = binding.resource_version
          AND generation.binding_write_revision = writer.current_write_revision
        LIMIT 1
    """


def external_gc_bindings(bootstrap, delete_export, reviewed_evidence_digest,
                         provider_report_bytes, consumer_bindings):
    """Select exact independently exported Delete authority and contract bytes.

    The export is produced by the read-only Rust operator from actual SQL.
    Its cohort is copied verbatim; no Python projection of upload authority is
    accepted. Installing these bindings does not establish probe readiness.
    """
    require(set(delete_export) == {
        "version", "publication", "issuer_installation", "delete_cohort",
    } and delete_export["version"] == 1, "Delete export shape differs")
    require(delete_export["publication"] == bootstrap["publication"]
            and delete_export["issuer_installation"] == bootstrap["issuer_installation"],
            "Delete export differs from the current reviewed SQL/issuer tuple")
    cohort = delete_export["delete_cohort"]
    require(cohort["credential"]["purpose"] == "delete"
            and cohort["allowed_effects"] == ["conditional_delete"]
            and cohort["association"] == bootstrap["write_cohort"]["association"]
            and cohort["admitted_prefix"] == bootstrap["write_cohort"]["admitted_prefix"],
            "Delete selection is not the exact independently narrowed cohort")
    require(isinstance(provider_report_bytes, bytes)
            and 0 < len(provider_report_bytes) <= 4 * 1024 * 1024
            and re.fullmatch(r"[0-9a-f]{64}", reviewed_evidence_digest or "")
            and hashlib.sha256(provider_report_bytes).hexdigest() == reviewed_evidence_digest,
            "independent versioned conditional-delete contract commitment differs")
    selected = copy.deepcopy(consumer_bindings)
    object_config = selected["HUB_EXTERNAL_OBJECT_CONSUMER"]
    require(object_config["publications"] == [delete_export["publication"]],
            "installed publication differs from Delete selection")
    require(cohort not in object_config["cohorts"], "Delete cohort was already installed")
    object_config["cohorts"].append(copy.deepcopy(cohort))
    selected["HUB_EXTERNAL_DELETE_CONSUMER"] = {
        "version": 1, "domains": [{
            "issuer_installation": copy.deepcopy(delete_export["issuer_installation"]),
            "delete_cohort": copy.deepcopy(cohort),
            "versioned_conditional_delete_evidence_digest": reviewed_evidence_digest,
        }],
    }
    return selected


def require_current_inventory(inventory, capability, pins):
    """Require actual complete hashed inventory and separately probed Delete.

    These dictionaries are projections of retained SQL, never inserted by this
    helper. Callers retain the SQL text, bounded row bytes and observation time.
    """
    require(inventory["state"] == "complete" and inventory["object_count"] > 0
            and inventory["page_count"] > 0 and inventory["hash_count"] == inventory["object_count"]
            and inventory["nonversioned_count"] == 0,
            "authoritative inventory lacks complete hashes or immutable versions")
    for name in ("registry_id", "placement_id", "captured_mutation_epoch",
                 "placement_resource_version", "placement_write_spec_version",
                 "placement_observation_version", "binding_id",
                 "binding_resource_version", "binding_write_revision"):
        require(inventory[name] == pins[name], "inventory current pin differs: " + name)
    require(capability["state"] == "valid"
            and capability["delete_credential_purpose"] == "delete"
            and capability["delete_credential_generation"] == pins["delete_credential_generation"]
            and capability["binding_id"] == pins["binding_id"]
            and capability["binding_resource_version"] == pins["binding_resource_version"]
            and capability["binding_write_revision"] == pins["binding_write_revision"],
            "current independent conditional-delete probe is absent or unsupported")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", inventory["inventory_digest"] or ""),
            "complete inventory commitment absent")


def reviewed_gc(controls, registry, policy_version, idempotency_key):
    """Obtain the server's actual actor-bound original; do not manufacture it."""
    planned = controls.call("ContainerService", "PlanRunContainerGc", {
        "registry": registry, "expectedResourceVersion": str(policy_version),
        "idempotencyKey": idempotency_key,
    })
    require(not planned.get("blockers"), "actual GC review has blockers")
    require(planned["plan"]["planId"] and planned["plan"]["confirmationHash"]
            and int(planned["run"]["candidateObjectCount"]) > 0
            and int(planned["run"]["placementActionCount"]) > 0,
            "actual GC review contains no physical deletion original")
    return planned


def apply_reviewed_gc(controls, planned, idempotency_key):
    """Apply only the exact server-returned original and confirmation."""
    return controls.call("ContainerService", "RunContainerGc", {
        "planId": planned["plan"]["planId"],
        "confirmationHash": planned["plan"]["confirmationHash"],
        "idempotencyKey": idempotency_key,
    })


def refuse_changed_review(controls, planned, mutate, provider_window, retain, label):
    """Exercise a genuine root/topology mutation between review and deletion.

    `mutate` performs the selected authenticated API operation. The provider
    collector must return actual received requests for the bounded window; an
    empty fabricated counter is not evidence. Native bulk accounting is a
    separate shared-codec transport join and is deliberately not inferred here.
    """
    before = provider_window.begin()
    mutation = mutate()
    start = len(controls.observations)
    try:
        apply_reviewed_gc(controls, planned, label + "-apply")
    except RuntimeError:
        pass
    else:
        raise ValueError("changed GC review unexpectedly applied")
    exchanges = controls.observations[start:]
    require(len(exchanges) == 1 and exchanges[0]["outcome"] == "received"
            and exchanges[0]["http_status"] in {400, 403, 404, 409, 412},
            "GC refusal was not an actual bounded API response")
    observed = provider_window.finish(before)
    require(observed["coverage"] == "complete" and observed["requests"] is not None,
            "provider refusal observation window is incomplete")
    require(not any(row["method"] == "DELETE" for row in observed["requests"]),
            "changed review dispatched a provider deletion")
    retain(label, {"plan": planned, "mutation": mutation, "controls": exchanges,
                   "providerWindow": observed, "scope": "actual changed-review refusal"})


def run_positive_gc(controls, registry, planned, provider_window, join_deletions,
                    retain, label, timeout=240):
    """Require real SQL completion plus independently joined exact deletions.

    `join_deletions` uses the shared receipt classifier and actual original,
    claim, offered/received provider bodies and exact-version absence reads.
    Missing semantic joins remain unknown and cannot satisfy this gate.
    """
    before = provider_window.begin()
    applied = apply_reviewed_gc(controls, planned, label + "-apply")
    run_id = planned["run"]["runId"]
    deadline = time.monotonic() + timeout
    while True:
        status = controls.call("ContainerService", "GetContainerGcRun", {
            "registry": registry, "runId": run_id,
        })
        if status["run"]["state"] == "complete":
            break
        require(status["run"]["state"] not in {"failed", "blocked"}, "actual GC failed")
        require(time.monotonic() < deadline, "actual GC did not complete within its fixture bound")
        time.sleep(1)
    require(int(status["run"]["deletedObjectCount"]) == int(planned["run"]["candidateObjectCount"]),
            "actual GC completion did not finalize the reviewed candidates")
    observed = provider_window.finish(before)
    joined = join_deletions(run_id, observed)
    require(observed["coverage"] == "complete" and len(joined) == int(planned["run"]["placementActionCount"]),
            "independent deletion joins are incomplete")
    for deletion in joined:
        require(all(re.fullmatch(r"[0-9a-f]{64}", deletion[name] or "") for name in
                    ("originalDigest", "claimDigest", "matchedPositiveReceiptDigest"))
                and deletion["providerVersion"] not in {None, "", "null"}
                and deletion["strongEtag"] and deletion["matchedConditionalRequestId"]
                and deletion["exactVersionAbsenceRequestId"],
                "a finalized action lacks exact conditional original/receipt/absence evidence")
    retain(label, {"plan": planned, "applied": applied, "completed": status,
                   "providerWindow": observed, "deletions": joined,
                   "scope": "actual conditional GC; Native body accounting reported separately"})
    return status
