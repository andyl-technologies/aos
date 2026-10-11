"""Associate exact decoded Mirror calls with actual completed destinations.

These current SQL joins and retained signed source rows do not reconstruct an
older claim or verify a transport MAC. Complete body consumption and checked
Native authentication remain separate mandatory evidence dimensions.
"""

import hashlib
import json


MIRROR_WORK_OPERATIONS = frozenset(("mirror_transfer", "mirror_transfer_batch_v1",
    "inspect_mirror_pack_v1", "inspect_mirror_live_metadata_v1",
    "inspect_mirror_live_metadata_batch_v1", "inspect_mirror_membership_v1",
    "inspect_mirror_tree_inventory_v1"))
MIRROR_GUARD_OPERATIONS = frozenset(("mirror_guard", "mirror_guard_batch"))
MIRROR_WORK_PATH = "/_internal/storage/v1/execute"
MIRROR_GUARD_PATHS = {
    "mirror_guard": frozenset(("/_internal/storage/mirror-final-guard",
        "/__hub/external-mirror-functional-guard")),
    "mirror_guard_batch": frozenset(("/_internal/storage/mirror-final-guard-batch",
        "/__hub/external-mirror-functional-guard-batch")),
}


def mirror_request_sources(request, operation):
    """Select only the shared decoder's known exact Mirror request branches."""
    if operation == "mirror_guard":
        return [request["original"]]
    if operation == "mirror_guard_batch":
        return [item["original"] for item in request["items"]]
    selected = request["operation"]
    wire = {"mirror_transfer": "mirror_transfer", "mirror_transfer_batch_v1": "mirror_transfer_batch",
        "inspect_mirror_pack_v1": "inspect_mirror_pack", "inspect_mirror_live_metadata_v1": "inspect_mirror_live_metadata",
        "inspect_mirror_live_metadata_batch_v1": "inspect_mirror_live_metadata_batch",
        "inspect_mirror_membership_v1": "inspect_mirror_membership",
        "inspect_mirror_tree_inventory_v1": "inspect_mirror_tree_inventory"}
    if selected["kind"] != wire.get(operation):
        raise ValueError("Mirror decoded operation differs from its retained request")
    if operation == "mirror_transfer":
        return [selected["original"]]
    if operation == "mirror_transfer_batch_v1":
        return [item["original"] for item in selected["items"]]
    if operation == "inspect_mirror_pack_v1":
        return [selected["inspection"]]
    if operation == "inspect_mirror_live_metadata_v1":
        return [selected["target"]]
    if operation == "inspect_mirror_live_metadata_batch_v1":
        return selected["targets"]
    if operation == "inspect_mirror_membership_v1":
        return [selected["query"]["inspection"]]
    if operation == "inspect_mirror_tree_inventory_v1":
        source = selected["query"]["source"]
        if source["kind"] == "pack":
            return [source["inspection"]]
        if source["kind"] == "loose":
            return [source]
    raise ValueError("Mirror original source remains unsupported")


def join_mirror_source_current(source, cases, profile_digest):
    """Join known pins to independent current SQL without issuing authority."""
    def field(snake, camel):
        return source[snake] if snake in source else source[camel]
    registry_id = field("registry_id", "registryId")
    matches = [case for case in cases.values()
        if int(case["effects"]["sql"]["value"]["registry"]["id"]) == int(registry_id)]
    if len(matches) != 1:
        raise ValueError("Mirror request selects an unknown or ambiguous actual registry")
    case = matches[0]
    rows = case["effects"]["sql"]["value"]
    for snake, camel, actual in (("registry_resource_version", "registryResourceVersion", rows["registry"]["resource_version"]),
            ("mirror_resource_version", "mirrorResourceVersion", rows["mirror"]["resource_version"])):
        if int(field(snake, camel)) != int(actual):
            raise ValueError("Mirror original current registry or source version changed")
    if (field("upstream_base", "upstreamBase") != case["selection"]["upstream"]
            or field("protected_profile_digest", "protectedProfileDigest") != profile_digest):
        raise ValueError("Mirror source differs from its actual installed profile or upstream")
    if "placement_id" in source:
        for name, value in (("placement_id", rows["placement"]["id"]),
                ("placement_resource_version", rows["placement"]["resource_version"]),
                ("write_spec_version", rows["placement"]["write_spec_version"]),
                ("binding_id", rows["binding"]["id"]),
                ("binding_resource_version", rows["binding"]["resource_version"])):
            if int(source[name]) != int(value):
                raise ValueError("Mirror original current placement or binding changed")
        if source["placement_prefix"] != case["selection"]["placementPrefix"]:
            raise ValueError("Mirror original crossed its actual reserved destination")
    raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    return {"originalSha256": hashlib.sha256(raw).hexdigest(),
        "currentSqlReceipt": case["effects"]["sql"]["receipt"],
        "registryId": str(registry_id), "profileDigest": profile_digest,
        "scope": "retained completed current destination association; not past permission"}


def mirror_current_query(case):
    """Select only one actual destination's current metadata, without writes."""
    selected = case["selection"]
    identifier = int(case["configuration"]["registryId"])
    if identifier <= 0:
        raise ValueError("Mirror current SQL registry is invalid")
    return (
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='20s'; "
        "SELECT json_build_object('registry',row_to_json(r),'mirror',row_to_json(m),"
        "'placement',row_to_json(p),'binding',json_build_object('id',b.id,'stable_id',b.stable_id,"
        "'resource_version',b.resource_version),'authority',row_to_json(w)) "
        "FROM registries r JOIN mirror_sources m ON m.registry_id=r.id "
        "JOIN surface_placements p ON p.registry_id=r.id JOIN bindings b ON b.id=p.binding_id "
        "JOIN surface_write_authorities w ON w.registry_id=r.id "
        "WHERE r.id=" + str(identifier) + " AND p.id="
        + str(int(case["effects"]["sql"]["value"]["placement"]["id"])) + "; COMMIT;"
    )
