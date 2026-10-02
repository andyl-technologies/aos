"""Exercise reviewed replication and repair against actual missing inventories.

Each target is a new prefix on the source's genuine External binding. The
controller's scan and per-object presence records establish completeness;
HTTP success alone never establishes a copy or a Native bulk-byte result.
"""

import json
import re
import base64


def external_copy_catalog(rows):
    """Validate a bounded, ordered observation of the actual logical catalogue."""
    if not rows or len(rows) > 512:
        raise ValueError("copy fixture requires a nonempty bounded logical catalogue")
    previous = None
    for row in rows:
        if set(row) != {"path", "sha256", "byteSize"}:
            raise ValueError("actual copy catalogue row shape differs")
        path = row["path"]
        if (not isinstance(path, str) or len(path.encode()) > 512
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or previous is not None and path <= previous
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                or type(row["byteSize"]) is not int or row["byteSize"] < 0):
            raise ValueError("actual copy catalogue identity or ordering differs")
        previous = path
    return rows


def _catalogue_digest(value):
    if not isinstance(value, str):
        raise ValueError("actual catalogue lacks a trusted SHA-256")
    if value.startswith("sha256-"):
        raw = base64.b64decode(value[7:], validate=True)
        if len(raw) != 32:
            raise ValueError("actual catalogue SHA-256 has another size")
        return raw.hex()
    text = value[7:] if value.startswith("sha256:") else value
    if not re.fullmatch(r"[0-9a-fA-F]{64}", text):
        raise ValueError("actual catalogue SHA-256 is malformed")
    return text.lower()


def observe_external_copy_catalog(read_sql, registry, source_commit, label):
    """Retain a complete small catalogue from the actual selected read-only DB.

    read_sql(sql, label) must retain bounded raw JSON and actual database/process
    pins, returning {value, receipt}. The supplied SQL owns one repeatable-read,
    read-only transaction. No database URL or unretained host command is used.
    """
    selected = registry["registry"]
    slug, stable = selected["slug"], selected["stableId"]
    if (not re.fullmatch(r"[a-z][a-z0-9-]*/[a-z][a-z0-9-]*", slug)
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,255}", stable)
            or not re.fullmatch(r"[0-9a-f]{64}", source_commit)):
        raise ValueError("copy SQL observation lacks exact registry/source identity")
    query = (
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
        "SELECT json_build_object('registry', row_to_json(r), 'indexed', row_to_json(i), "
        "'objects', (SELECT COALESCE(json_agg(row_to_json(o)), '[]') FROM ("
        "SELECT object.id, object.object_key AS path, object.content_hash AS digest, "
        "object.size, object.resource_version FROM surface_objects object "
        "WHERE object.registry_id = r.id AND object.cache_id IS NULL "
        "AND object.lifecycle_state = 'active' ORDER BY object.object_key LIMIT 513) o)) "
        "FROM registries r JOIN registry_index i ON i.registry_id = r.id "
        "WHERE r.slug = '" + slug + "' AND r.stable_id = '" + stable + "' "
        "AND i.state = 'fresh' AND i.last_indexed_commit = '" + source_commit + "'; COMMIT;"
    )
    observed = read_sql(query, label)
    if set(observed) != {"value", "receipt"} or not observed["receipt"]:
        raise ValueError("copy SQL lacks the actual retained read-only receipt")
    value = observed["value"]
    if (not isinstance(value, dict) or set(value) != {"registry", "indexed", "objects"}
            or value["registry"]["stable_id"] != stable or value["registry"]["slug"] != slug
            or value["indexed"]["registry_id"] != value["registry"]["id"]
            or value["indexed"]["state"] != "fresh"
            or value["indexed"]["last_indexed_commit"] != source_commit):
        raise ValueError("copy SQL belongs to another or stale registry/index")
    if len(json.dumps(value, separators=(",", ":")).encode()) > 1024 * 1024:
        raise ValueError("actual copy catalogue exceeds its byte bound")
    rows = [{"path": row["path"], "sha256": _catalogue_digest(row["digest"]),
             "byteSize": row["size"]} for row in value["objects"]]
    external_copy_catalog(rows)
    for row in value["objects"]:
        if type(row["id"]) is not int or row["id"] <= 0 or row["resource_version"] <= 0:
            raise ValueError("copy SQL lacks the exact active object identity/version")
    return {"version": 1, "registrySlug": slug, "registryStableId": stable,
            "sourceCommit": source_commit, "objects": rows, "sql": value,
            "receipt": observed["receipt"]}


def require_external_copy_presence(reply, objects, source, destination, *, copied):
    """Match actual source and target presence to the observed logical catalogue."""
    if len(reply) != len(objects):
        raise ValueError("actual copy presence replies are incomplete")
    for expected, observation in zip(objects, reply):
        if observation.get("nextPageToken"):
            raise ValueError("copy fixture presence page exceeded its bounded placement count")
        presences = observation.get("presences", [])
        selected = {row["placementName"]: row for row in presences}
        if len(selected) != len(presences) or not {source, destination}.issubset(selected):
            raise ValueError("actual copy presence lacks the selected source or destination")
        for name in (source, destination):
            row = selected[name]
            if row["objectRef"] != expected["path"]:
                raise ValueError("actual copy presence belongs to another object")
            if name == destination and not copied:
                if row["state"] != "missing":
                    raise ValueError("repair or replicate target is not genuinely missing the source")
            elif (row["state"] != "present"
                    or row["contentDigest"] not in {expected["sha256"], "sha256:" + expected["sha256"]}
                    or int(row["size"]) != expected["byteSize"]):
                raise ValueError("actual copied object lacks matching full inventory evidence")


def require_external_copy_operation(detail, kind, source, destination, object_count):
    """Require the completed original's actual copy and final inventory counters."""
    operation = detail["operation"]
    facts = json.loads(detail["detailJson"])
    if (operation["kind"] != kind + "_placement" or operation["state"] != "succeeded"
            or facts["phase"] != "complete" or facts["catalogObjects"] != object_count
            or facts["missingObjects"] != 0 or facts["corruptObjects"] != 0
            or facts["copy"]["source"] != source
            or facts["copy"]["destination"] != destination
            or facts["copy"]["copiedObjects"] < object_count
            or facts["copy"]["copiedBytes"] <= 0):
        raise ValueError("actual controller did not copy and verify the selected missing catalogue")
    return facts


def run_external_placement_copy(controls, registry, binding, catalogue_observation, *,
                                run_id, retain, read_sql):
    """Run both real workflows on a small already published signed registry."""
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise ValueError("copy workflow requires the actual canonical fresh run")
    objects = external_copy_catalog(catalogue_observation["objects"])
    initial = observe_external_copy_catalog(read_sql, registry,
        catalogue_observation["sourceCommit"], "copy-" + run_id + "-initial-catalogue")
    if initial["sql"] != catalogue_observation["sql"]:
        raise ValueError("copy catalogue changed before the actual workflow")
    surface = {"registrySlug": registry["registry"]["slug"]}
    source = controls.call("TopologyService", "GetPlacement", {
        "surface": surface, "name": registry["placement"]["name"],
    })["placement"]
    if source["observation"]["completeness"] != "complete":
        raise ValueError("copy source lacks actual complete authoritative inventory")
    binding_prefix = binding["spec"]["s3"]["prefix"].rstrip("/")
    if (source["bindingName"] != binding["spec"]["name"]
            or not source["prefix"].startswith(binding_prefix + "/")):
        raise ValueError("copy source is outside the actual selected External binding")
    results = {}
    for kind in ("replicate", "repair"):
        name = "copy-" + run_id[:12] + "-" + kind
        label = "copy-" + run_id + "-" + kind
        prefix = source["prefix"] + "-" + kind + "-" + run_id
        controls.reviewed("TopologyService", "PlanCreatePlacement", "CreatePlacement", {
            "surface": surface, "name": name, "bindingId": binding["stableId"],
            "prefix": prefix, "kind": "complete", "desiredState": "active",
            "desiredReadEnabled": True, "readOrder": "10", "requiresConditionalWrites": False,
            "expectedResourceVersion": "",
        }, label + "-target")
        target = controls.call("TopologyService", "GetPlacement", {
            "surface": surface, "name": name,
        })["placement"]
        if (target["bindingName"] != source["bindingName"] or target["prefix"] != prefix
                or target["prefix"] == source["prefix"]):
            raise ValueError("actual target is not a different prefix on the same binding")
        scan = controls.reviewed("TopologyService", "PlanScanPlacement", "ScanPlacement", {
            "surface": surface, "placementName": name,
            "expectedResourceVersion": target["resourceVersion"],
        }, label + "-scan")["operation"]
        missing_scan = controls.wait_operation(scan["operationId"], {"succeeded"})
        missing_facts = json.loads(missing_scan["detailJson"])
        if (missing_facts["catalogObjects"] != len(objects)
                or missing_facts["missingObjects"] != len(objects)):
            raise ValueError("fresh destination scan did not observe the genuine missing catalogue")

        def presence():
            return [controls.call("TopologyService", "ListObjectPresence", {
                "surface": surface, "objectRef": row["path"], "pageSize": 16,
            }) for row in objects]

        before = presence()
        require_external_copy_presence(before, objects, source["name"], name, copied=False)
        target = controls.call("TopologyService", "GetPlacement", {
            "surface": surface, "name": name,
        })["placement"]
        if target["observation"]["completeness"] != "partial":
            raise ValueError("actual scanned copy destination is not incomplete")
        request = {"surface": surface, "sourcePlacementName": source["name"],
            "expectedResourceVersion": target["resourceVersion"]}
        request["destinationPlacementName" if kind == "replicate" else "placementName"] = name
        method = "ReplicatePlacement" if kind == "replicate" else "RepairPlacement"
        plan = controls.call("TopologyService", "Plan" + method, {
            **request, "idempotencyKey": label + "-plan",
        })["plan"]
        if not plan["effects"] or not plan["planId"] or not plan["confirmationHash"]:
            raise ValueError("actual copy review plan is incomplete")
        apply = {"planId": plan["planId"], "confirmationHash": plan["confirmationHash"],
            "idempotencyKey": label + "-apply"}
        original = controls.call("TopologyService", method, apply)["operation"]
        completed = controls.wait_operation(original["operationId"], {"succeeded"}, timeout=300)
        facts = require_external_copy_operation(completed, kind, source["name"], name, len(objects))
        after = presence()
        require_external_copy_presence(after, objects, source["name"], name, copied=True)
        replay = controls.call("TopologyService", method, apply)["operation"]
        if replay["operationId"] != original["operationId"]:
            raise ValueError("exact reviewed copy replay allocated another operation")
        results[kind] = {"plan": plan, "apply": apply, "original": original,
            "missingScan": missing_scan, "presenceBefore": before, "completed": completed,
            "controllerFacts": facts, "presenceAfter": after, "replayedOriginal": replay,
            "nativeBulkBytes": None, "replayProviderDispatches": None,
            "scope": "actual API/controller full inventory; independent body and provider joins remain required"}
        latest = observe_external_copy_catalog(read_sql, registry,
            catalogue_observation["sourceCommit"], label + "-final-catalogue")
        if latest["sql"] != catalogue_observation["sql"]:
            raise ValueError("copy logical catalogue or index changed during the workflow")
        results[kind]["catalogueAfter"] = latest
        retain(label, results[kind])
    return {"version": 1, "catalogueBefore": initial, "workflows": results}
