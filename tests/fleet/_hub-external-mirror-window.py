"""Call public Mirror controls and join completed work to retained signed bytes.

The controlled External purpose producer is a required input to this fixture.
Its artifact and installed process observations belong to the producer's closed
validator. This caller never converts a queued operation or task registration
into successful synchronization, and never supplies provider authority itself.
"""

import re
import time


MIRROR_SERVICE = "RegistryMirrorService"
MIRROR_MODES = {"full": 1, "pull_through": 2}
MAX_MIRROR_OBJECTS = 4096
MAX_MIRROR_OBJECT_BYTES = 512 * 1024 * 1024
MAX_MIRROR_SURFACE_BYTES = 1024 * 1024 * 1024


def mirror_selection(registry, upstream, run_id, mode, *, frontier, source_commit, binding):
    """Pin a real registry, signed upstream and distinct controlled namespace."""
    if (mode not in MIRROR_MODES or not re.fullmatch(r"[0-9a-f]{32}", run_id)
            or not re.fullmatch(r"[0-9a-f]{64}", source_commit)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", frontier)):
        raise ValueError("Mirror selection lacks its signed source and mode")
    expected_upstream = "https://aos.fleet.test:4778/fleet-mirror/" + run_id
    if upstream != expected_upstream:
        raise ValueError("Mirror upstream leaves its selected local TLS surface")
    selected = registry["registry"]
    placement = registry["placement"]
    if (not re.fullmatch(r"[a-z][a-z0-9-]*/[a-z][a-z0-9-]*", selected["slug"])
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,255}", selected["stableId"])
            or not selected.get("trustKeys")
            or placement["prefix"] != ".aos-mirror-qualification/" + run_id + "/final/"
                + ("full" if mode == "full" else "pull-through")
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,255}", binding.get("stableId", ""))
            or placement.get("bindingName") != binding["spec"]["name"]
            or not re.fullmatch(r"[1-9][0-9]*", str(binding.get("resourceVersion", "")))
            or not re.fullmatch(r"[1-9][0-9]*", str(placement.get("resourceVersion", "")))
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,79}", placement.get("name", ""))):
        raise ValueError("Mirror destination differs from its actual admitted namespace")
    return {"registrySlug": selected["slug"], "registryStableId": selected["stableId"],
        "placementName": placement["name"], "placementPrefix": placement["prefix"],
        "bindingStableId": binding["stableId"], "bindingResourceVersion": binding["resourceVersion"],
        "placementResourceVersion": placement["resourceVersion"], "trustKeys": selected["trustKeys"],
        "upstream": upstream, "runId": run_id,
        "mode": mode, "sourceCommit": source_commit, "frontier": frontier}


def mirror_desired(selection):
    """Select required signatures and the actual controller's full cadence."""
    return {"sourceUrl": selection["upstream"], "refspec": "refs/*",
        "authSecretRef": "", "intervalSeconds": "60" if selection["mode"] == "full" else "0",
        "signaturePolicy": "required", "mode": MIRROR_MODES[selection["mode"]]}


def require_mirror_configuration(mirror, selection, resource_version=None):
    """Refuse changes in the actual API configuration during an observation."""
    expected = mirror_desired(selection)
    for field in ("sourceUrl", "refspec", "authSecretRef", "signaturePolicy", "mode"):
        # Protobuf omits an empty string in some responses. It does not turn a
        # missing nonempty selection into an accepted configuration.
        actual = mirror.get(field, "") if field == "authSecretRef" else mirror.get(field)
        if actual != expected[field]:
            raise ValueError("Current Mirror configuration changed " + field)
    if (str(mirror.get("intervalSeconds", 0)) != expected["intervalSeconds"]
            or not re.fullmatch(r"[1-9][0-9]*", str(mirror.get("registryId", "")))
            or not re.fullmatch(r"[1-9][0-9]*", str(mirror.get("resourceVersion", "")))
            or resource_version is not None and str(mirror["resourceVersion"]) != str(resource_version)):
        raise ValueError("Current Mirror identity, cadence or version changed")
    return mirror


def configure_external_mirror(controls, selection, label):
    """Apply and reopen the exact server-reviewed public Mirror configuration."""
    result = controls.reviewed(MIRROR_SERVICE, "PlanSetRegistryMirror", "SetRegistryMirror", {
        "registryId": selection["registrySlug"], "desired": mirror_desired(selection),
        "expectedResourceVersion": "0", "updateMask": [],
    }, label + "-set")
    configured = require_mirror_configuration(result["mirror"], selection)
    current = controls.call(MIRROR_SERVICE, "GetRegistryMirror", {
        "registryId": selection["registrySlug"],
    })["mirror"]
    require_mirror_configuration(current, selection, configured["resourceVersion"])
    if current["registryId"] != configured["registryId"]:
        raise ValueError("Mirror Get selected another actual registry")
    return current


def enqueue_external_mirror_sync(controls, selection, configured, label):
    """Retain the real queued acknowledgement independently from completion."""
    require_mirror_configuration(configured, selection)
    if selection["mode"] != "full":
        raise ValueError("Pull-through mirrors require an actual demand read")
    result = controls.reviewed(MIRROR_SERVICE, "PlanSyncRegistryMirror", "SyncRegistryMirror", {
        "registryId": selection["registrySlug"],
        "expectedResourceVersion": configured["resourceVersion"],
    }, label + "-sync")
    operation = result["operation"]
    if (operation.get("kind") != "registry_mirror_sync"
            or not re.fullmatch(r"mirror-sync:[0-9a-f]{32}", operation.get("operationId", ""))
            or operation.get("state") != "queued"):
        raise ValueError("Mirror Sync did not return its actual queued operation")
    return {"operation": operation, "scope": "queued public control acknowledgement; completion unknown"}


def require_mirror_source_inventory(rows, *, mode="full"):
    """Bound independently retained source bytes without dropping unknown paths."""
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_MIRROR_OBJECTS:
        raise ValueError("Mirror source inventory is empty or incomplete")
    selected, total = {}, 0
    for row in rows:
        if (set(row) != {"path", "sha256", "byteSize"}
                or not isinstance(row["path"], str) or row["path"].startswith("/")
                or any(part in {"", ".", ".."} for part in row["path"].split("/"))
                or len(row["path"].encode()) > 512
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                or type(row["byteSize"]) is not int
                or not 0 <= row["byteSize"] <= MAX_MIRROR_OBJECT_BYTES
                or row["path"] in selected):
            raise ValueError("Mirror source inventory contains an unsupported or duplicate object")
        selected[row["path"]] = row
        total += row["byteSize"]
    if total > MAX_MIRROR_SURFACE_BYTES:
        raise ValueError("Mirror source exceeds its complete signed-surface bound")
    if mode == "full":
        if not {"HEAD", "info/refs"}.issubset(selected):
            raise ValueError("Full Mirror source omits its signed refs and HEAD")
    elif mode == "pull_through":
        narinfos = [path for path in selected if re.fullmatch(r"[0-9a-z]{32}\.narinfo", path)]
        nars = [path for path in selected if re.fullmatch(r"nar/[0-9a-z]{32}-[A-Za-z0-9._-]+\.nar(?:\.zst)?", path)]
        if (len(selected) != 2 or len(narinfos) != 1 or len(nars) != 1
                or narinfos[0][:32] != nars[0][4:36]):
            raise ValueError("Pull-through source is not one exact governing narinfo/NAR pair")
    else:
        raise ValueError("Mirror source inventory mode is unsupported")
    return selected


def _catalogue_hash(value):
    if isinstance(value, str) and value.startswith("sha256:"):
        value = value[7:]
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Mirror catalogue hash is not an exact SHA256 commitment")
    return value


def require_mirror_effects(observed, selection, configured, expected, *, full):
    """Join read-only catalogue, placement and settled import/publication rows."""
    if not isinstance(observed, dict) or set(observed) != {"value", "receipt"} or not observed["receipt"]:
        raise ValueError("Mirror effects lack a retained actual SQL observation")
    value = observed["value"]
    if value is None:
        return None
    if set(value) != {"registry", "mirror", "placement", "binding", "authority", "objects", "imports", "publication"}:
        raise ValueError("Mirror SQL returned another observation shape")
    registry, mirror = value["registry"], value["mirror"]
    placement, binding = value["placement"], value["binding"]
    authority = value["authority"]
    if (str(registry["id"]) != str(configured["registryId"])
            or registry["slug"] != selection["registrySlug"]
            or registry["stable_id"] != selection["registryStableId"]
            or mirror["registry_id"] != registry["id"]
            or mirror["resource_version"] != int(configured["resourceVersion"])
            or mirror["upstream_url"] != selection["upstream"]
            or mirror["mode"] != ("full" if full else "pullthrough")
            or mirror["verify"] != 1
            or mirror["refspec"] != "refs/*" or mirror["auth_secret_ref"] != ""
            or mirror["schedule_secs"] != (60 if full else 0)
            or placement["registry_id"] != registry["id"]
            or placement["name"] != selection["placementName"]
            or placement["prefix"] != selection["placementPrefix"]
            or str(placement["resource_version"]) != str(selection["placementResourceVersion"])
            or placement["binding_id"] != binding["id"]
            or binding["stable_id"] != selection["bindingStableId"]
            or str(binding["resource_version"]) != str(selection["bindingResourceVersion"])
            or authority["registry_id"] != registry["id"]
            or authority["reconciliation_state"] != "ready"
            or authority["desired_placement_id"] != placement["id"]
            or authority["observed_placement_id"] != placement["id"]
            or authority["desired_write_spec_version"] != placement["write_spec_version"]
            or authority["observed_write_spec_version"] != placement["write_spec_version"]
            or authority["observed_generation"] != authority["desired_generation"]
            or authority["observed_binding_write_revision"] != authority["desired_binding_write_revision"]):
        raise ValueError("Mirror SQL does not join the actual current selected source and destination")
    source = require_mirror_source_inventory(expected, mode=selection["mode"])
    seen = {}
    for row in value["objects"]:
        path = row["path"]
        if path in seen or path not in source:
            raise ValueError("Mirror SQL returned duplicate or unselected catalogue bytes")
        wanted = source[path]
        if (_catalogue_hash(row["digest"]) != wanted["sha256"] or row["size"] != wanted["byteSize"]
                or row["presence"] != "present" or row["placement_id"] != placement["id"]
                or _catalogue_hash(row["observed_hash"]) != wanted["sha256"]
                or row["observed_size"] != wanted["byteSize"]
                or row["resource_version"] != row["catalog_object_resource_version"]):
            raise ValueError("Mirror catalogue/presence differs from independently retained source bytes")
        seen[path] = row
    # ACK retirement may remove settled import rows. Every remaining selected
    # journal must be committed; absence alone cannot prove an object was copied.
    for row in value["imports"]:
        if row["source_path"] not in source or row["state"] != "committed" or not row["commit_digest"]:
            return None
    if set(seen) != set(source):
        return None
    if full:
        publication = value["publication"]
        if (publication is None or publication["state"] != "ready"
                or publication["default_commit"] != selection["sourceCommit"]
                or publication["registry_id"] != registry["id"]
                or mirror["last_sync_status"] != "ok"
                or mirror["upstream_frontier"] != selection["frontier"]):
            return None
    return {"sql": observed, "objectCount": len(source),
        "encodedBytes": sum(row["byteSize"] for row in source.values()),
        "scope": "actual catalogue/presence with settled current Mirror imports"}


def observe_mirror_effects(read_sql, selection, configured, label):
    """Read current selected Mirror rows in one bounded private transaction."""
    require_mirror_configuration(configured, selection)
    numeric = int(configured["registryId"])
    query = (
        "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
        "SET LOCAL statement_timeout='20s'; "
        "SELECT json_build_object('registry',row_to_json(r),'mirror',row_to_json(m),"
        "'placement',row_to_json(p),'binding',json_build_object('id',b.id,'stable_id',b.stable_id,"
        "'resource_version',b.resource_version),'authority',row_to_json(w),"
        "'objects',(SELECT COALESCE(json_agg(row_to_json(o)), '[]') FROM ("
        "SELECT s.object_key AS path,s.content_hash AS digest,s.size,s.resource_version,"
        "a.state AS presence,a.placement_id,a.observed_hash,a.observed_size,a.catalog_object_resource_version "
        "FROM surface_objects s LEFT JOIN object_placements a ON a.surface_object_id=s.id AND a.placement_id=p.id "
        "WHERE s.registry_id=r.id AND s.lifecycle_state='active' ORDER BY s.object_key LIMIT 4097) o),"
        "'imports',(SELECT COALESCE(json_agg(row_to_json(j)), '[]') FROM ("
        "SELECT source_path,state,commit_digest FROM mirror_import_objects WHERE registry_id=r.id "
        "ORDER BY job_id LIMIT 4097) j),"
        "'publication',(SELECT row_to_json(pub) FROM registry_publication_state head "
        "JOIN registry_publications pub ON pub.publication_id=head.current_publication_id "
        "AND pub.registry_id=head.registry_id WHERE head.registry_id=r.id)) "
        "FROM registries r JOIN mirror_sources m ON m.registry_id=r.id "
        "JOIN surface_placements p ON p.registry_id=r.id JOIN bindings b ON b.id=p.binding_id "
        "JOIN surface_write_authorities w ON w.registry_id=r.id "
        "WHERE r.id=" + str(numeric) + " AND r.slug='" + selection["registrySlug"]
        + "' AND r.stable_id='" + selection["registryStableId"] + "' AND p.name='"
        + selection["placementName"] + "'; COMMIT;"
    )
    return read_sql(query, label)


def require_empty_mirror_destination(observed, selection, configured):
    """Require retained fresh destination state before functional admission."""
    if (not isinstance(observed, dict) or set(observed) != {"value", "receipt"}
            or not observed["receipt"] or not isinstance(observed["value"], dict)):
        raise ValueError("Mirror destination emptiness lacks actual retained SQL")
    value = observed["value"]
    if (str(value["registry"]["id"]) != str(configured["registryId"])
            or value["registry"]["stable_id"] != selection["registryStableId"]
            or value["placement"]["prefix"] != selection["placementPrefix"]
            or value["objects"] != [] or value["imports"] != [] or value["publication"] is not None):
        raise ValueError("Mirror destination already contains unresolved or completed work")
    return observed


def run_external_mirror_case(controls, selection, expected_source, readiness, *,
                             install_purpose, observe_effects, read_visible, retain,
                             cutoff, clock=time.monotonic, sleep=time.sleep):
    """Call one real configured case without promoting its acknowledgement.

    install_purpose must invoke the current source-owned controlled producer,
    validate and install its actual signed artifacts, and return retained inputs
    and process observations. read_visible must fetch the selected actual bytes;
    observe_effects must return the retained current SQL query above. Missing
    callbacks refuse before applying any configuration.
    """
    if not all(callable(callback) for callback in (install_purpose, observe_effects, read_visible, retain)):
        raise ValueError("Mirror caller requires actual purpose, SQL and visible-byte producers")
    if readiness.get("backgroundControllers", {}).get("mirrorSync") != {"intervalSeconds": 60, "mode": "full"}:
        raise ValueError("Mirror caller lacks actual scheduler registration")
    if cutoff <= clock():
        raise ValueError("Mirror caller's original fixture cutoff has expired")
    expected = require_mirror_source_inventory(expected_source, mode=selection["mode"])
    label = "external-mirror-" + selection["runId"] + "-" + selection["mode"].replace("_", "-")
    configured = configure_external_mirror(controls, selection, label)
    baseline = require_empty_mirror_destination(observe_effects(selection, configured, 0), selection, configured)
    retain(label + "-empty-destination.json", baseline)
    producer = install_purpose(selection, configured)
    if producer is None:
        raise ValueError("Actual controlled External Mirror purpose remains unavailable")
    retain(label + "-controlled-purpose.json", producer)
    deadline = min(cutoff, clock() + 360)
    if clock() >= deadline:
        raise ValueError("Mirror purpose installation reached the original fixture cutoff")
    acknowledgement = None
    if selection["mode"] == "full":
        acknowledgement = enqueue_external_mirror_sync(controls, selection, configured, label)
        retain(label + "-queued-ack.json", acknowledgement)
    else:
        # This call issues real selected demand reads. SQL is observed afterward;
        # no queued Sync or scheduled Full completion is claimed for this mode.
        visible = read_visible(selection, expected_source, deadline)
        require_mirror_visible_bytes(visible, expected)
        retain(label + "-demand-read.json", visible)
    attempts = []
    while True:
        registry = controls.call("RegistryService", "GetRegistry", {"slug": selection["registrySlug"]})["registry"]
        if (registry["stableId"] != selection["registryStableId"]
                or registry["trustKeys"] != selection["trustKeys"]):
            raise ValueError("Actual current Mirror registry trust configuration changed")
        current = controls.call(MIRROR_SERVICE, "GetRegistryMirror", {
            "registryId": selection["registrySlug"],
        })["mirror"]
        require_mirror_configuration(current, selection, configured["resourceVersion"])
        if current["registryId"] != configured["registryId"]:
            raise ValueError("Mirror status crossed its actual registry")
        attempt = {name: current.get(name, "") for name in ("state", "observedCommit", "lastSyncAt")}
        attempt["hasError"] = bool(current.get("error"))
        attempts.append(attempt)
        status_complete = selection["mode"] == "pull_through" or (
            current.get("state") == "ready" and current.get("observedCommit") == selection["frontier"]
            and int(current.get("lastSyncAt", 0)) > 0 and not current.get("error"))
        effects = observe_effects(selection, configured, len(attempts))
        joined = require_mirror_effects(effects, selection, configured, expected_source,
            full=selection["mode"] == "full")
        if status_complete and joined is not None:
            visible = read_visible(selection, expected_source, deadline)
            require_mirror_visible_bytes(visible, expected)
            result = {"version": 1, "selection": selection, "configuration": configured,
                "purpose": producer, "queuedAcknowledgement": acknowledgement,
                "initialEmptyDestination": baseline,
                "statusObservations": attempts, "effects": joined, "visible": visible,
                "nativeBulkBytes": None,
                "scope": "actual controlled External Mirror case; whole-flow byte accounting remains separate"}
            retain(label + "-completed.json", result)
            return result
        if clock() >= deadline:
            retain(label + "-incomplete.json", {"observations": attempts, "sql": effects,
                "queuedAcknowledgement": acknowledgement, "completion": None})
            raise RuntimeError("Actual Mirror status/effects did not complete before the original cutoff")
        sleep(min(1, max(0, deadline - clock())))


def require_mirror_visible_bytes(observed, expected):
    """Require complete public byte captures to match the retained signed source."""
    if not isinstance(observed, list) or len(observed) != len(expected):
        raise ValueError("Mirror public byte observation is incomplete")
    seen = set()
    for row in observed:
        path = row.get("path")
        if path not in expected or path in seen:
            raise ValueError("Mirror public read crossed or repeated its selected object")
        source = expected[path]
        if (row.get("httpStatus") != 200 or row.get("sha256") != source["sha256"]
                or row.get("byteSize") != source["byteSize"] or not row.get("privateCapture")):
            raise ValueError("Mirror public bytes differ from the actual signed source")
        seen.add(path)
    return observed
