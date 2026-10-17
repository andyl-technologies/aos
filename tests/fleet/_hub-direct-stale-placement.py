"""Advance one real placement while its genuine Native metadata request waits."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time


STALE_INDEX_TABLES = {
    "index", "packages", "releases", "channels", "channel_floors", "keys",
    "release_records", "release_notes", "container_roots", "container_closure_members",
    "container_evidence", "container_provenance", "container_layers", "versions",
    "platforms", "channel_partitions", "catalog_artifacts", "documentation",
    "browse_catalogs", "browse_nodes", "browse_ancestors", "browse_entries",
    "artifact_snapshots", "release_artifacts", "release_documentation",
}


def _decimal(value, *, positive=False):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        raise ValueError("stale placement integer spelling")
    number = int(value)
    if number > 2**63 - 1 or (positive and number == 0):
        raise ValueError("stale placement integer range")
    return number


def _closed_json(body):
    def fields(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("stale placement duplicate original field")
            value[key] = item
        return value

    return json.loads(body, object_pairs_hook=fields,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite original")))


def _private_original(file, expected_sha256):
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_mode & 0o077
                or not 0 < before.st_size <= 64 * 1024):
            raise ValueError("stale placement original custody")
        body = os.read(descriptor, 64 * 1024 + 1)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)
        if (before.st_size != len(body) or identity(before) != identity(after)
                or hashlib.sha256(body).hexdigest() != expected_sha256):
            raise ValueError("stale placement original changed")
    finally:
        os.close(descriptor)
    return body


def advance_held_stale_placement(controls, held, original_file, surface, placement_name, label):
    """Apply only a real read-order revision pinned to the held Native original.

    The caller retains the existing signed request/Worker handler/provider joins.
    This fixture does not authenticate a request from a digest or socket status.
    """
    fields = {"version", "state", "requestSha256", "signatureSha256", "planIdSha256",
        "bodyBytes", "expiresAtUnixSeconds", "observedAtUnixMillis"}
    if (set(held) != fields or held["version"] != 1 or held["state"] != "held"
            or not re.fullmatch(r"[0-9a-f]{64}", held["requestSha256"] or "")
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", label)):
        raise ValueError("stale placement held selection")
    expiry = _decimal(held["expiresAtUnixSeconds"], positive=True)
    if time.time() >= expiry:
        raise ValueError("stale placement original expired")
    body = _private_original(Path(original_file), held["requestSha256"])
    if len(body) != _decimal(held["bodyBytes"], positive=True):
        raise ValueError("stale placement original byte count")
    original = _closed_json(body)
    if (original.get("version") != 1
            or original.get("operation") != {"kind": "inspect_metadata", "path": "info/refs"}
            or original.get("expires_at") != expiry
            or hashlib.sha256(original["plan_id"].encode()).hexdigest() != held["planIdSha256"]):
        raise ValueError("stale placement original operation")

    before = controls.call("TopologyService", "GetPlacement", {
        "surface": surface, "name": placement_name,
    })["placement"]
    previous_version = _decimal(before["resourceVersion"], positive=True)
    previous_order = _decimal(before["spec"].get("readOrder", "0"))
    if (previous_version != original["placement_resource_version"]
            or before["prefix"] != original["placement_prefix"]
            or before["spec"]["desiredState"] != "active"
            or not before["spec"]["desiredReadEnabled"]
            or not before["status"]["effectiveReadEnabled"]
            or previous_order == 2**63 - 1):
        raise ValueError("stale placement current public pin")
    if time.time() >= expiry:
        raise ValueError("stale placement original expired before plan")

    applied = controls.reviewed("TopologyService", "PlanUpdatePlacement", "UpdatePlacement", {
        "surface": surface, "name": placement_name,
        "expectedResourceVersion": before["resourceVersion"],
        "readOrder": str(previous_order + 1), "updateMask": ["read_order"],
    }, label)["placement"]
    after = controls.call("TopologyService", "GetPlacement", {
        "surface": surface, "name": placement_name,
    })["placement"]
    if (after != applied or after["name"] != before["name"]
            or after["prefix"] != before["prefix"]
            or after["bindingName"] != before["bindingName"]
            or _decimal(after["resourceVersion"], positive=True) <= previous_version
            or _decimal(after["spec"]["readOrder"]) != previous_order + 1
            or after["spec"]["desiredState"] != before["spec"]["desiredState"]
            or after["spec"]["desiredReadEnabled"] != before["spec"]["desiredReadEnabled"]):
        raise ValueError("stale placement applied revision mismatch")
    if time.time() >= expiry:
        # The real SQL mutation remains retained. Never recreate or release an
        # expired authorization to make this case appear successful.
        raise ValueError("stale placement original expired after apply")
    return {
        "version": 1, "requestSha256": held["requestSha256"],
        "placementId": str(original["placement_id"]),
        "placementBefore": before, "placementAfter": after,
        "eligibleUntilUnixSeconds": str(expiry),
        "providerRequests": None, "nativeBulkBytes": None,
    }


def assert_stale_index_refusal(before, after, index_result, request_sha256):
    """Check real CLI failure while retaining eligible old read traffic separately."""
    if (type(index_result["exitCode"]) is not int or not 0 < index_result["exitCode"] <= 255
            or index_result.get("timedOut") is not False
            or index_result["requestSha256"] != request_sha256
            or not isinstance(index_result["stderr"], bytes) or len(index_result["stderr"]) > 65536
            or b"storage placement or binding changed during Worker execution"
                not in index_result["stderr"]):
        raise ValueError("stale placement Native index fence not observed")
    if (set(before) != STALE_INDEX_TABLES or set(after) != STALE_INDEX_TABLES
            or any(not isinstance(rows, list) for rows in [*before.values(), *after.values()])
            or any(not before[name] for name in ("packages", "releases", "channels"))
            or len(before["index"]) != 1 or len(after["index"]) != 1
            or len(before["index"][0]) != 9 or len(after["index"][0]) != 9
            or before["index"][0][:2] != ["fresh", None]
            or after["index"][0][0] != "failed"
            or not isinstance(after["index"][0][1], str)
            or "storage placement or binding changed during Worker execution" not in after["index"][0][1]
            or before["index"][0][2:] != after["index"][0][2:]
            or any(before[name] != after[name] for name in STALE_INDEX_TABLES - {"index"})):
        raise ValueError("stale placement authoritative index changed or incomplete")
    return {"version": 1, "outcome": "native_stale_result_refused",
        "requestSha256": request_sha256,
        "indexBeforeSha256": hashlib.sha256(json.dumps(before, sort_keys=True, allow_nan=False).encode()).hexdigest(),
        "indexAfterSha256": hashlib.sha256(json.dumps(after, sort_keys=True, allow_nan=False).encode()).hexdigest(),
        "providerRequests": None, "nativeBulkBytes": None}
