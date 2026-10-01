"""Numeric observations at the actual Native HTTP fixture boundary.

The proxy retains private body files without logging authorization headers.
Unknown request lengths stay unknown until their captured files are checked;
offered HTTP bytes and completed reply bodies have separate totals.
These observations cannot establish provider readiness or zero bulk traffic by
themselves. The workload also needs the actual typed control and provider traces.
"""

import json
import math
import re


DIRECT_NATIVE_PHASES = frozenset(("admission", "authorize", "commit", "abort-report"))
LEGACY_UPLOAD_PHASES = frozenset(("preflight", "admit", "complete"))
DIRECT_CONTROL_BODY_LIMIT = 256 * 1024
LEGACY_ORIGIN_REQUEST_LIMIT = 64 * 1024
WORKER_CONTROL_REPLY_LIMIT = 8 * 1024 * 1024
CLIENT_INVENTORY_REPLY_LIMIT = 64 * 1024 * 1024
PUBLICATION_INVENTORY_PROCEDURES = frozenset(
    f"/aos.hub.v1.PublishService/{method}" for method in (
        "BeginRegistryPublicationManifest", "AppendRegistryPublicationManifest",
        "SealRegistryPublicationManifest", "CommitRegistryPublication",
        "GetRegistryPublication", "ListRegistryPublications",
    )
)
DOCUMENTATION_CONTENT_PROCEDURES = frozenset(
    f"/aos.hub.v1.DocumentationService/{method}" for method in (
        "GetPackageDocumentation", "ListPackageOptions", "GetPackageOption",
        "ComparePackageDocumentation", "GetDocumentationArtifact",
    )
)
NATIVE_OBSERVATION_FIELDS = frozenset((
    "procedure", "phase", "status", "request_http_bytes", "request_body_bytes",
    "response_body_bytes", "response_http_bytes", "elapsed_seconds",
    "upstream_status", "upstream_seconds",
    "request_id", "request_body_file", "response_body_file", "method",
    "response_content_type", "response_content_encoding",
    "request_transfer_encoding",
))


def native_control_observations(text, body_root="/var/lib/hybrid-native-observations"):
    """Read closed numeric proxy records without inventing missing body sizes."""
    if body_root not in {"/var/lib/hybrid-native-observations",
            "/var/lib/hybrid-native-outbound", "/var/lib/hybrid-worker-boundary"}:
        raise ValueError("body observation directory is not selected")
    observations = []
    for line in text.splitlines():
        if len(line) > 4096:
            raise ValueError("Native boundary observation exceeds bounds")
        raw = json.loads(line)
        if not isinstance(raw, dict) or raw.keys() != NATIVE_OBSERVATION_FIELDS:
            raise ValueError("Native boundary observation changed shape")
        procedure = raw["procedure"]
        if not isinstance(procedure, str) or not re.fullmatch(
            r"/[A-Za-z0-9_./-]{1,512}", procedure,
        ):
            raise ValueError("Native boundary observation has an invalid procedure")
        phase = raw["phase"]
        if phase and phase not in DIRECT_NATIVE_PHASES | LEGACY_UPLOAD_PHASES:
            raise ValueError("Native boundary observation has an unknown phase")

        observation = {"procedure": procedure, "phase": phase}
        for name in ("request_id", "request_body_file", "response_body_file", "method",
                     "response_content_type", "response_content_encoding", "request_transfer_encoding"):
            if not isinstance(raw[name], str) or len(raw[name]) > 4096:
                raise ValueError("Native private body reference is invalid")
            observation[name] = raw[name]
        if not re.fullmatch(r"[0-9a-f]{32}", observation["request_id"]):
            raise ValueError("Native request identity is invalid")
        if (observation["response_body_file"] != body_root + "/response-bodies/"
                + observation["request_id"] or observation["method"] not in {"GET", "POST"}):
            raise ValueError("Native body reference or method changed")
        for field in (
            "status", "request_http_bytes", "request_body_bytes",
            "response_body_bytes", "response_http_bytes",
        ):
            value = raw[field]
            if field == "request_body_bytes" and value == "-":
                observation[field] = None
                continue
            if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,18}", value):
                raise ValueError("Native boundary observation has invalid byte or status fields")
            observation[field] = int(value)
        if not 100 <= observation["status"] <= 599:
            raise ValueError("Native boundary status is invalid")
        for field in ("elapsed_seconds", "upstream_seconds"):
            value = raw[field]
            if field == "upstream_seconds" and value == "-":
                observation[field] = None
                continue
            if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
                raise ValueError("Native boundary timing is invalid")
            number = float(value)
            if not math.isfinite(number):
                raise ValueError("Native boundary timing is not finite")
            observation[field] = number
        upstream = raw["upstream_status"]
        if upstream != "-" and not re.fullmatch(r"[1-5][0-9]{2}", upstream):
            raise ValueError("Native boundary observation contains multiple upstream attempts")
        observation["upstream_status"] = None if upstream == "-" else int(upstream)
        body = observation["request_body_bytes"]
        if body is not None and body > observation["request_http_bytes"]:
            raise ValueError("Native body exceeds its observed HTTP request")
        if observation["response_body_bytes"] > observation["response_http_bytes"]:
            raise ValueError("Native body exceeds its observed HTTP response")
        observations.append(observation)
    if not observations:
        raise ValueError("Native boundary observations are absent")
    return observations


def native_control_class(actual):
    """Name actual protocol surfaces without absorbing inventory into legacy."""
    if actual["phase"] in DIRECT_NATIVE_PHASES or actual["procedure"].startswith(
        "/aos.hub.v1.DirectUploadService/",
    ):
        return "direct_logical_control"
    if actual["procedure"] in PUBLICATION_INVENTORY_PROCEDURES:
        return "publication_inventory_control"
    if actual["procedure"] in DOCUMENTATION_CONTENT_PROCEDURES:
        return "documentation_semantic_control"
    return "legacy_control"


def summarize_native_control_bytes(observations, object_count):
    """Retain per-procedure/phase totals and both unchanged gate outcomes."""
    if not isinstance(object_count, int) or isinstance(object_count, bool) or object_count <= 0:
        raise ValueError("the actual original object count must be positive")
    groups = {}
    for actual in observations:
        key = (actual["procedure"], actual["phase"])
        group = groups.setdefault(key, {
            "procedure": key[0], "phase": key[1], "calls": 0,
            "traffic_class": native_control_class(actual),
            "request_http_bytes": 0, "response_http_bytes": 0,
            "known_request_body_bytes": 0, "unknown_request_body_lengths": 0,
            "response_body_bytes": 0, "maximum_request_body_bytes": 0,
            "maximum_response_body_bytes": 0, "successful_calls": 0,
        })
        group["calls"] += 1
        group["successful_calls"] += actual["status"] == 200
        for field in ("request_http_bytes", "response_http_bytes", "response_body_bytes"):
            group[field] += actual[field]
        body = actual["request_body_bytes"]
        if body is None:
            group["unknown_request_body_lengths"] += 1
        else:
            group["known_request_body_bytes"] += body
            group["maximum_request_body_bytes"] = max(group["maximum_request_body_bytes"], body)
        group["maximum_response_body_bytes"] = max(
            group["maximum_response_body_bytes"], actual["response_body_bytes"],
        )

    direct = [actual for actual in observations if native_control_class(actual) == "direct_logical_control"]
    inventory = [actual for actual in observations if native_control_class(actual) == "publication_inventory_control"]
    documentation = [actual for actual in observations if native_control_class(actual) == "documentation_semantic_control"]
    legacy = [actual for actual in observations if native_control_class(actual) == "legacy_control"]
    known_direct = [actual["request_body_bytes"] for actual in direct if actual["request_body_bytes"] is not None]
    unknown_direct = sum(actual["request_body_bytes"] is None for actual in direct)
    direct_bounded = (
        bool(direct) and not unknown_direct
        and max(known_direct) <= DIRECT_CONTROL_BODY_LIMIT
        and max(actual["response_body_bytes"] for actual in direct) <= DIRECT_CONTROL_BODY_LIMIT
    )
    legacy_known = [actual["request_body_bytes"] for actual in legacy if actual["request_body_bytes"] is not None]
    legacy_bounded = (
        bool(legacy) and len(legacy_known) == len(legacy)
        and max(legacy_known) < LEGACY_ORIGIN_REQUEST_LIMIT
    )
    inventory_bounded = (
        bool(inventory)
        and all(actual["request_body_bytes"] is not None for actual in inventory)
        and max(actual["request_body_bytes"] for actual in inventory) <= DIRECT_CONTROL_BODY_LIMIT
        and max(actual["response_body_bytes"] for actual in inventory) <= WORKER_CONTROL_REPLY_LIMIT
    )
    request_http = sum(actual["request_http_bytes"] for actual in observations)
    response_http = sum(actual["response_http_bytes"] for actual in observations)
    return {
        "groups": [groups[key] for key in sorted(groups)],
        "original_object_count": object_count,
        "request_http_bytes": request_http,
        "response_http_bytes": response_http,
        "control_http_bytes_per_original_object": (request_http + response_http) / object_count,
        "direct_body_limit_bytes": DIRECT_CONTROL_BODY_LIMIT,
        "direct_body_limit_passed": direct_bounded,
        "direct_unknown_request_body_lengths": unknown_direct,
        "publication_inventory_request_body_limit_bytes": DIRECT_CONTROL_BODY_LIMIT,
        "publication_inventory_worker_reply_limit_bytes": WORKER_CONTROL_REPLY_LIMIT,
        "publication_inventory_client_reply_limit_bytes": CLIENT_INVENTORY_REPLY_LIMIT,
        "publication_inventory_transport_limit_passed": inventory_bounded,
        "publication_inventory_observed_calls": len(inventory),
        "documentation_semantic_observed_calls": len(documentation),
        "documentation_semantic_response_body_bytes": sum(
            actual["response_body_bytes"] for actual in documentation
        ),
        # Public Compare can contain multiple independently bounded projections.
        # The internal 4 MiB + 1 KiB per-query cap needs actual operation traces.
        "documentation_internal_result_limit_evidence": "requires inspect_documentation_content operation traces",
        "documentation_request_body_limit_passed": all(
            actual["request_body_bytes"] is not None
            and actual["request_body_bytes"] < LEGACY_ORIGIN_REQUEST_LIMIT
            for actual in documentation
        ) if documentation else None,
        "legacy_request_body_limit_bytes_exclusive": LEGACY_ORIGIN_REQUEST_LIMIT,
        "legacy_request_body_limit_passed": legacy_bounded,
        "all_request_bodies_below_legacy_limit": all(
            actual["request_body_bytes"] is not None
            and actual["request_body_bytes"] < LEGACY_ORIGIN_REQUEST_LIMIT
            for actual in observations
        ),
        "native_bulk_bytes": None,
        "native_bulk_evidence": "requires typed control and independent provider traces",
    }
