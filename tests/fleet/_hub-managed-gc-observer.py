"""Collect complete scoped Worker SDK brackets without granting authority.

Records come from the installed Worker's private console capture. Expected
selectors come from actual authenticated StorageWork requests and results;
neither a caller-created record nor this parser proves their provenance.
The output covers only managed_gc_guard and managed_inventory_range requests.
Separate real R2 and persisted guard observations remain mandatory.
"""

import json
import re


SCOPES = {"managed_gc_guard", "managed_inventory_range"}
COMMON = {"version", "capture_id", "request_id", "scope", "key", "subject_id", "event"}
MAX_RECORD_BYTES = 4096
MAX_REQUEST_BYTES = 256 * 1024
MAX_WINDOW_BYTES = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def selector(record):
    return record["scope"], record["key"], record["subject_id"]


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 2**64 - 1


def outcome_valid(method, outcome):
    if not isinstance(outcome, dict):
        return False
    kind = outcome.get("kind")
    if kind == "resolved":
        return method == "delete" and set(outcome) == {"kind"}
    if kind == "absent":
        return method in {"head", "get"} and set(outcome) == {"kind"}
    if kind != "object" or method not in {"head", "get"}:
        return False
    return (set(outcome) == {"kind", "size", "etag", "version"}
            and integer(outcome["size"])
            and isinstance(outcome["etag"], str)
            and 2 <= len(outcome["etag"].encode()) <= 512
            and outcome["etag"].startswith('"') and outcome["etag"].endswith('"')
            and isinstance(outcome["version"], str)
            and 0 < len(outcome["version"].encode()) <= 512
            and not any(ord(char) < 32 or ord(char) == 127 for char in outcome["version"]))


def collect(records, capture_id, backing_identity, expected_requests):
    """Require every selected request's real entry, calls and healthy terminal.

    Missing records, duplicate IDs, unknown SDK outcomes, unclosed requests and
    bound violations refuse. An empty record list cannot establish zero calls.
    This function performs no SDK, SQL, signing or provider operation.
    """
    require(isinstance(records, list) and 0 < len(records) <= 4096,
            "scoped SDK records are missing or exceed their bound")
    require(isinstance(capture_id, str) and re.fullmatch(r"[0-9a-f]{32}", capture_id)
            and isinstance(backing_identity, str)
            and re.fullmatch(r"[0-9a-f]{64}", backing_identity),
            "capture or backing identity differs")
    require(isinstance(expected_requests, list) and 0 < len(expected_requests) <= 64,
            "actual expected request selectors are missing or unbounded")
    expected = set()
    for item in expected_requests:
        require(isinstance(item, dict) and set(item) == {"scope", "key", "subject_id"}
                and item["scope"] in SCOPES
                and isinstance(item["key"], str) and 0 < len(item["key"].encode()) <= 512
                and isinstance(item["subject_id"], str)
                and 0 < len(item["subject_id"].encode()) <= 128,
                "actual expected request selector differs")
        expected.add(selector(item))
    require(len(expected) == len(expected_requests), "expected selector is duplicated")

    requests = {}
    calls = []
    total_bytes = 0
    for sequence, record in enumerate(records, 1):
        require(isinstance(record, dict) and set(record) == COMMON
                and type(record["version"]) is int and record["version"] == 1
                and record["capture_id"] == capture_id
                and isinstance(record["request_id"], str)
                and re.fullmatch(r"[0-9a-f]{32}", record["request_id"])
                and selector(record) in expected,
                "SDK record is foreign, malformed or not an actual expected request")
        byte_count = len(json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode())
        total_bytes += byte_count
        require(byte_count <= MAX_RECORD_BYTES and total_bytes <= MAX_WINDOW_BYTES,
                "SDK metadata exceeds its record or window bound")
        event = record["event"]
        require(isinstance(event, dict), "SDK event differs")
        identity = record["request_id"]
        kind = event.get("kind")
        if kind == "request_entry":
            require(set(event) == {"kind"} and identity not in requests,
                    "SDK request entry is repeated or malformed")
            requests[identity] = {"selector": selector(record), "calls": {},
                                  "terminal": False, "bytes": byte_count}
            continue

        require(identity in requests, "SDK event has no actual request entry")
        request = requests[identity]
        request["bytes"] += byte_count
        require(request["selector"] == selector(record) and not request["terminal"]
                and request["bytes"] <= MAX_REQUEST_BYTES,
                "SDK request changed, exceeded its bound or continued after terminal")
        if kind == "call_invoke":
            require(set(event) == {"kind", "ordinal", "method", "range"}
                    and integer(event["ordinal"], 1) and event["ordinal"] <= 32
                    and event["ordinal"] == len(request["calls"]) + 1
                    and event["method"] in {"head", "get", "delete"},
                    "SDK invocation order or method differs")
            requested_range = event["range"]
            require(requested_range is None or (
                event["method"] == "get" and isinstance(requested_range, list)
                and len(requested_range) == 2 and integer(requested_range[0])
                and integer(requested_range[1], 1)
                and requested_range[0] + requested_range[1] <= 2**64 - 1),
                "SDK range arguments differ")
            require((record["scope"] == "managed_gc_guard"
                     and event["method"] in {"head", "delete"} and requested_range is None)
                    or (record["scope"] == "managed_inventory_range"
                        and event["method"] == "get" and requested_range is not None),
                    "SDK invocation exceeds its actual caller scope")
            request["calls"][event["ordinal"]] = {
                "callId": identity + ":" + str(event["ordinal"]), "requestId": identity,
                "scope": record["scope"], "subjectId": record["subject_id"],
                "sequence": sequence, "method": event["method"], "key": record["key"],
                "range": requested_range,
            }
        elif kind == "call_result":
            require(set(event) == {"kind", "ordinal", "method", "outcome"}
                    and integer(event["ordinal"], 1)
                    and event["ordinal"] in request["calls"],
                    "SDK result has no invocation")
            call = request["calls"][event["ordinal"]]
            require("result" not in call and call["method"] == event["method"]
                    and outcome_valid(event["method"], event["outcome"]),
                    "SDK result is repeated, unknown or changed")
            outcome = event["outcome"]
            call["result"] = ({key: value for key, value in outcome.items() if key != "kind"}
                              if outcome["kind"] == "object" else outcome)
            calls.append(call)
        elif kind == "request_terminal":
            require(set(event) == {"kind", "healthy", "invoked", "completed", "pending"}
                    and event["healthy"] is True
                    and integer(event["invoked"]) and integer(event["completed"])
                    and type(event["pending"]) is int and event["pending"] == 0
                    and event["invoked"] == event["completed"] == len(request["calls"])
                    and all("result" in call for call in request["calls"].values()),
                    "SDK request is incomplete, unknown or missing call records")
            request["terminal"] = True
        else:
            raise ValueError("SDK event kind differs")

    require(all(request["terminal"] for request in requests.values())
            and {request["selector"] for request in requests.values()} == expected,
            "expected SDK requests lack actual healthy terminal brackets")
    brackets = [{"requestId": identity, "scope": request["selector"][0],
                 "key": request["selector"][1], "subjectId": request["selector"][2],
                 "invoked": len(request["calls"])} for identity, request in requests.items()]
    return {"coverage": "scoped_requests_complete", "captureId": capture_id,
            "backingIdentity": backing_identity, "brackets": brackets,
            "calls": sorted(calls, key=lambda call: call["sequence"])}
