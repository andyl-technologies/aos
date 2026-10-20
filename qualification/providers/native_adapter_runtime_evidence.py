"""Checks native durable flights independently of the fleet evidence producer.

The checked CLI reader supplies journal facts. Independent resource oracles
supply ownership and substrate facts; retained outputs never substitute for
those observations. Unsupported scenario obligations fail closed.
"""

from __future__ import annotations

from typing import Any

from native_adapter_evidence_common import sha256, _canonical_evidence, required_operations


SUBJECT_SCHEMA = "aos.qualification.native-operation-subject"
FLIGHT_SCHEMA = "aos.qualification.native-operation-flight"
REJECTION_SCHEMA = "aos.qualification.native-operation-rejection"
DEPENDENCY_SCHEMA = "aos.qualification.native-operation-dependency-block"
RETAINED_SCHEMA = "aos.qualification.native-retained-transition"
CONTROL_SCHEMA = "aos.qualification.native-operation-pending-control"
CONTROL_SCENARIOS = {"cancel-pending-invocation", "expire-invocation-deadline"}
REJECTION_SCENARIOS = {"fail-manager-after-dispatch-attempt", "reject-uncertain-recovery",
                       "reject-foreign-resource-mutation"}
SCENARIO_BOUNDARIES = {
    "interrupt-after-durable-intent": "intent-durable",
    "lose-external-result": "dispatch-returned",
    "interrupt-after-durable-outcome": "outcome-durable",
}
SUPPORTED_POSTCONDITIONS = {
    "durable-attempt-state-classified", "at-most-one-resource-owner",
    "foreign-resources-unchanged", "dependent-effects-not-executed",
    "exactly-one-resource-owner",
    "uncertain-invocation-not-replayed", "retained-target-identity-preserved",
    "foreign-attempt-rejected-before-mutation", "prerequisite-failure-recorded",
}
INSPECTION_FIELDS = {
    "schema", "liveStateVerified", "incompleteTailBytes", "transaction",
    "pending", "completed", "desired", "retainedOutputs", "retiredEffects", "records",
}


def require(condition: bool, message: str) -> None:
    """Rejects an unproved native qualification invariant."""
    if not condition:
        raise RuntimeError(message)


def dispatch_identity(value: Any) -> None:
    """Requires one bounded identity emitted by the checked journal reader."""
    require(isinstance(value, dict) and set(value) == {
        "effect", "revision", "action", "journalSequence",
    }, "native dispatch has unexpected fields")
    require(all(isinstance(value[key], str) and 0 < len(value[key].encode()) <= 4096
                for key in ("effect", "revision")), "native dispatch lacks identity")
    require(value["action"] in {"apply", "remove"}, "native dispatch action is invalid")
    require(type(value["journalSequence"]) is int and value["journalSequence"] >= 0,
            "native dispatch sequence is invalid")


def _validate_physical_precondition(selected: dict[str, Any]) -> None:
    """Checks the optional live account database mount witness's closed shape."""
    if "precondition" not in selected:
        return
    proof = selected["precondition"]
    fields = {"kind", "path", "mountId", "device", "root", "mountPoint", "options",
              "filesystem", "source", "superOptions", "contentSha256"}
    require(isinstance(proof, dict) and set(proof) == fields
            and proof["kind"] == "read-only-account-database"
            and proof["path"] == proof["mountPoint"] == "/etc/group"
            and type(proof["mountId"]) is int and 0 < proof["mountId"] < 2**31,
            "native account precondition lacks its actual confined read-only mount identity")
    require(all(isinstance(proof[key], str) and 0 < len(proof[key].encode()) <= 4096
                and "\0" not in proof[key] for key in ("device", "root", "filesystem", "source"))
            and len(proof["device"].split(":")) == 2
            and all(component.isascii() and component.isdigit() for component in proof["device"].split(":"))
            and proof["root"].startswith("/"), "native account precondition has malformed mount fields")
    for key in ("options", "superOptions"):
        values = proof[key]
        require(isinstance(values, list) and 0 < len(values) <= 128
                and all(isinstance(value, str) and 0 < len(value.encode()) <= 4096
                        and "\0" not in value for value in values)
                and len(values) == len(set(values)), "native account precondition mount options are malformed")
    require("ro" in proof["options"] and "rw" not in proof["options"],
            "native account precondition is not actually a read-only mount")
    digest = proof["contentSha256"]
    require(isinstance(digest, str) and len(digest) == 71 and digest.startswith("sha256:")
            and all(character in "0123456789abcdef" for character in digest[7:]),
            "native account precondition lacks its exact physical file digest")


def inspect(value: Any) -> list[dict[str, Any]]:
    """Rechecks the native projection's ordering and pending intent state."""
    require(isinstance(value, dict) and set(value) == INSPECTION_FIELDS,
            "native inspection has unexpected fields")
    require(value["schema"] == "aos.activation.inspection" and value["liveStateVerified"] is False,
            "qualification requires a checked native journal reader")
    require(type(value["incompleteTailBytes"]) is int and value["incompleteTailBytes"] == 0,
            "qualification requires a complete journal prefix")
    records = value["records"]
    require(isinstance(records, list) and len(records) <= 100000, "native journal records are unbounded")
    transaction = None
    pending = None
    last_completed = None
    retired = set()
    for sequence, record in enumerate(records, start=1):
        require(isinstance(record, dict) and set(record) == {"sequence", "event", "transaction", "dispatch"},
                "native journal record has unexpected fields")
        require(type(record["sequence"]) is int and record["sequence"] == sequence,
                "native journal sequence is not an exact prefix")
        event = record["event"]
        if event == "begin":
            require(transaction is None and pending is None and record["dispatch"] is None,
                    "native transaction begins over unsettled work")
            transaction = record["transaction"]
            require(isinstance(transaction, str) and bool(transaction), "native transaction lacks identity")
        else:
            require(transaction is not None and record["transaction"] == transaction,
                    "native journal event has a foreign transaction")
            if event == "started":
                require(pending is None, "native dispatch overlaps unsettled intent")
                dispatch_identity(record["dispatch"])
                require(record["dispatch"]["journalSequence"] == sequence,
                        "native intent sequence differs from its frame")
                pending = record["dispatch"]
            elif event == "finished":
                require(pending is not None and record["dispatch"] == pending,
                        "native outcome differs from its durable intent")
                if pending["action"] == "remove":
                    retired.add(pending["effect"])
                else:
                    retired.discard(pending["effect"])
                pending = None
            elif event in {"released", "commit"}:
                require(pending is None and record["dispatch"] is None,
                        "native transaction closes with unsettled intent")
                if event == "commit":
                    last_completed = transaction
                    transaction = None
            else:
                raise RuntimeError("native journal has an unsupported event")
    require(value["transaction"] == transaction and value["pending"] == pending,
            "native inspection summary differs from its records")
    completed = value["completed"]
    require((completed is None and last_completed is None)
            or (isinstance(completed, dict) and set(completed) == {"transaction", "content"}
                and completed["transaction"] == last_completed
                and isinstance(completed["content"], str) and bool(completed["content"])),
            "native completed summary differs from its commit records")
    require(value["retiredEffects"] == sorted(retired), "native retired effects differ from completed invocations")
    require(isinstance(value["retainedOutputs"], dict), "native retained outputs are malformed")
    require(transaction is not None or value["desired"] is None,
            "native inspection retains an active graph without a transaction")
    return records


def validate_flight(cell: dict[str, Any], subject: Any, evidence_bytes: bytes,
                    spec: dict[str, Any], operations: list[dict[str, Any]]) -> dict[str, Any]:
    """Checks exact matrix custody, interruption, recovery, and live isolation."""
    required_operations(spec)
    require(spec.get("schema") == "aos.qualification.native-operation-matrix-spec"
            and sum(candidate == cell for candidate in spec.get("cells", [])) == 1
            and cell["id"] in spec.get("applicability", {}).get("applicable_cell_ids", [])
            and operations == spec.get("surface", {}).get("adapters"),
            "native flight lacks its exact applicable matrix cell and operation surface")
    require(isinstance(subject, dict) and set(subject) == {
        "schema", "cell", "transaction", "resolvedRevision", "action",
        "journalSequence", "effect", "selectedGraphDigest",
    } and subject["schema"] == SUBJECT_SCHEMA, "unsupported native operation subject")
    require(subject["cell"] == cell["id"] and subject["action"] == cell["action"],
            "native subject names another matrix cell")
    flight = _canonical_evidence(evidence_bytes, "native flight")
    dependency_blocked = flight.get("schema") == DEPENDENCY_SCHEMA
    retained = flight.get("schema") == RETAINED_SCHEMA
    controlled = flight.get("schema") == CONTROL_SCHEMA
    rejected = flight.get("schema") in {REJECTION_SCHEMA, CONTROL_SCHEMA, DEPENDENCY_SCHEMA}
    phase_fields = {"failureReceipt", "dispatchInventory"} if rejected else {"unsettled"}
    if dependency_blocked:
        phase_fields |= {"dependencyBarrier"}
    if retained:
        phase_fields = {"desiredBefore", "desiredAfter", "priorReceipt", "transition", "activationReceipt"}
    if controlled:
        phase_fields |= {"controlReceipt"}
    expected_fields = {"schema", "subject", "journalBefore", "journalAfter",
                       "baseline", "settled", "expectedSelected", "selectedGraph"} | phase_fields
    if not retained:
        expected_fields.add("boundaries")
    require(set(flight) == expected_fields
            and flight["schema"] in {FLIGHT_SCHEMA, REJECTION_SCHEMA, CONTROL_SCHEMA, RETAINED_SCHEMA, DEPENDENCY_SCHEMA}
            and flight["subject"] == subject, "native flight subject or fields differ")
    adapters = [adapter for adapter in operations if adapter.get("adapter") == cell["adapter"]]
    require(len(adapters) == 1, "native subject lacks one authenticated operation")
    adapter = adapters[0]
    effect = subject["effect"]
    require(isinstance(effect, dict) and set(effect) == {
        "id", "identity", "revision", "handler", "lifetime", "dependencies",
    }, "native subject effect has unexpected fields")
    operation = cell["operation"]
    require(adapter["operation"]["ability"] == operation["ability"]
            and adapter["operation"]["name"] == operation["name"]
            and effect["handler"] == adapter["handler"]
            and effect["identity"][-3:-1] == [operation["ability"], operation["name"]],
            "native subject operation or handler differs from the authenticated surface")
    require({key: effect[key] for key in ("id", "identity", "revision", "lifetime", "dependencies")}
            in adapter["effects"], "native effect differs from the authenticated surface")
    if retained:
        return _validate_retained_transition(cell, subject, flight)
    before = inspect(flight["journalBefore"])
    after = inspect(flight["journalAfter"])
    require(after[:len(before)] == before, "native recovery rewrites the retained journal prefix")
    dispatch = {"effect": effect["id"], "revision": subject["resolvedRevision"],
                "action": subject["action"], "journalSequence": subject["journalSequence"]}
    dispatch_identity(dispatch)
    matches = lambda record: record["transaction"] == subject["transaction"] and record["dispatch"] == dispatch
    intent = [record for record in before if matches(record) and record["event"] == "started"]
    require(len(intent) == 1 and intent[0]["sequence"] == subject["journalSequence"],
            "native flight lacks its exact durable intent")
    scenario = cell["scenario"]["id"]
    supported_scenarios = {"block-dependent-effect"} if dependency_blocked else (CONTROL_SCENARIOS if controlled else REJECTION_SCENARIOS if rejected else SCENARIO_BOUNDARIES)
    require(scenario in supported_scenarios,
            "native scenario has no independent evidence validator")
    boundary = None if rejected else SCENARIO_BOUNDARIES[scenario]
    finished_before = any(matches(record) and record["event"] == "finished" for record in before)
    if rejected:
        expected_disposition = ({"cancel-pending-invocation": "cancelled-retains-pending-intent", "expire-invocation-deadline": "deadline-exceeded-retains-ownership"}[scenario]
                                if controlled else "dependent-effect-blocked" if dependency_blocked
                                else "foreign-mutation-rejected" if scenario == "reject-foreign-resource-mutation"
                                else "pending-intent-retained")
        require(cell.get("disposition") == {"kind": "exact", "value": expected_disposition},
                "native rejection contradicts its matrix disposition")
        require(flight["journalBefore"] == flight["journalAfter"] and not finished_before
                and flight["journalAfter"]["pending"] == dispatch
                and flight["journalAfter"]["transaction"] == subject["transaction"]
                and not any(record["event"] == "commit" and record["transaction"] == subject["transaction"] for record in after),
                "native rejection changed or completed its exact pending intent")
    else:
        require(finished_before == (boundary == "outcome-durable"), "native interruption contradicts its durable outcome")
        require(any(matches(record) and record["event"] == "finished" for record in after),
                "native recovery lacks an exact durable outcome")
        require(any(record["event"] == "commit" and record["transaction"] == subject["transaction"] for record in after),
                "native recovery lacks the selected transaction commit")
    graph = flight["selectedGraph"]
    require(isinstance(graph, dict) and graph.get("schema") == "aos.activation.graph"
            and sha256(graph) == subject["selectedGraphDigest"], "native flight selected graph differs")
    if subject["action"] == "apply":
        require(graph == flight["journalBefore"]["desired"],
                "native apply selected graph differs from its checked durable transaction")
    node = graph.get("nodes", {}).get(effect["id"])
    require(isinstance(node, dict) and all(node.get(key) == effect[key] for key in effect if key != "id"),
            "native flight selected graph effect differs")
    phases = []
    for event in flight["boundaries"]:
        require(isinstance(event, dict) and set(event) == {"schema", "boundary", "transaction", "effect", "revision", "action", "journal_sequence"},
                "native boundary has unexpected fields")
        require(event["schema"] == "aos.activation.boundary" and event["transaction"] == subject["transaction"]
                and all(event[key] == dispatch[key] for key in ("effect", "revision", "action"))
                and event["journal_sequence"] == subject["journalSequence"], "native boundary names a foreign intent")
        require(event["boundary"] in {
            "intent-durable", "dispatch-started", "dispatch-returned", "outcome-durable",
            "observation-started", "observation-returned",
        }, "native boundary has an unsupported phase")
        phases.append(event["boundary"])
    if rejected:
        receipt = flight["failureReceipt"]
        require(isinstance(receipt, dict) and set(receipt) == {
            "unit", "result", "execMainCode", "execMainStatus",
        } and isinstance(receipt["unit"], str) and 0 < len(receipt["unit"].encode()) <= 256
                and receipt["result"] in {"exit-code", "signal", "timeout"}
                and all(type(receipt[key]) is int and receipt[key] >= 0 for key in ("execMainCode", "execMainStatus")),
                "native rejection lacks its actual manager failure receipt")
        required_attempts = _validate_control_receipt(flight["controlReceipt"], scenario, node) if controlled else 1
        inventory = flight["dispatchInventory"]
        require(isinstance(inventory, dict) and set(inventory) == {"dispatchAttemptCount"}
                and type(inventory["dispatchAttemptCount"]) is int
                and inventory["dispatchAttemptCount"] == phases.count("dispatch-started") == required_attempts,
                "native rejection lacks one exact dispatch attempt or attempted a replay")
        if controlled:
            require("intent-durable" in phases and not any(phase in phases for phase in ("dispatch-returned", "outcome-durable")),
                    "pending native control dispatch returned or acquired an outcome")
        held_position = phases.index("dispatch-started") if required_attempts else phases.index("intent-durable")
    else:
        require(boundary in phases, "native flight lacks its selected interruption boundary")
        held_position = phases.index(boundary)
    if "dispatch-started" in phases and "dispatch-returned" in phases:
        require(phases.index("dispatch-started") < phases.index("dispatch-returned"),
                "native dispatch returned before its attempt boundary")
    if (not rejected and not finished_before) or (rejected and scenario == "reject-uncertain-recovery"):
        recovery_phases = phases[held_position + 1:]
        require("observation-started" in recovery_phases,
                "pending native intent was not observed before recovery")
        if not rejected:
            require("observation-returned" in recovery_phases,
                    "pending native intent was not observed before recovery")
        if "observation-returned" in recovery_phases:
            require(recovery_phases.index("observation-started") < recovery_phases.index("observation-returned"),
                    "pending native observation returned before its attempt")
    dependents = (
        {key for key, node in graph["nodes"].items() if effect["id"] in node["dependencies"]}
        if subject["action"] == "apply" else set(effect["dependencies"])
    )
    require(not any(record["event"] == "started" and record["transaction"] == subject["transaction"]
                    and record["dispatch"]["action"] == subject["action"]
                    and record["dispatch"]["effect"] in dependents for record in before),
            "dependent native effect dispatched before the interruption settled")
    if dependency_blocked:
        _validate_dependency_barrier(flight, graph, effect["id"], subject["action"], before)
    if scenario == "reject-foreign-resource-mutation":
        require(flight["baseline"]["selected"] == flight["settled"]["selected"],
                "native foreign target changed during refused activation")
    oracle_phases = ("baseline", "settled") if rejected else ("baseline", "unsettled", "settled")
    for phase in oracle_phases:
        reading = flight[phase]
        require(isinstance(reading, dict) and set(reading) == {"selected", "foreign"}
                and isinstance(reading["selected"], dict), "native live oracle lacks separated substrate observations")
        _validate_physical_precondition(reading["selected"])
        owners = reading["selected"].get("owners")
        require(isinstance(owners, list) and all(isinstance(owner, str) and 0 < len(owner.encode()) <= 256 for owner in owners)
                and owners == sorted(set(owners)) and len(owners) <= 1,
                "native live oracle lacks an independent single-owner inventory")
    require(all(flight[phase]["foreign"] == flight["baseline"]["foreign"] for phase in oracle_phases),
            "native flight mutated a foreign resource")
    require(flight["settled"]["selected"] == flight["expectedSelected"],
            "native flight settled substrate differs from the expected target")
    return flight


def _validate_dependency_barrier(flight: dict[str, Any], graph: dict[str, Any],
                                 prerequisite: str, action: str,
                                 records: list[dict[str, Any]]) -> None:
    """Checks the real dependency direction, including reversed removal order."""
    barrier = flight["dependencyBarrier"]
    require(isinstance(barrier, dict) and set(barrier) == {"effect", "baseline", "settled"}
            and barrier["effect"] in graph["nodes"] and barrier["effect"] != prerequisite,
            "native dependency barrier lacks an actual separate graph node")
    blocked = barrier["effect"]
    root, ancestor = (blocked, prerequisite) if action == "apply" else (prerequisite, blocked)
    pending = list(graph["nodes"][root]["dependencies"])
    seen = set()
    while pending:
        current = pending.pop()
        require(current in graph["nodes"], "native dependency barrier references an absent node")
        if current not in seen:
            seen.add(current)
            pending.extend(graph["nodes"][current]["dependencies"])
    require(ancestor in seen, "native dependency barrier reverses the actual scheduling relation")
    require(not any(record["event"] == "started" and record["transaction"] == flight["subject"]["transaction"]
                    and record["dispatch"]["effect"] == blocked and record["dispatch"]["action"] == action
                    for record in records), "native blocked dependent actually dispatched")
    for phase in ("baseline", "settled"):
        reading = barrier[phase]
        require(isinstance(reading, dict) and set(reading) == {"selected", "foreign"}
                and isinstance(reading["selected"], dict), "native dependent physical oracle is malformed")
        _validate_physical_precondition(reading["selected"])
        owners = reading["selected"].get("owners")
        require(isinstance(owners, list) and len(owners) <= 1
                and all(isinstance(owner, str) and 0 < len(owner.encode()) <= 256 for owner in owners)
                and owners == sorted(set(owners)), "native dependent lacks independent bounded owners")
    require(barrier["baseline"] == barrier["settled"], "native blocked dependent or its foreign witness changed")


def _validate_retained_transition(cell: dict[str, Any], subject: dict[str, Any],
                                  flight: dict[str, Any]) -> dict[str, Any]:
    """Separates source disappearance from actual retained invocation receipts."""
    routes = {
        "activate-retained-target": ("retained-activation", "apply", "retained-target-activated"),
        "retain-persistent-orphan": ("persistent-orphan", "remove", "persistent-resource-retained"),
        "retire-explicit-persistent-target": ("explicit-retirement", "remove", "persistent-resource-retired"),
    }
    scenario = cell["scenario"]["id"]
    require(scenario in routes, "native retained transition names an unsupported scenario")
    kind, action, disposition = routes[scenario]
    require(cell["action"] == action and flight["transition"] == {"kind": kind, "action": action}
            and cell["disposition"] == {"kind": "exact", "value": disposition},
            "native retained transition contradicts its authored scenario")
    graph = flight["selectedGraph"]
    effect = subject["effect"]
    effect_id = effect["id"]
    require(isinstance(graph, dict) and graph.get("schema") == "aos.activation.graph"
            and sha256(graph) == subject["selectedGraphDigest"], "native retained graph differs")
    node = graph.get("nodes", {}).get(effect_id)
    require(isinstance(node, dict) and all(node.get(key) == effect[key] for key in effect if key != "id"),
            "native retained graph effect differs from the authenticated surface")
    before = inspect(flight["journalBefore"])
    after = inspect(flight["journalAfter"])
    require(after[:len(before)] == before and all(flight[phase]["pending"] is None
            and flight[phase]["completed"] is not None for phase in ("journalBefore", "journalAfter")),
            "native retained transition lacks complete committed journal states")
    for name in ("desiredBefore", "desiredAfter"):
        desired = flight[name]
        require(isinstance(desired, dict) and desired.get("schema") == "aos.activation.graph"
                and isinstance(desired.get("nodes"), dict), "native retained desired graph is malformed")
    require(flight["desiredBefore"]["nodes"].get(effect_id) == node,
            "native retained predecessor differs from the selected original target")
    prior = flight["priorReceipt"]
    require(isinstance(prior, dict) and set(prior) == {"transaction", "dispatch", "outputs"},
            "native retained receipt has unexpected fields")
    dispatch_identity(prior["dispatch"])
    require(prior["dispatch"] == {"effect": effect_id, "revision": subject["resolvedRevision"],
                                  "action": "apply", "journalSequence": subject["journalSequence"]}
            and prior["transaction"] == subject["transaction"],
            "native retained receipt fabricates a logical remove invocation")
    matches = [record for record in before if record["event"] == "finished"
               and record["dispatch"]["effect"] == effect_id]
    require(bool(matches) and matches[-1]["transaction"] == prior["transaction"]
            and matches[-1]["dispatch"] == prior["dispatch"]
            and flight["journalBefore"]["retainedOutputs"].get(effect_id) == prior["outputs"]
            and effect_id in flight["journalBefore"]["retainedOutputs"],
            "native retained receipt is not the latest checked applied output")
    suffix = after[len(before):]
    changed = [record for record in suffix if record["dispatch"] is not None
               and record["dispatch"]["effect"] == effect_id]
    if kind == "retained-activation":
        require(flight["desiredAfter"]["nodes"].get(effect_id) == node,
                "native retained activation changed its original target")
    else:
        require(node["lifetime"] == "persistent" and effect_id not in flight["desiredAfter"]["nodes"]
                and any(record["event"] == "commit" for record in suffix),
                "native persistent transition lacks its checked source disappearance commit")
    if kind == "explicit-retirement":
        require(len(changed) == 2 and [record["event"] for record in changed] == ["started", "finished"]
                and changed[0]["dispatch"] == changed[1]["dispatch"]
                and changed[0]["dispatch"]["action"] == "remove"
                and effect_id not in flight["journalAfter"]["retainedOutputs"]
                and effect_id in flight["journalAfter"]["retiredEffects"],
                "native explicit retirement lacks its actual remove intent and outcome")
    else:
        require(not changed and flight["journalAfter"]["retainedOutputs"].get(effect_id) == prior["outputs"]
                and flight["baseline"]["selected"] == flight["settled"]["selected"],
                "native retained transition dispatched or changed its original target")
    for phase in ("baseline", "settled"):
        reading = flight[phase]
        require(isinstance(reading, dict) and set(reading) == {"selected", "foreign"}
                and isinstance(reading["selected"], dict), "native retained oracle is malformed")
        _validate_physical_precondition(reading["selected"])
        owners = reading["selected"].get("owners")
        require(isinstance(owners, list) and len(owners) <= 1
                and all(isinstance(owner, str) and 0 < len(owner.encode()) <= 256 for owner in owners)
                and owners == sorted(set(owners)), "native retained oracle lacks bounded independent owners")
    require(flight["baseline"]["foreign"] == flight["settled"]["foreign"]
            and flight["settled"]["selected"] == flight["expectedSelected"],
            "native retained transition changed foreign state or its expected target")
    receipt = flight["activationReceipt"]
    require(isinstance(receipt, dict) and set(receipt) == {"unit", "result", "execMainCode", "execMainStatus"}
            and isinstance(receipt["unit"], str) and 0 < len(receipt["unit"].encode()) <= 256
            and receipt["result"] == "success" and type(receipt["execMainCode"]) is int
            and receipt["execMainCode"] == 1 and type(receipt["execMainStatus"]) is int
            and receipt["execMainStatus"] == 0, "native retained transition lacks its successful manager receipt")
    return flight


def _validate_control_receipt(control: Any, scenario: str, node: dict[str, Any]) -> int:
    """Checks actual requested controls without inferring handler cancellation."""
    if scenario == "cancel-pending-invocation":
        require(isinstance(control, dict) and set(control) == {"kind", "signal", "processId", "executable"}
                and control["kind"] == "signal-cancellation" and control["signal"] == "SIGTERM"
                and type(control["processId"]) is int and 0 < control["processId"] < 2**31
                and isinstance(control["executable"], str) and len(control["executable"]) <= 4096
                and control["executable"].startswith("/nix/store/") and control["executable"].endswith("/bin/apm")
                and not any(component in {".", ".."} for component in control["executable"].split("/")),
                "native pending cancellation lacks its bounded actual control receipt")
        return 0
    require(isinstance(control, dict) and set(control) == {"kind", "timeoutMillis", "elapsedMillis"}
            and control["kind"] == "invocation-deadline"
            and type(control["timeoutMillis"]) is int and control["timeoutMillis"] > 0
            and control["timeoutMillis"] == node.get("timeout_ms")
            and type(control["elapsedMillis"]) is int
            and control["timeoutMillis"] <= control["elapsedMillis"] <= control["timeoutMillis"] + 300000,
            "native pending deadline differs from the selected timeout or elapsed interval")
    return 1


def probe_facts(name: str, flight: dict[str, Any]) -> dict[str, Any]:
    """Extracts only the distinct semantic facts proved by a native flight."""
    require(name in SUPPORTED_POSTCONDITIONS, "native flight does not prove this postcondition")
    identity = flight["subject"]
    oracle_phases = ("baseline", "settled") if flight["schema"] in {REJECTION_SCHEMA, CONTROL_SCHEMA, RETAINED_SCHEMA, DEPENDENCY_SCHEMA} else ("baseline", "unsettled", "settled")
    if name == "durable-attempt-state-classified":
        def selected_records(phase: str) -> list[dict[str, Any]]:
            return [record for record in flight[phase]["records"]
                    if record["transaction"] == identity["transaction"]
                    and (record["dispatch"] is None
                         or record["dispatch"]["effect"] == identity["effect"]["id"])]
        facts = {"before": selected_records("journalBefore"),
                 "after": selected_records("journalAfter"),
                 "boundaries": flight.get("boundaries", []),
                 "transition": flight.get("transition")}
    elif name in {"at-most-one-resource-owner", "exactly-one-resource-owner"}:
        facts = {phase: flight[phase]["selected"]["owners"] for phase in oracle_phases}
        if name == "exactly-one-resource-owner":
            require(len(facts["settled"]) == 1, "native settled resource does not have exactly one owner")
    elif name == "foreign-resources-unchanged":
        facts = {phase: flight[phase]["foreign"] for phase in oracle_phases}
    elif name == "prerequisite-failure-recorded":
        require(flight["schema"] == DEPENDENCY_SCHEMA,
                "native flight does not prove an actual blocked dependent")
        facts = {"barrier": flight["dependencyBarrier"], "pending": flight["journalAfter"]["pending"],
                 "manager-failure": flight["failureReceipt"], "attempts": flight["dispatchInventory"]}
    elif name == "foreign-attempt-rejected-before-mutation":
        require(flight["schema"] == REJECTION_SCHEMA
                and identity["cell"].endswith("/reject-foreign-resource-mutation")
                and flight["baseline"]["selected"] == flight["settled"]["selected"],
                "native flight lacks an independently unchanged refused foreign target")
        facts = {"baseline": flight["baseline"], "settled": flight["settled"],
                 "attempts": flight["dispatchInventory"], "manager-failure": flight["failureReceipt"]}
    elif name == "retained-target-identity-preserved":
        require(flight["schema"] == RETAINED_SCHEMA and flight["transition"]["kind"] != "explicit-retirement",
                "native flight does not prove retained target identity")
        facts = {"prior": flight["priorReceipt"], "transition": flight["transition"],
                 "baseline": flight["baseline"]["selected"], "settled": flight["settled"]["selected"]}
    elif name == "uncertain-invocation-not-replayed":
        require(flight["schema"] == REJECTION_SCHEMA
                and flight["subject"]["cell"].endswith("/reject-uncertain-recovery")
                and "observation-started" in [event["boundary"] for event in flight["boundaries"]],
                "native success or unobserved failure does not prove uncertain recovery rejection")
        facts = {"attempted-dispatches": flight["dispatchInventory"],
                 "boundaries": flight["boundaries"],
                 "pending": flight["journalAfter"]["pending"],
                 "manager-failure": flight["failureReceipt"]}
    else:
        selected = identity["effect"]
        graph = flight["selectedGraph"]
        barred = sorted(
            key for key, node in graph["nodes"].items()
            if selected["id"] in node["dependencies"]
        ) if identity["action"] == "apply" else sorted(selected["dependencies"])
        facts = {"barred-effects": barred,
                 "before-dispatches": [record["dispatch"]
                                       for record in flight["journalBefore"]["records"]
                                       if record["transaction"] == identity["transaction"]
                                       and record["event"] == "started"]}
    return {"native-subject": identity, "postcondition": name, "facts": facts}


def validate_framework_audits(audits: Any) -> int:
    """Checks framework failure and recovery proofs without claiming domain coverage."""
    require(isinstance(audits, dict) and set(audits) == {"admission", "recovery"},
            "native framework evidence lacks its exact audit pair")
    for audit in audits.values():
        require(isinstance(audit, dict) and set(audit) == {
            "schema", "framework", "liveStateVerified", "graph", "checks",
        } and audit["schema"] == "aos.qualification.native-runtime-audit"
                and audit["framework"] == "activation" and audit["liveStateVerified"] is False,
                "unsupported native framework audit")
        require(isinstance(audit["graph"], dict) and audit["graph"].get("schema") == "aos.activation.graph",
                "native framework audit lacks its selected fixture graph")
    admission = audits["admission"]["checks"]
    require(isinstance(admission, dict) and set(admission) == {
        "retentionBeforeIntent", "cancelledBeforeDispatch", "invalidOutcomeRemainsPending",
    }, "native admission audit has unexpected proofs")
    rejected = inspect(admission["retentionBeforeIntent"])
    cancelled = inspect(admission["cancelledBeforeDispatch"])
    inspect(admission["invalidOutcomeRemainsPending"])
    require(not rejected and not any(record["event"] == "started" for record in cancelled),
            "native rejected admission or cancelled activation dispatched a handler")
    invalid = admission["invalidOutcomeRemainsPending"]
    require(invalid["pending"] is not None and invalid["completed"] is None,
            "native invalid outcome was durably committed")

    recovery = audits["recovery"]["checks"]
    require(isinstance(recovery, dict) and set(recovery) == {
        "pendingExactIntent", "uncertainObservationDoesNotReplay", "recoveredCurrentOutcome",
        "boundaries", "handlerMutationCount",
    }, "native recovery audit has unexpected proofs")
    pending = recovery["pendingExactIntent"]
    uncertain = recovery["uncertainObservationDoesNotReplay"]
    completed = recovery["recoveredCurrentOutcome"]
    prefix = inspect(pending)
    require(inspect(uncertain) == prefix and pending["pending"] is not None
            and uncertain["pending"] == pending["pending"],
            "indeterminate native recovery changed its exact retained intent")
    require(inspect(completed)[:len(prefix)] == prefix and completed["pending"] is None
            and completed["completed"] is not None,
            "native recovery did not preserve and complete its retained prefix")
    require(type(recovery["handlerMutationCount"]) is int and recovery["handlerMutationCount"] == 1,
            "native recovery repeated the framework fixture mutation")
    dispatch = pending["pending"]
    phases = []
    for boundary in recovery["boundaries"]:
        if (boundary.get("schema") == "aos.activation.boundary"
                and boundary.get("transaction") == pending["transaction"]
                and boundary.get("effect") == dispatch["effect"]
                and boundary.get("revision") == dispatch["revision"]
                and boundary.get("action") == dispatch["action"]
                and boundary.get("journal_sequence") == dispatch["journalSequence"]):
            phases.append(boundary.get("boundary"))
    require(phases.count("observation-started") >= 2 and phases.count("observation-returned") >= 2,
            "native recovery lacks separate indeterminate and successful observations")
    return 6
