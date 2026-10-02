"""Validates native interruption evidence collected by checked CLI readers.

Desired graphs, durable journal outcomes, and independent substrate readings
remain separate. A graph digest or retained output never proves live state.
The fleet supplies the checked journal reader and a domain-specific live oracle.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


SCENARIO_BOUNDARIES = {
    "interrupt-after-durable-intent": "intent-durable",
    "lose-external-result": "dispatch-returned",
    "interrupt-after-durable-outcome": "outcome-durable",
}
IDENTITY_FIELDS = ("transaction", "effect", "revision", "action", "journal_sequence")


def canonical(value: Any) -> bytes:
    """Encodes retained evidence without changing Unicode or integer values."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def digest(value: Any) -> str:
    """Identifies exact canonical evidence bytes without asserting authority."""
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def event_identity(event: dict[str, Any]) -> tuple[Any, ...]:
    """Selects the native durable intent identity across recovery observations."""
    if event.get("schema") != "aos.activation.boundary":
        raise ValueError("unsupported native boundary schema")
    if set(event) != {"schema", "boundary", *IDENTITY_FIELDS}:
        raise ValueError("unexpected native boundary fields")
    if event["action"] not in {"apply", "remove"}:
        raise ValueError("invalid native mutation action")
    sequence = event["journal_sequence"]
    if type(sequence) is not int or sequence < 1:
        raise ValueError("invalid durable intent sequence")
    if any(not isinstance(event[field], str) or not event[field] for field in IDENTITY_FIELDS[:3]):
        raise ValueError("missing native invocation identity")
    return tuple(event[field] for field in IDENTITY_FIELDS)


def checked_inspection(view: dict[str, Any]) -> None:
    """Requires the explicit native checked-reader provenance marker."""
    if view.get("schema") != "aos.activation.inspection" or view.get("liveStateVerified") is not False:
        raise ValueError("expected checked native journal inspection")
    if view.get("incompleteTailBytes") != 0:
        raise ValueError("qualification requires a complete native journal prefix")
    sequences = [record["sequence"] for record in view["records"]]
    if sequences != list(range(1, len(sequences) + 1)):
        raise ValueError("native inspection records do not form an exact one-based prefix")


def dispatch_matches(record: dict[str, Any], event: dict[str, Any]) -> bool:
    """Matches a checked journal projection to an exact boundary identity."""
    dispatch = record.get("dispatch")
    return bool(dispatch) and record.get("transaction") == event["transaction"] and dispatch == {
        "effect": event["effect"],
        "revision": event["revision"],
        "action": event["action"],
        "journalSequence": event["journal_sequence"],
    }


@dataclass(frozen=True)
class NativeObservation:
    """Retains independently collected desired, durable, and substrate facts."""

    graph: dict[str, Any]
    held: dict[str, Any]
    before: dict[str, Any]
    after: dict[str, Any]
    boundaries: list[dict[str, Any]]
    baseline: dict[str, Any]
    unsettled: dict[str, Any]
    settled: dict[str, Any]
    expected: Any


@dataclass(frozen=True)
class NativeRejection:
    """Retains an exact pending intent, failed manager, and live isolation facts."""

    graph: dict[str, Any]
    held: dict[str, Any]
    before: dict[str, Any]
    after: dict[str, Any]
    boundaries: list[dict[str, Any]]
    baseline: dict[str, Any]
    settled: dict[str, Any]
    expected: Any
    failure_receipt: dict[str, Any]


@dataclass(frozen=True)
class NativePendingControl(NativeRejection):
    """Retains requested cancellation or an elapsed native invocation deadline."""

    control_receipt: dict[str, Any]


@dataclass(frozen=True)
class NativeDependencyBlock(NativeRejection):
    """Separates actual failed prerequisite state from an independent blocked marker."""

    dependent: str
    dependent_baseline: dict[str, Any]
    dependent_settled: dict[str, Any]


@dataclass(frozen=True)
class NativeRetainedTransition:
    """Separates a desired source transition from its original retained invocation."""

    graph: dict[str, Any]
    desired_before: dict[str, Any]
    desired_after: dict[str, Any]
    effect: str
    before: dict[str, Any]
    after: dict[str, Any]
    baseline: dict[str, Any]
    settled: dict[str, Any]
    expected: Any
    activation_receipt: dict[str, Any]


class NativeEvidence:
    """Binds native matrix cells to checked journals and independent oracles."""

    def __init__(self, matrix: dict[str, Any], qualified: list[str]):
        self.cells = {cell["id"]: cell for cell in matrix["cells"]}
        self.adapters = {adapter["adapter"]: adapter for adapter in matrix["surface"]["adapters"]}
        if len(self.cells) != len(matrix["cells"]) or len(set(qualified)) != len(qualified):
            raise ValueError("qualification repeats a native matrix identity")
        if any(cell not in self.cells for cell in qualified):
            raise ValueError("qualification names a foreign native cell")
        self.qualified = set(qualified)
        self.subjects: dict[str, Any] = {}
        self.evidence: dict[str, bytes] = {}
        self.probes: dict[str, Any] = {}

    def retain(self, cell_id: str, observation: NativeObservation) -> None:
        """Checks exact operation selection, interruption, recovery, and isolation."""
        if cell_id not in self.qualified or cell_id in self.evidence:
            raise ValueError("native cell is foreign or already qualified")
        cell = self.cells[cell_id]
        adapter = self.adapters[cell["adapter"]]
        event = observation.held
        identity = event_identity(event)
        scenario = cell["scenario"]["id"]
        if event["boundary"] != SCENARIO_BOUNDARIES[scenario] or event["action"] != cell["action"]:
            raise ValueError("interruption differs from the selected native cell")
        graph = observation.graph
        if graph.get("schema") != "aos.activation.graph":
            raise ValueError("expected the checked native graph")
        node = graph["nodes"][event["effect"]]
        operation = cell["operation"]
        if node["identity"][-3:-1] != [operation["ability"], operation["name"]] or node["handler"] != adapter["handler"]:
            raise ValueError("effect operation or retained handler differs from the matrix")
        checked_inspection(observation.before)
        checked_inspection(observation.after)
        before = [record for record in observation.before["records"] if dispatch_matches(record, event)]
        after = [record for record in observation.after["records"] if dispatch_matches(record, event)]
        if not any(record["event"] == "started" and record["sequence"] == event["journal_sequence"] for record in before):
            raise ValueError("held invocation has no exact durable intent")
        finished_before = any(record["event"] == "finished" for record in before)
        if finished_before != (event["boundary"] == "outcome-durable"):
            raise ValueError("interruption position disagrees with the durable outcome")
        if not any(record["event"] == "finished" for record in after):
            raise ValueError("recovered invocation has no durable checked outcome")
        matching = [boundary for boundary in observation.boundaries if event_identity(boundary) == identity]
        if event["boundary"] != "outcome-durable":
            phases = [boundary["boundary"] for boundary in matching]
            try:
                started = phases.index("observation-started")
                returned = phases.index("observation-returned", started + 1)
            except ValueError as error:
                raise ValueError("pending invocation was not observed before recovery") from error
            if returned <= started:
                raise ValueError("recovery observation order differs")
        if event["action"] == "apply":
            dependents = {effect for effect, candidate in graph["nodes"].items() if event["effect"] in candidate["dependencies"]}
        else:
            # Removal reverses dependency order: an owned prerequisite cannot
            # retire while one of its retained dependents is still unsettled.
            dependents = set(node["dependencies"])
        if event["boundary"] != "outcome-durable" and any(record["event"] == "started" and record["transaction"] == event["transaction"] and (record.get("dispatch") or {}).get("effect") in dependents for record in observation.before["records"]):
            raise ValueError("dependent dispatched before its prerequisite settled")
        for reading in (observation.baseline, observation.unsettled, observation.settled):
            if set(reading) != {"selected", "foreign"}:
                raise ValueError("live oracle must separately observe selected and foreign resources")
        for reading in (observation.baseline, observation.unsettled, observation.settled):
            owners = reading["selected"].get("owners")
            if not isinstance(owners, list) or any(not isinstance(owner, str) or not owner or len(owner.encode()) > 256 for owner in owners) or owners != sorted(set(owners)):
                raise ValueError("live oracle must expose an independent sorted owner inventory")
            if len(owners) > 1:
                raise ValueError("selected live resource has multiple owners")
        if observation.settled["selected"] != observation.expected:
            raise ValueError("settled live resource differs from the operator's expected target")
        if not (observation.baseline["foreign"] == observation.unsettled["foreign"] == observation.settled["foreign"]):
            raise ValueError("interruption or recovery changed a foreign live resource")
        if not any(record["event"] == "commit" and record["transaction"] == event["transaction"] for record in observation.after["records"]):
            raise ValueError("recovery did not durably complete the selected transaction")
        subject = {
            "schema": "aos.qualification.native-operation-subject",
            "cell": cell_id,
            "transaction": event["transaction"],
            "resolvedRevision": event["revision"],
            "action": event["action"],
            "journalSequence": event["journal_sequence"],
            "effect": {"id": event["effect"], **{key: node[key] for key in ("identity", "revision", "handler", "lifetime", "dependencies")}},
            "selectedGraphDigest": digest(graph),
        }
        evidence = {
            "schema": "aos.qualification.native-operation-flight",
            "subject": subject,
            "selectedGraph": graph,
            "journalBefore": observation.before,
            "journalAfter": observation.after,
            "boundaries": matching,
            "baseline": observation.baseline,
            "unsettled": observation.unsettled,
            "settled": observation.settled,
            "expectedSelected": observation.expected,
        }
        self.subjects[cell_id] = subject
        self.evidence[cell_id] = canonical(evidence)
        self.probes[cell_id] = {"disposition": "checked", "evidenceDigest": digest(evidence)}

    def retain_rejection(self, cell_id: str, observation: NativeRejection) -> None:
        """Retains failed native execution without claiming a handler mutation."""
        if self.cells[cell_id]["scenario"]["id"] not in {"fail-manager-after-dispatch-attempt", "reject-uncertain-recovery", "reject-foreign-resource-mutation"}:
            raise ValueError("rejection does not cover the selected native scenario")
        self._retain_pending(cell_id, observation)

    def retain_dependency_block(self, cell_id: str, observation: NativeDependencyBlock) -> None:
        """Checks action-specific scheduling and a physically unchanged dependent."""
        cell = self.cells[cell_id]
        if cell["scenario"]["id"] != "block-dependent-effect":
            raise ValueError("dependency evidence does not cover the selected scenario")
        nodes = observation.graph["nodes"]
        selected = observation.held["effect"]
        dependent = observation.dependent
        if dependent not in nodes or dependent == selected:
            raise ValueError("dependency marker is not a separate authored graph node")

        def requires(node, prerequisite, visited):
            if node in visited:
                return False
            visited.add(node)
            dependencies = nodes[node]["dependencies"]
            return prerequisite in dependencies or any(requires(child, prerequisite, visited) for child in dependencies)

        ordered = requires(dependent, selected, set()) if cell["action"] == "apply" else requires(selected, dependent, set())
        if not ordered:
            raise ValueError("dependent marker does not follow the actual native action ordering")
        for view in (observation.before, observation.after):
            if any(record["transaction"] == observation.held["transaction"] and record["event"] == "started" and record["dispatch"]["effect"] == dependent and record["dispatch"]["action"] == cell["action"] for record in view["records"]):
                raise ValueError("blocked dependent acquired an actual dispatch")
        if observation.dependent_baseline != observation.dependent_settled or set(observation.dependent_baseline) != {"selected", "foreign"}:
            raise ValueError("failed prerequisite changed the independent dependent or foreign witness")
        owners = observation.dependent_baseline["selected"].get("owners")
        if not isinstance(owners, list) or owners != sorted(set(owners)) or len(owners) > 1:
            raise ValueError("dependent marker has no bounded independent owner inventory")
        attempts = sum(event_identity(event) == event_identity(observation.held) and event["boundary"] == "dispatch-started" for event in observation.boundaries)
        if attempts != 1:
            raise ValueError("dependency barrier has no exact attempted prerequisite dispatch")
        self._retain_pending(cell_id, observation)
        evidence = json.loads(self.evidence[cell_id])
        evidence["schema"] = "aos.qualification.native-operation-dependency-block"
        evidence["dependencyBarrier"] = {"effect": dependent, "baseline": observation.dependent_baseline, "settled": observation.dependent_settled}
        self.evidence[cell_id] = canonical(evidence)
        self.probes[cell_id]["evidenceDigest"] = digest(evidence)

    def retain_pending_control(self, cell_id: str, observation: NativePendingControl) -> None:
        """Checks a real requested signal or elapsed invocation deadline with pending ownership."""
        scenario = self.cells[cell_id]["scenario"]["id"]
        control = observation.control_receipt
        if scenario == "cancel-pending-invocation":
            if set(control) != {"kind", "signal", "processId", "executable"} or control["kind"] != "signal-cancellation" or control["signal"] != "SIGTERM":
                raise ValueError("pending cancellation lacks its exact requested process signal")
            if type(control["processId"]) is not int or not 0 < control["processId"] < 2**31 or (not isinstance(control["executable"], str) or not control["executable"].startswith("/nix/store/") or len(control["executable"]) > 4096):
                raise ValueError("pending cancellation did not identify its live native manager")
        elif scenario == "expire-invocation-deadline":
            node = observation.graph["nodes"][observation.held["effect"]]
            if set(control) != {"kind", "timeoutMillis", "elapsedMillis"} or control["kind"] != "invocation-deadline":
                raise ValueError("deadline lacks its bounded elapsed invocation receipt")
            timeout = node["timeout_ms"]
            if type(control["timeoutMillis"]) is not int or control["timeoutMillis"] != timeout or type(control["elapsedMillis"]) is not int or not timeout <= control["elapsedMillis"] <= timeout + 300000:
                raise ValueError("deadline differs from the admitted native effect limit")
        else:
            raise ValueError("pending control does not cover the selected native scenario")
        self._retain_pending(cell_id, observation, control)

    def _retain_pending(self, cell_id: str, observation: NativeRejection, control: dict[str, Any] | None = None) -> None:
        """Preserves actual pending history and independent live-resource facts."""
        if cell_id not in self.qualified or cell_id in self.evidence:
            raise ValueError("native cell is foreign or already qualified")
        cell = self.cells[cell_id]
        event = observation.held
        identity = event_identity(event)
        if event["action"] != cell["action"]:
            raise ValueError("rejection differs from the selected native action")
        graph = observation.graph
        node = graph["nodes"][event["effect"]]
        adapter = self.adapters[cell["adapter"]]
        if node["identity"][-3:-1] != [cell["operation"]["ability"], cell["operation"]["name"]] or node["handler"] != adapter["handler"]:
            raise ValueError("rejected effect differs from the selected native operation")
        for view in (observation.before, observation.after):
            checked_inspection(view)
            if not dispatch_matches({"transaction": view["transaction"], "dispatch": view["pending"]}, event):
                raise ValueError("rejection did not preserve its exact pending intent")
            matching_records = [record for record in view["records"] if record["transaction"] == event["transaction"]]
            if any(record["event"] == "commit" or (record["event"] == "finished" and dispatch_matches(record, event)) for record in matching_records):
                raise ValueError("rejected transaction falsely acquired a durable outcome")
        if observation.after["records"] != observation.before["records"]:
            raise ValueError("rejection changed its durable pending prefix")
        matching = [boundary for boundary in observation.boundaries if event_identity(boundary) == identity]
        attempts = sum(boundary["boundary"] == "dispatch-started" for boundary in matching)
        if control is not None:
            required_attempts = 0 if control["kind"] == "signal-cancellation" else 1
            if attempts != required_attempts or any(boundary["boundary"] in {"dispatch-returned", "outcome-durable"} for boundary in matching):
                raise ValueError("pending control acquired an unproved dispatch or outcome")
        if cell["scenario"]["id"] == "reject-uncertain-recovery":
            phases = [boundary["boundary"] for boundary in matching]
            if attempts != 1 or "observation-started" not in phases :
                raise ValueError("uncertain recovery attempted another dispatch or lacked observation")
        if cell["scenario"]["id"] == "reject-foreign-resource-mutation":
            if attempts != 1 or observation.baseline["selected"] != observation.settled["selected"]:
                raise ValueError("foreign-resource rejection lacks an attempted dispatch or changed its live target")
        if observation.baseline["foreign"] != observation.settled["foreign"]:
            raise ValueError("rejected invocation changed a foreign live resource")
        if observation.settled["selected"] != observation.expected:
            raise ValueError("rejected invocation differs from its expected live target")
        for reading in (observation.baseline, observation.settled):
            if set(reading) != {"selected", "foreign"}:
                raise ValueError("rejection requires separate live ownership and foreign facts")
            owners = reading["selected"].get("owners")
            if not isinstance(owners, list) or owners != sorted(set(owners)) or len(owners) > 1:
                raise ValueError("rejection does not prove a bounded unique owner inventory")
        receipt = observation.failure_receipt
        if set(receipt) != {"unit", "result", "execMainCode", "execMainStatus"} or not receipt["unit"] or receipt["result"] not in {"exit-code", "signal", "timeout"} or type(receipt["execMainCode"]) is not int or type(receipt["execMainStatus"]) is not int:
            raise ValueError("rejection has no actual failed-manager receipt")
        subject = {
            "schema": "aos.qualification.native-operation-subject",
            "cell": cell_id,
            "transaction": event["transaction"],
            "resolvedRevision": event["revision"],
            "action": event["action"],
            "journalSequence": event["journal_sequence"],
            "effect": {"id": event["effect"], **{key: node[key] for key in ("identity", "revision", "handler", "lifetime", "dependencies")}},
            "selectedGraphDigest": digest(graph),
        }
        evidence = {
            "schema": "aos.qualification.native-operation-pending-control" if control is not None else "aos.qualification.native-operation-rejection",
            "subject": subject,
            "selectedGraph": graph,
            "journalBefore": observation.before,
            "journalAfter": observation.after,
            "boundaries": matching,
            "baseline": observation.baseline,
            "settled": observation.settled,
            "expectedSelected": observation.expected,
            "failureReceipt": receipt,
            "dispatchInventory": {"dispatchAttemptCount": attempts},
        }
        if control is not None:
            evidence["controlReceipt"] = control
        self.subjects[cell_id] = subject
        self.evidence[cell_id] = canonical(evidence)
        self.probes[cell_id] = {"disposition": "checked", "evidenceDigest": digest(evidence)}

    def retain_transition(self, cell_id: str, observation: NativeRetainedTransition) -> None:
        """Checks committed reuse, persistent source disappearance, or explicit removal."""
        if cell_id not in self.qualified or cell_id in self.evidence:
            raise ValueError("native cell is foreign or already qualified")
        cell = self.cells[cell_id]
        scenario = cell["scenario"]["id"]
        expected_action = "apply" if scenario == "activate-retained-target" else "remove"
        kinds = {
            "activate-retained-target": "retained-activation",
            "retain-persistent-orphan": "persistent-orphan",
            "retire-explicit-persistent-target": "explicit-retirement",
        }
        if scenario not in kinds or cell["action"] != expected_action:
            raise ValueError("retained transition differs from the semantic scenario action")
        effect = observation.effect
        graph = observation.graph
        node = graph["nodes"][effect]
        adapter = self.adapters[cell["adapter"]]
        if node["identity"][-3:-1] != [cell["operation"]["ability"], cell["operation"]["name"]] or node["handler"] != adapter["handler"]:
            raise ValueError("retained transition differs from the selected operation")
        for view in (observation.before, observation.after):
            checked_inspection(view)
            if view["pending"] is not None or view["completed"] is None:
                raise ValueError("retained transition requires complete committed journal states")
        prefix = observation.before["records"]
        if observation.after["records"][:len(prefix)] != prefix:
            raise ValueError("retained transition rewrote its checked predecessor journal")
        receipts = [record for record in prefix if record["event"] == "finished"
                    and (record.get("dispatch") or {}).get("effect") == effect]
        if not receipts or receipts[-1]["dispatch"]["action"] != "apply":
            raise ValueError("retained transition has no original applied receipt")
        prior = receipts[-1]
        dispatch = prior["dispatch"]
        if effect not in observation.before["retainedOutputs"]:
            raise ValueError("selected predecessor has no retained output")
        previous_outputs = observation.before["retainedOutputs"][effect]
        suffix = observation.after["records"][len(prefix):]
        new_dispatch = [record for record in suffix if (record.get("dispatch") or {}).get("effect") == effect]
        if scenario == "activate-retained-target":
            if effect not in observation.desired_after["nodes"] or observation.desired_after["nodes"][effect] != node:
                raise ValueError("retained activation changed the original selected effect")
        else:
            if scenario == "retain-persistent-orphan" and observation.desired_before["nodes"].get(effect) != node:
                raise ValueError("orphan transition did not begin with its exact declared predecessor")
            if node["lifetime"] != "persistent" or effect in observation.desired_after["nodes"]:
                raise ValueError("persistent source transition did not remove the selected declaration")
            if not any(record["event"] == "commit" for record in suffix):
                raise ValueError("persistent source transition lacks its durable target commit")
        if scenario == "retire-explicit-persistent-target":
            starts = [record for record in new_dispatch if record["event"] == "started"]
            finishes = [record for record in new_dispatch if record["event"] == "finished"]
            if len(starts) != 1 or len(finishes) != 1 or starts[0]["dispatch"] != finishes[0]["dispatch"] or starts[0]["dispatch"]["action"] != "remove":
                raise ValueError("explicit retirement lacks its actual single remove intent and outcome")
            if effect in observation.after["retainedOutputs"] or effect not in observation.after["retiredEffects"]:
                raise ValueError("explicit retirement retained its original owned outputs")
        else:
            if new_dispatch or observation.after["retainedOutputs"].get(effect) != previous_outputs:
                raise ValueError("retained source transition dispatched or changed its original output")
            if observation.settled["selected"] != observation.baseline["selected"]:
                raise ValueError("retained source transition changed the original live resource identity")
        for reading in (observation.baseline, observation.settled):
            if set(reading) != {"selected", "foreign"}:
                raise ValueError("retained transition requires independent selected and foreign facts")
            owners = reading["selected"].get("owners")
            if not isinstance(owners, list) or owners != sorted(set(owners)) or len(owners) > 1:
                raise ValueError("retained transition lacks a unique independent owner inventory")
        if observation.baseline["foreign"] != observation.settled["foreign"] or observation.settled["selected"] != observation.expected:
            raise ValueError("retained transition changed foreign state or its expected target")
        receipt = observation.activation_receipt
        if set(receipt) != {"unit", "result", "execMainCode", "execMainStatus"} or not receipt["unit"] or receipt["result"] != "success" or receipt["execMainCode"] != 1 or receipt["execMainStatus"] != 0:
            raise ValueError("retained transition lacks its actual successful manager receipt")
        subject = {
            "schema": "aos.qualification.native-operation-subject", "cell": cell_id,
            "transaction": prior["transaction"], "resolvedRevision": dispatch["revision"],
            "action": cell["action"], "journalSequence": dispatch["journalSequence"],
            "effect": {"id": effect, **{key: node[key] for key in ("identity", "revision", "handler", "lifetime", "dependencies")}},
            "selectedGraphDigest": digest(graph),
        }
        evidence = {
            "schema": "aos.qualification.native-retained-transition", "subject": subject,
            "selectedGraph": graph, "desiredBefore": observation.desired_before, "desiredAfter": observation.desired_after,
            "journalBefore": observation.before, "journalAfter": observation.after,
            "priorReceipt": {"transaction": prior["transaction"], "dispatch": dispatch, "outputs": previous_outputs},
            "transition": {"kind": kinds[scenario], "action": cell["action"]},
            "baseline": observation.baseline, "settled": observation.settled,
            "expectedSelected": observation.expected, "activationReceipt": receipt,
        }
        self.subjects[cell_id] = subject
        self.evidence[cell_id] = canonical(evidence)
        self.probes[cell_id] = {"disposition": "checked", "evidenceDigest": digest(evidence)}

    def finish(self) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any]]:
        """Requires actual retained evidence for every selected native flight."""
        if set(self.evidence) != self.qualified:
            raise ValueError("native qualification has unexecuted cells")
        return self.subjects, self.evidence, self.probes
