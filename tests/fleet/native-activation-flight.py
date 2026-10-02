"""Runs native package-manager interruption flights with checked inspection.

The importing fleet supplies guest tools, an admitted operator worktree,
exact graph effect IDs, and independent live substrate oracles. This helper
never constructs handler outcomes or reads private journal frames itself.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from typing import Any, Callable


STATE_ROOT = "/var/lib/aos/ability-boundary-test"
TARGET = f"{STATE_ROOT}/target.json"
CONTINUE = f"{STATE_ROOT}/continue.json"
HELD = f"{STATE_ROOT}/held-event.json"
EVENTS = f"{STATE_ROOT}/events.jsonl"
PROFILE = "/var/lib/profiles/system"
JOURNAL = f"{PROFILE}/deployment/effects.journal"


@dataclass(frozen=True)
class NativeFlight:
    """Selects a matrix cell and an exact desired native graph effect."""

    cell: dict[str, Any]
    effect: str
    worktree: str
    unit: str
    selected_graph: dict[str, Any] | None = None


def read_bounded(path: str, maximum: int = 16 * 1024 * 1024) -> str:
    """Reads at most one byte beyond the document limit before rejecting it."""
    contents = runtime.succeed(f"{COREUTILS}/head --bytes={maximum + 1} {shlex.quote(path)}")
    if len(contents.encode()) > maximum:
        raise RuntimeError("native fixture document exceeds its read bound")
    return contents


def read_json(path: str) -> Any:
    """Reads a bounded fixture document through the guest's source-built tool."""
    return json.loads(read_bounded(path))


def write_canonical(path: str, value: Any) -> None:
    """Publishes root-owned controller configuration through its bounded helper."""
    runtime.succeed(f"{OBSERVER_CONTROLLER} write-canonical {shlex.quote(path)} {NATIVE_EVIDENCE.canonical(value).hex()}")


def select(flight: NativeFlight, boundary: str, sequence: str, action: str) -> None:
    """Selects one exact invocation and native execution boundary."""
    write_canonical(TARGET, {
        "action": action,
        "boundary": boundary,
        "effect": flight.effect,
        "invocation_action": flight.cell["action"],
        "sequence": sequence,
    })


def wait_held(flight: NativeFlight, sequence: str, boundary: str) -> dict[str, Any]:
    """Requires the selected exact event before collecting substrate evidence."""
    runtime.wait_until_succeeds(f"{JQ} -e --arg sequence {shlex.quote(sequence)} '.sequence == $sequence' {shlex.quote(HELD)}", timeout=900)
    held = read_json(HELD)
    event = held["event"]
    NATIVE_EVIDENCE.event_identity(event)
    if event["effect"] != flight.effect or event["action"] != flight.cell["action"] or event["boundary"] != boundary:
        raise RuntimeError("observer held another native invocation")
    return event


INTERCEPTION_ROOT = "/run/aos/native-handler-interception"


def arm_handler_response(operation: str) -> dict[str, Any]:
    """Arms the original retained fixture for the currently held exact invocation.

    Call this from prepare_block or a rejection injection hook while the actual
    native callback is held. This changes only protected fixture controls.
    """
    if operation not in {"apply", "remove", "observe"}:
        raise ValueError("invalid interception exchange")
    event = read_json(HELD)["event"]
    NATIVE_EVIDENCE.event_identity(event)
    control = {
        "schema": "aos.qualification.native-handler-barrier",
        "effect": event["effect"], "revision": event["revision"],
        "action": event["action"], "operation": operation,
    }
    runtime.succeed(f"{COREUTILS}/install -d -m 0700 {INTERCEPTION_ROOT}")
    runtime.succeed(f"{COREUTILS}/rm -f {INTERCEPTION_ROOT}/captured.json {INTERCEPTION_ROOT}/release.json")
    payload = NATIVE_EVIDENCE.canonical(control).hex()
    writer = (
        "import os; "
        f"p={INTERCEPTION_ROOT + '/armed.json'!r}; "
        "f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600); "
        f"os.write(f,bytes.fromhex({payload!r})); os.fsync(f); os.close(f)"
    )
    runtime.succeed(f"{PYTHON} -c {shlex.quote(writer)}")
    return control


def captured_handler_response(control: dict[str, Any]) -> dict[str, Any]:
    """Checks the exact independently captured real backend response receipt."""
    receipt = read_json(INTERCEPTION_ROOT + "/captured.json")
    required = set(control) | {"responseSha256", "responseSize"}
    if set(receipt) != required or receipt["schema"] != "aos.qualification.native-handler-response":
        raise RuntimeError("invalid native backend capture receipt")
    if any(receipt[key] != value for key, value in control.items() if key != "schema"):
        raise RuntimeError("native response capture belongs to another invocation")
    digest = receipt["responseSha256"]
    if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:") or any(character not in "0123456789abcdef" for character in digest[7:]):
        raise RuntimeError("invalid captured backend response digest")
    if type(receipt["responseSize"]) is not int or not 0 <= receipt["responseSize"] <= 16 * 1024 * 1024:
        raise RuntimeError("captured backend response exceeds its bound")
    return receipt


def start(flight: NativeFlight) -> None:
    """Applies the retained operator worktree through the ordinary native manager."""
    runtime.succeed(f"{SYSTEMCTL} reset-failed {shlex.quote(flight.unit)} 2>/dev/null || true")
    runtime.succeed(f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(flight.unit)} --property=Type=exec {APM} switch --worktree {shlex.quote(flight.worktree)} --eval-root /var/lib/aos/native-flights/{shlex.quote(flight.unit)}")


def stop_interrupted(flight: NativeFlight) -> None:
    """Kills only the controlled candidate manager while its observer is held."""
    runtime.succeed(f"{SYSTEMCTL} kill --signal=KILL --kill-whom=all {shlex.quote(flight.unit)}")
    runtime.wait_until_succeeds(f"! {SYSTEMCTL} is-active --quiet {shlex.quote(flight.unit)}", timeout=180)


def inspect() -> dict[str, Any]:
    """Uses the native checksum and replay reader without repairing the journal."""
    view = json.loads(runtime.succeed(f"{AOS} ability journal {shlex.quote(JOURNAL)} --format json"))
    NATIVE_EVIDENCE.checked_inspection(view)
    return view


def run(flight: NativeFlight, builder: Any, observe: Callable[[], dict[str, Any]], expected_selected: Any, launch: Callable[[NativeFlight], None] = start) -> None:
    """Retains actual interruption, recovery, and independent isolation evidence."""
    scenario = flight.cell["scenario"]["id"]
    boundary = NATIVE_EVIDENCE.SCENARIO_BOUNDARIES[scenario]
    sequence = flight.unit
    baseline_sequence = sequence + "-baseline"
    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(HELD)} {shlex.quote(CONTINUE)}")
    select(flight, "intent-durable", baseline_sequence, "pause")
    launch(flight)
    baseline_event = wait_held(flight, baseline_sequence, "intent-durable")
    baseline = observe()

    if boundary == "intent-durable":
        held = baseline_event
    else:
        select(flight, boundary, sequence, "disconnect")
        write_canonical(CONTINUE, {"sequence": baseline_sequence})
        held = wait_held(flight, sequence, boundary)
    unsettled = observe()
    stop_interrupted(flight)
    before = inspect()
    if before["desired"] is None:
        raise RuntimeError("candidate graph disappeared before interruption evidence")
    graph = flight.selected_graph if flight.selected_graph is not None else before["desired"]
    if flight.cell["action"] == "remove" and flight.selected_graph is None:
        raise RuntimeError("removal requires the authenticated retained predecessor graph")

    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(TARGET)}")
    launch(flight)
    runtime.wait_until_succeeds(f"test \"$({SYSTEMCTL} show --property=Result --value {shlex.quote(flight.unit)})\" = success && ! {SYSTEMCTL} is-active --quiet {shlex.quote(flight.unit)}", timeout=1200)
    after = inspect()
    settled = observe()
    boundaries = [json.loads(line) for line in read_bounded(EVENTS).splitlines()]
    builder.retain(flight.cell["id"], NATIVE_EVIDENCE.NativeObservation(graph, held, before, after, boundaries, baseline, unsettled, settled, expected_selected))


def failed_manager_receipt(flight: NativeFlight) -> dict[str, Any]:
    """Reads the failed manager unit without claiming a backend failure reason."""
    output = runtime.succeed(f"{SYSTEMCTL} show {shlex.quote(flight.unit)} --property=Result,ExecMainCode,ExecMainStatus")
    values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if values.get("Result") not in {"exit-code", "signal", "timeout"}:
        raise RuntimeError("candidate manager did not leave an actual failure receipt")
    return {
        "unit": flight.unit,
        "result": values["Result"],
        "execMainCode": int(values["ExecMainCode"]),
        "execMainStatus": int(values["ExecMainStatus"]),
    }


def wait_failed(flight: NativeFlight) -> None:
    """Waits for a failed controlled manager rather than accepting a timeout as proof."""
    runtime.wait_until_succeeds(
        f"! {SYSTEMCTL} is-active --quiet {shlex.quote(flight.unit)} && "
        f"{SYSTEMCTL} is-failed --quiet {shlex.quote(flight.unit)}",
        timeout=1200,
    )


def run_rejection(flight: NativeFlight, builder: Any, observe: Callable[[], dict[str, Any]], expected_selected: Any, inject: Callable[[], None], launch: Callable[[NativeFlight], None] = start, interruption_boundary: str = "dispatch-returned") -> None:
    """Collects real pending-intent failures and conservative dispatch attempt evidence."""
    scenario = flight.cell["scenario"]["id"]
    if scenario not in {"fail-manager-after-dispatch-attempt", "reject-uncertain-recovery", "reject-foreign-resource-mutation"}:
        raise ValueError("rejection flight has no concrete native evidence route")
    sequence = flight.unit
    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(HELD)} {shlex.quote(CONTINUE)}")
    select(flight, "intent-durable", sequence, "pause")
    launch(flight)
    held = wait_held(flight, sequence, "intent-durable")
    baseline = observe()

    if scenario in {"fail-manager-after-dispatch-attempt", "reject-foreign-resource-mutation"}:
        # Injection changes only the explicitly selected disposable substrate.
        # Its separate foreign witness must remain unchanged throughout.
        inject()
        if scenario == "reject-foreign-resource-mutation":
            injected = observe()
            if injected["foreign"] != baseline["foreign"]:
                raise RuntimeError("foreign-denial fixture changed its independent witness")
            baseline = injected
        write_canonical(CONTINUE, {"sequence": sequence})
        wait_failed(flight)
        before = inspect()
        after = inspect()
    else:
        if interruption_boundary not in {"dispatch-started", "dispatch-returned"}:
            raise ValueError("rejection interruption must select an actual native dispatch boundary")
        select(flight, interruption_boundary, sequence + "-interrupted", "disconnect")
        write_canonical(CONTINUE, {"sequence": sequence})
        wait_held(flight, sequence + "-interrupted", interruption_boundary)
        stop_interrupted(flight)
        before = inspect()
        inject()
        injected = observe()
        if injected["foreign"] != baseline["foreign"]:
            raise RuntimeError("negative fixture injection changed a foreign witness")
        baseline = injected
        runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(TARGET)}")
        launch(flight)
        wait_failed(flight)
        after = inspect()

    graph = flight.selected_graph if flight.selected_graph is not None else before["desired"]
    if graph is None or (flight.cell["action"] == "remove" and flight.selected_graph is None):
        raise RuntimeError("rejected invocation lacks its checked selected source graph")
    settled = observe()
    boundaries = [json.loads(line) for line in read_bounded(EVENTS).splitlines()]
    builder.retain_rejection(flight.cell["id"], NATIVE_EVIDENCE.NativeRejection(
        graph, held, before, after, boundaries, baseline, settled,
        expected_selected, failed_manager_receipt(flight),
    ))


def run_dependency_block(flight: NativeFlight, builder: Any, observe: Callable[[], dict[str, Any]], expected_selected: Any, dependent: str, observe_dependent: Callable[[], dict[str, Any]], inject: Callable[[], None], launch: Callable[[NativeFlight], None] = start) -> None:
    """Holds a real failed prerequisite while checking an authored live dependent.

    The injection may arm the original response barrier. Apply tests select a
    graph successor; removal tests select a predecessor in reverse retirement
    order. Each marker remains an independent live substrate observation.
    """
    if flight.cell["scenario"]["id"] != "block-dependent-effect" or flight.selected_graph is None:
        raise ValueError("dependency flight requires its authenticated original graph")
    sequence = flight.unit
    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(HELD)} {shlex.quote(CONTINUE)}")
    select(flight, "intent-durable", sequence, "pause")
    launch(flight)
    held = wait_held(flight, sequence, "intent-durable")
    baseline = observe()
    dependent_baseline = observe_dependent()
    inject()
    write_canonical(CONTINUE, {"sequence": sequence})
    wait_failed(flight)
    before = inspect()
    after = inspect()
    boundaries = [json.loads(line) for line in read_bounded(EVENTS).splitlines()]
    builder.retain_dependency_block(flight.cell["id"], NATIVE_EVIDENCE.NativeDependencyBlock(
        flight.selected_graph, held, before, after, boundaries, baseline,
        observe(), expected_selected, failed_manager_receipt(flight),
        dependent, dependent_baseline, observe_dependent(),
    ))


def run_pending_control(flight: NativeFlight, builder: Any, observe: Callable[[], dict[str, Any]], expected_selected: Any, prepare_block: Callable[[], None] | None = None, launch: Callable[[NativeFlight], None] = start) -> None:
    """Retains bounded requested cancellation or a real dispatched handler deadline.

    Deadline callers hold an independently controlled substrate lock or supply
    an authored blocking handler. An observer timeout is never a deadline proof.
    Each flight leaves the original pending journal intact for its fresh guest.
    """
    import time

    scenario = flight.cell["scenario"]["id"]
    if scenario not in {"cancel-pending-invocation", "expire-invocation-deadline"}:
        raise ValueError("pending control has no concrete native execution route")
    sequence = flight.unit
    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(HELD)} {shlex.quote(CONTINUE)}")
    select(flight, "intent-durable", sequence, "pause")
    launch(flight)
    held = wait_held(flight, sequence, "intent-durable")
    before = inspect()
    baseline = observe()
    graph = flight.selected_graph if flight.selected_graph is not None else before["desired"]
    if graph is None or (flight.cell["action"] == "remove" and flight.selected_graph is None):
        raise ValueError("pending control lacks its selected retained source graph")

    if scenario == "cancel-pending-invocation":
        process = int(runtime.succeed(f"{SYSTEMCTL} show --property=MainPID --value {shlex.quote(flight.unit)}").strip())
        if not 0 < process < 2**31:
            raise RuntimeError("cancellation target is not a live controlled manager")
        executable = runtime.succeed(f"{COREUTILS}/readlink /proc/{process}/exe").strip()
        if executable != APM:
            raise RuntimeError("cancellation target differs from the admitted package manager")
        # One signal targets only the APM main process. Its source-built signal
        # guard requests the shared token; a second signal would force an exit.
        runtime.succeed(f"{SYSTEMCTL} kill --signal=TERM --kill-whom=main {shlex.quote(flight.unit)}")
        control = {"kind": "signal-cancellation", "signal": "SIGTERM", "processId": process, "executable": executable}
    else:
        if prepare_block is None:
            raise ValueError("deadline requires an actual independently blocked handler substrate")
        prepare_block()
        started = time.monotonic()
        write_canonical(CONTINUE, {"sequence": sequence})
        wait_failed(flight)
        elapsed = int((time.monotonic() - started) * 1000)
        control = {"kind": "invocation-deadline", "timeoutMillis": graph["nodes"][flight.effect]["timeout_ms"], "elapsedMillis": elapsed}
    wait_failed(flight)
    after = inspect()
    settled = observe()
    boundaries = [json.loads(line) for line in read_bounded(EVENTS).splitlines()]
    builder.retain_pending_control(flight.cell["id"], NATIVE_EVIDENCE.NativePendingControl(
        graph, held, before, after, boundaries, baseline, settled,
        expected_selected, failed_manager_receipt(flight), control,
    ))


def successful_manager_receipt(flight: NativeFlight) -> dict[str, Any]:
    """Reads an actual completed manager unit without inventing an invocation."""
    output = runtime.succeed(f"{SYSTEMCTL} show {shlex.quote(flight.unit)} --property=Result,ExecMainCode,ExecMainStatus")
    values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    receipt = {"unit": flight.unit, "result": values.get("Result"),
               "execMainCode": int(values.get("ExecMainCode", "-1")),
               "execMainStatus": int(values.get("ExecMainStatus", "-1"))}
    if receipt["result"] != "success" or receipt["execMainCode"] != 1 or receipt["execMainStatus"] != 0:
        raise RuntimeError("source transition did not complete through the real package manager")
    return receipt


def run_retained_transition(flight: NativeFlight, builder: Any, observe: Callable[[], dict[str, Any]], expected_selected: Any, launch: Callable[[NativeFlight], None] = start) -> None:
    """Runs an ordinary source transition with original checked receipt custody.

    Callers supply the authenticated predecessor graph in ``selected_graph``.
    The worktree restores the exact original source, disables it without retire,
    or disables it with an explicit retire decision, according to the cell.
    This route never manufactures an intent for persistent source disappearance.
    """
    if flight.selected_graph is None:
        raise ValueError("retained transition requires its authenticated original source graph")
    runtime.succeed(f"{COREUTILS}/rm -f {shlex.quote(TARGET)}")
    before = inspect()
    desired_before = current_reference_graph()
    baseline = observe()
    launch(flight)
    runtime.wait_until_succeeds(f"test \"$({SYSTEMCTL} show --property=Result --value {shlex.quote(flight.unit)})\" = success && ! {SYSTEMCTL} is-active --quiet {shlex.quote(flight.unit)}", timeout=1200)
    after = inspect()
    desired_after = current_reference_graph()
    settled = observe()
    builder.retain_transition(flight.cell["id"], NATIVE_EVIDENCE.NativeRetainedTransition(
        flight.selected_graph, desired_before, desired_after, flight.effect,
        before, after, baseline, settled, expected_selected,
        successful_manager_receipt(flight),
    ))
