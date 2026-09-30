"""Runs native filesystem/configuration/firewall flights with live domain oracles.

Every selected effect is a concrete controlled fixture resource. Removal uses
its authenticated predecessor graph and explicit retirement; independent
foreign resources never pass through the selected backend invocation.
"""

import base64
import hashlib
import json
import shlex

DIRECTORY_OPERATIONS = {"directory", "allocate", "persistentAllocate", "entry"}
INTERRUPTION_SCENARIOS = {
    "interrupt-after-durable-intent",
    "lose-external-result",
    "interrupt-after-durable-outcome",
    "fail-manager-after-dispatch-attempt",
    "reject-uncertain-recovery",
    "reject-foreign-resource-mutation",
    "block-dependent-effect",
}
PENDING_SCENARIOS = {"cancel-pending-invocation", "expire-invocation-deadline"}
RETAINED_SCENARIOS = {
    "activate-retained-target",
    "retain-persistent-orphan",
    "retire-explicit-persistent-target",
}
SCENARIOS = INTERRUPTION_SCENARIOS | PENDING_SCENARIOS | RETAINED_SCENARIOS
ROOT = "/var/lib/aos/native-domain-qualification"


def supports(cell, adapter, graph):
    """Accepts only concrete operations with implemented substrate observations."""
    operation = cell["operation"]
    pair = (operation["ability"], operation["name"])
    scenario = cell["scenario"]["id"]
    if scenario == "activate-retained-target" and cell["action"] != "apply":
        return False
    if scenario in {"retain-persistent-orphan", "retire-explicit-persistent-target"}:
        if pair != ("filesystem", "persistentAllocate") or cell["action"] != "remove":
            return False
    return (
        (pair[0] == "filesystem" and pair[1] in DIRECTORY_OPERATIONS or pair in {("configuration", "file"), ("networkPolicy", "ruleset")})
        and cell["action"] in {"apply", "remove"}
        and cell["scenario"]["id"] in SCENARIOS
    )


def guest_oracle(request):
    """Executes source-backed observations inside the actual resource-owning guest."""
    program = base64.b64encode(NATIVE_FILESYSTEM_ORACLE_SOURCE.encode()).decode()
    launcher = "import base64;exec(compile(base64.b64decode(" + repr(program) + "),'<native-domain-oracle>','exec'))"
    return json.loads(runtime.succeed(f"{PYTHON} -c {shlex.quote(launcher)} {shlex.quote(json.dumps(request))}"))


def selected_effect(graph, ability, operation, adapter):
    """Requires one actual fixture identity with the retained matrix handler."""
    matches = []
    for effect, node in graph["nodes"].items():
        if node["identity"][-3:-1] != [ability, operation] or node["handler"] != adapter["handler"]:
            continue
        if ability == "networkPolicy" or node["identity"][-1] == "native-qualification":
            matches.append(effect)
    if len(matches) != 1:
        raise RuntimeError("native domain fixture has no unique selected effect")
    return matches[0]



def dependency_effect(graph, operation, relationship):
    """Selects the independently authored marker in the original checked graph."""
    expected = ["nativeDependencyBarrier", "ensure", relationship + "-" + operation]
    matches = [identity for identity, node in graph["nodes"].items() if node["identity"][-3:] == expected]
    if len(matches) != 1:
        raise RuntimeError("controlled dependency has no unique original marker")
    return matches[0]


def run_cell(cell, adapter, graph):
    """Collects real interruption/rejection receipts and independent live state."""
    if not supports(cell, adapter, graph):
        raise RuntimeError("native domain cell has no implemented concrete proof")
    ability = cell["operation"]["ability"]
    operation = cell["operation"]["name"]
    slug = hashlib.sha256(cell["id"].encode()).hexdigest()[:20]
    unit = "native-domain-" + slug
    baseline_worktree = write_reference_worktree(
        f"/var/lib/aos/native-worktrees/{unit}-baseline",
        extra_module=OBSERVER_HOST_MODULE,
    )
    apply_reference(baseline_worktree, unit + "-baseline")
    predecessor = current_reference_graph()
    effect = selected_effect(predecessor, ability, operation, adapter)
    admitted_effect = selected_effect(graph, ability, operation, adapter)
    if predecessor["nodes"][effect] != graph["nodes"][admitted_effect]:
        raise RuntimeError("controlled baseline differs from its original selected target")
    scenario = cell["scenario"]["id"]
    firewall = ability == "networkPolicy"
    configuration = ability == "configuration"
    selected = f"{ROOT}-{operation}"
    foreign = "aos_qualification_" + slug if firewall else f"{ROOT}-foreign-{slug}"
    if firewall:
        runtime.succeed(f"{NFT} add table inet {foreign}")
        runtime.succeed(f"{NFT} add chain inet {foreign} independent")
        runtime.succeed(f"{NFT} add rule inet {foreign} independent tcp dport 18193 accept")
        request = {"domain": "firewall", "nft": NFT, "foreign": foreign}
    else:
        runtime.succeed(f"{COREUTILS}/install -m 0600 /dev/null {shlex.quote(foreign)}")
        runtime.succeed(f"{COREUTILS}/printf 'independent-foreign-witness\\n' > {shlex.quote(foreign)}")
        request = {"domain": "configuration" if configuration else "filesystem", "selected": selected, "foreign": foreign}
    request["identity"] = (
        scenario in PENDING_SCENARIOS | RETAINED_SCENARIOS | {"reject-foreign-resource-mutation"}
        and scenario != "expire-invocation-deadline"
    )
    observe = lambda: guest_oracle(request)
    baseline = observe()["selected"]
    if not baseline.get("claimMatches") or baseline.get("owners") != [effect]:
        raise RuntimeError("controlled baseline lacks matching independent backend ownership")

    removal = {"aos": {"activation": {"retire": [effect]}}}
    if firewall:
        removal["aos"]["networkPolicy"] = {"enable": False}
    else:
        removal["aos"]["nativeDomainQualification"] = {"enabled": {operation: False}}
    if scenario == "block-dependent-effect" and cell["action"] == "remove":
        # Remove the independently authored parent declaration as well. Native
        # retirement reverses the original graph edge, so a failed selected
        # removal must leave that real prerequisite marker untouched.
        removal["aos"].setdefault("nativeDomainQualification", {})["dependencyParents"] = {operation: False}
    removal_worktree = write_reference_worktree(
        f"/var/lib/aos/native-worktrees/{unit}-removed",
        removal,
        extra_module=OBSERVER_HOST_MODULE,
    )
    if scenario in RETAINED_SCENARIOS:
        candidate = baseline_worktree
        expected = dict(baseline)
        if scenario != "activate-retained-target":
            orphan = {"aos": {"nativeDomainQualification": {"enabled": {operation: False}}}}
            orphan_worktree = write_reference_worktree(
                f"/var/lib/aos/native-worktrees/{unit}-orphan", orphan,
                extra_module=OBSERVER_HOST_MODULE,
            )
            candidate = orphan_worktree
            if scenario == "retire-explicit-persistent-target":
                apply_reference(orphan_worktree, unit + "-orphan")
                if observe()["selected"] != baseline:
                    raise RuntimeError("persistent orphan changed its original owned resource")
                candidate = removal_worktree
                expected = {"exists": False, "owners": []}
        flight = NATIVE_FLIGHT.NativeFlight(cell, effect, candidate, unit, predecessor)
        NATIVE_FLIGHT.run_retained_transition(flight, NATIVE_BUILDER, observe, expected)
        return

    if cell["action"] == "apply":
        if cell["scenario"].get("family") == "rollout-durability":
            # Only the predecessor varies. The candidate remains the exact
            # source and revision bound by the selected evaluation and matrix.
            original_input = predecessor["nodes"][effect]["input"]
            if firewall:
                original_ports = set(original_input["allowedTCP"])
                old_port = next(port for port in (18191, 18194) if port not in original_ports)
                settings = {"aos": {"nativeDomainQualification": {"firewallPort": old_port}}}
            elif configuration:
                settings = {"aos": {"nativeDomainQualification": {"content": "native-domain-predecessor\n"}}}
            else:
                old_mode = "0711" if original_input["mode"] != "0711" else "0700"
                settings = {"aos": {"nativeDomainQualification": {"mode": old_mode}}}
            old_worktree = write_reference_worktree(
                f"/var/lib/aos/native-worktrees/{unit}-predecessor", settings,
                extra_module=OBSERVER_HOST_MODULE,
            )
            apply_reference(old_worktree, unit + "-prepare")
            old_graph = current_reference_graph()
            old_node = old_graph["nodes"].get(effect)
            if (
                old_node is None
                or old_node["handler"] != adapter["handler"]
                or old_node["revision"] == predecessor["nodes"][effect]["revision"]
            ):
                raise RuntimeError("update predecessor has no distinct admitted revision with the selected handler")
            old_reading = observe()["selected"]
            if not old_reading.get("claimMatches") or old_reading.get("owners") != [effect]:
                raise RuntimeError("update predecessor lacks independent matching ownership")
        else:
            apply_reference(removal_worktree, unit + "-prepare")
            absent = observe()["selected"]
            if absent != {"exists": False, "owners": []}:
                raise RuntimeError("controlled resource was not released before creation flight")
        candidate = baseline_worktree
        expected = dict(baseline)
    else:
        candidate = removal_worktree
        expected = {"exists": False, "owners": []}
    flight = NATIVE_FLIGHT.NativeFlight(
        cell, effect, candidate, unit,
        predecessor if cell["action"] == "remove" or scenario == "block-dependent-effect" else None,
    )

    if scenario == "block-dependent-effect":
        relationship = "child" if cell["action"] == "apply" else "parent"
        dependent = dependency_effect(predecessor, operation, relationship)
        dependency_request = {
            "domain": "dependency",
            "selected": "/var/lib/aos/native-dependency-barrier/" + relationship + "-" + operation,
            "witness": request,
        }
        def observe_dependent():
            reading = guest_oracle(dependency_request)
            selected_marker = reading["selected"]
            exists = cell["action"] == "remove"
            if selected_marker.get("exists") != exists or selected_marker.get("owners") != ([dependent] if exists else []):
                raise RuntimeError("dependency marker differs from its independently owned action baseline")
            return reading
        armed = []
        def inject():
            armed.append(NATIVE_FLIGHT.arm_handler_response(cell["action"]))
        NATIVE_FLIGHT.run_dependency_block(
            flight, NATIVE_BUILDER, observe, expected,
            dependent, observe_dependent, inject,
        )
        NATIVE_FLIGHT.captured_handler_response(armed[0])
        return

    if scenario in PENDING_SCENARIOS:
        unchanged = observe()["selected"]
        interception = []
        def prepare_block():
            # The original admitted wrapper completes real convergence, then
            # holds this invocation's transport until the manager deadline.
            # Backend lock budgets cannot race this controlled deadline.
            interception.append(NATIVE_FLIGHT.arm_handler_response(cell["action"]))
        NATIVE_FLIGHT.run_pending_control(
            flight, NATIVE_BUILDER, observe,
            expected if scenario == "expire-invocation-deadline" else unchanged,
            prepare_block=prepare_block if scenario == "expire-invocation-deadline" else None,
        )
        if interception:
            NATIVE_FLIGHT.captured_handler_response(interception[0])
        # A pending-control guest keeps the actual failed transaction intact;
        # restoring through it would erase the scenario's custody boundary.
        return

    if scenario in {"fail-manager-after-dispatch-attempt", "reject-uncertain-recovery", "reject-foreign-resource-mutation"}:
        dispatched_removal = scenario == "reject-uncertain-recovery" and cell["action"] == "remove"
        unclaimed_conflict = dispatched_removal or scenario in {"fail-manager-after-dispatch-attempt", "reject-foreign-resource-mutation"} and cell["action"] == "apply"
        if firewall:
            expected = dict(baseline, claimMatches=False)
            def inject():
                if unclaimed_conflict:
                    runtime.succeed(f"{NFT} add table inet aos_filter")
                    runtime.succeed(f"{NFT} 'add chain inet aos_filter input {{ type filter hook input priority 0; policy accept; }}'")
                runtime.succeed(f"{NFT} add rule inet aos_filter input tcp dport 18192 accept")
            if unclaimed_conflict:
                expected = {"exists": True, "owners": [], "policies": {"input": "accept"}, "tcp": [18192], "udp": [], "claimMatches": False}
            else:
                expected["tcp"] = sorted(set(baseline["tcp"]) | {18192})
        elif configuration:
            expected = dict(baseline, digest="sha256:" + hashlib.sha256(b"foreign-selected-drift\n").hexdigest(), claimMatches=False)
            def inject():
                runtime.succeed(f"{COREUTILS}/printf 'foreign-selected-drift\\n' > {shlex.quote(selected)}; {COREUTILS}/chmod 0640 {shlex.quote(selected)}")
        else:
            expected = dict(baseline, mode="0711", claimMatches=False)
            def inject():
                runtime.succeed(f"if test -e {shlex.quote(selected)}; then {COREUTILS}/mv {shlex.quote(selected)} {shlex.quote(selected + '-displaced')}; fi; {COREUTILS}/mkdir -m 0711 {shlex.quote(selected)}")
        if unclaimed_conflict:
            expected["owners"] = []
        if scenario == "reject-foreign-resource-mutation":
            mutate = inject
            def inject():
                mutate()
                # Capture the real foreign target before dispatch. Refusal
                # must preserve its complete inode or kernel identity, rather
                # than merely match the original requested mode or ports.
                foreign_target = observe()["selected"]
                if foreign_target.get("claimMatches") is not False:
                    raise RuntimeError("foreign target still matches its original backend claim")
                expected.clear()
                expected.update(foreign_target)
        NATIVE_FLIGHT.run_rejection(flight, NATIVE_BUILDER, observe, expected, inject)
    else:
        NATIVE_FLIGHT.run(flight, NATIVE_BUILDER, observe, expected)

    # Restore through the normal manager. Foreign sentinels are removed only by
    # their independent fixture owner after the complete isolation observation.
    if scenario in {"fail-manager-after-dispatch-attempt", "reject-uncertain-recovery", "reject-foreign-resource-mutation"}:
        return  # The dedicated rejection guest retains its pending journal as evidence.
    apply_reference(baseline_worktree, unit + "-restore")
    runtime.succeed(f"{NFT} delete table inet {foreign}" if firewall else f"{COREUTILS}/rm {shlex.quote(foreign)}")
