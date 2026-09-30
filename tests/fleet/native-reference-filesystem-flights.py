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
SCENARIOS = {"interrupt-after-durable-intent", "lose-external-result", "interrupt-after-durable-outcome", "fail-manager-after-dispatch-attempt", "reject-indeterminate-replay"}
ROOT = "/var/lib/aos/native-domain-qualification"


def supports(cell, adapter, graph):
    """Accepts only concrete operations with implemented substrate observations."""
    operation = cell["operation"]
    pair = (operation["ability"], operation["name"])
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


def run_cell(cell, adapter, graph):
    """Collects real interruption/rejection receipts and independent live state."""
    if not supports(cell, adapter, graph):
        raise RuntimeError("native domain cell has no implemented concrete proof")
    ability = cell["operation"]["ability"]
    operation = cell["operation"]["name"]
    slug = hashlib.sha256(cell["id"].encode()).hexdigest()[:20]
    unit = "native-domain-" + slug
    baseline_worktree = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-baseline")
    apply_reference(baseline_worktree, unit + "-baseline")
    predecessor = current_reference_graph()
    effect = selected_effect(predecessor, ability, operation, adapter)
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
    observe = lambda: guest_oracle(request)
    baseline = observe()["selected"]
    if not baseline.get("claimMatches") or baseline.get("owners") != [effect]:
        raise RuntimeError("controlled baseline lacks matching independent backend ownership")

    removal = {"aos": {"activation": {"retire": [effect]}}}
    if firewall:
        removal["aos"]["networkPolicy"] = {"enable": False}
    else:
        removal["aos"]["nativeDomainQualification"] = {"enabled": {operation: False}}
    removal_worktree = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-removed", removal)
    if cell["action"] == "apply":
        # Recreate the original admitted revision. Reconfiguration requires its
        # own candidate evaluation and matrix, rather than borrowing this one.
        apply_reference(removal_worktree, unit + "-prepare")
        absent = observe()["selected"]
        if absent != {"exists": False, "owners": []}:
            raise RuntimeError("controlled resource was not released before creation flight")
        candidate = baseline_worktree
        expected = dict(baseline)
    else:
        candidate = removal_worktree
        expected = {"exists": False, "owners": []}
    flight = NATIVE_FLIGHT.NativeFlight(cell, effect, candidate, unit, predecessor if cell["action"] == "remove" else None)

    scenario = cell["scenario"]["id"]
    if scenario in {"fail-manager-after-dispatch-attempt", "reject-indeterminate-replay"}:
        dispatched_removal = scenario == "reject-indeterminate-replay" and cell["action"] == "remove"
        unclaimed_conflict = dispatched_removal or scenario == "fail-manager-after-dispatch-attempt" and cell["action"] == "apply"
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
        NATIVE_FLIGHT.run_rejection(flight, NATIVE_BUILDER, observe, expected, inject)
    else:
        NATIVE_FLIGHT.run(flight, NATIVE_BUILDER, observe, expected)

    # Restore through the normal manager. Foreign sentinels are removed only by
    # their independent fixture owner after the complete isolation observation.
    if scenario in {"fail-manager-after-dispatch-attempt", "reject-indeterminate-replay"}:
        return  # The dedicated rejection guest retains its pending journal as evidence.
    apply_reference(baseline_worktree, unit + "-restore")
    runtime.succeed(f"{NFT} delete table inet {foreign}" if firewall else f"{COREUTILS}/rm {shlex.quote(foreign)}")
