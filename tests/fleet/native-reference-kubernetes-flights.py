"""Runs native Kubernetes flights against independent API and physical oracles.

The cluster remains running while a disposable ConfigMap or configuration file
changes. Removal selects its retained predecessor graph; unrelated cluster
objects and configuration files remain under a separate fixture owner.
"""

import base64
import hashlib
import json
import shlex

OPERATIONS = {("kubernetes", "ensure"), ("k3sConfiguration", "ensure")}
SCENARIOS = {"interrupt-after-durable-intent", "lose-external-result", "interrupt-after-durable-outcome",
             "fail-manager-after-dispatch-attempt", "reject-uncertain-recovery", "reject-foreign-resource-mutation",
             "cancel-pending-invocation", "expire-invocation-deadline", "activate-retained-target",
             "retain-persistent-orphan", "retire-explicit-persistent-target", "block-dependent-effect"}
KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
SELECTED_OBJECT = "native-qualification-owned"
SELECTED_CONFIGURATION = "/run/aos/k3s/qualification.json"
FOREIGN_OWNER = "sha256:" + "b" * 64


def supports(cell, adapter, graph):
    """Accepts only cells with an implemented conservative native proof route."""
    return (tuple(cell["operation"][key] for key in ("ability", "name")) in OPERATIONS
            and cell["action"] in {"apply", "remove"}
            and cell["scenario"]["id"] in SCENARIOS
            and (cell["action"] == "apply" or cell["scenario"]["id"] != "activate-retained-target")
            and (cell["action"] == "remove" or cell["scenario"]["id"] not in {
                "retain-persistent-orphan", "retire-explicit-persistent-target"}))


def observe_guest(request):
    """Runs the source-backed domain oracle inside the actual cluster guest."""
    encoded = base64.b64encode(KUBERNETES_ORACLE_SOURCE.encode()).decode()
    launcher = "import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<native-kubernetes-oracle>','exec'))"
    return json.loads(runtime.succeed(f"{PYTHON} -c {shlex.quote(launcher)} {shlex.quote(json.dumps(request))}"))


def selected_effect(graph, adapter, ability):
    matches = [effect for effect, node in graph["nodes"].items()
               if node["identity"][-3:] == [ability, "ensure", "native-qualification"]
               and node["handler"] == adapter["handler"]]
    if len(matches) != 1:
        raise RuntimeError("Kubernetes cohort lacks a unique controlled native effect")
    return matches[0]


def content_digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run_cell(cell, adapter, graph):
    """Collects real interrupted manager flights with an explicit expected target."""
    if not supports(cell, adapter, graph):
        raise RuntimeError("Kubernetes cell has no implemented native observation route")
    slug = hashlib.sha256(cell["id"].encode()).hexdigest()[:20]
    unit = "native-kubernetes-" + slug
    baseline_worktree = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-baseline", extra_module=OBSERVER_HOST_MODULE)
    apply_reference(baseline_worktree, unit + "-baseline")
    predecessor = current_reference_graph()
    ability = cell["operation"]["ability"]
    effect = selected_effect(predecessor, adapter, ability)
    kubernetes = ability == "kubernetes"
    foreign = "native-qualification-foreign-" + slug if kubernetes else f"/run/aos/k3s/foreign-{slug}.json"
    if kubernetes:
        runtime.succeed(f"{KUBECTL} --kubeconfig {KUBECONFIG} --namespace default create configmap {foreign} --from-literal=message=foreign")
        request = {"domain": ability, "kubectl": KUBECTL, "kubeconfig": KUBECONFIG,
                   "namespace": "default", "selected": SELECTED_OBJECT, "foreign": foreign}
    else:
        runtime.succeed(f"{COREUTILS}/printf '%s' '{{\"foreign\":true}}' > {shlex.quote(foreign)}; {COREUTILS}/chmod 0600 {shlex.quote(foreign)}")
        request = {"domain": ability, "selected": SELECTED_CONFIGURATION, "foreign": foreign}
    observe = lambda: observe_guest(request)
    baseline = observe()["selected"]
    if not baseline["exists"] or len(baseline["owners"]) != 1 or (not kubernetes and not baseline["claimMatches"]):
        raise RuntimeError("controlled Kubernetes baseline lacks independent physical ownership")

    # The immutable matrix describes the target. A separate retained source
    # establishes a real changed predecessor before applying that exact target.
    target_expected = dict(baseline)
    if kubernetes:
        declared_digest = content_digest({"data": {"message": "baseline"}, "binaryData": {}})
        if target_expected["contentDigest"] != declared_digest:
            raise RuntimeError("Kubernetes baseline differs from the explicitly authored target")
    else:
        declared_digest = content_digest({
            "flannel-backend": "vxlan", "disable-network-policy": False,
            "disable-kube-proxy": False,
            "node-label": ["qualification.andyl.com/generation=baseline"],
        })
        if target_expected["digest"] != declared_digest:
            raise RuntimeError("K3s baseline differs from the explicitly authored target")
    settings = {"aos": {"nativeKubernetesQualification": {}}}
    target = settings["aos"]["nativeKubernetesQualification"]
    scenario = cell["scenario"]["id"]
    if scenario == "activate-retained-target":
        candidate = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-reuse", extra_module=OBSERVER_HOST_MODULE)
        flight = NATIVE_FLIGHT.NativeFlight(cell, effect, candidate, unit, predecessor)
        NATIVE_FLIGHT.run_retained_transition(flight, NATIVE_BUILDER, observe, target_expected)
        return
    if scenario in {"retain-persistent-orphan", "retire-explicit-persistent-target"}:
        target["objects" if kubernetes else "configuration"] = False
        explicit = scenario == "retire-explicit-persistent-target"
        if explicit:
            settings["aos"]["activation"] = {"retire": [effect]}
        expected = {"exists": False, "owners": []} if explicit else target_expected
        candidate = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-retained", settings, extra_module=OBSERVER_HOST_MODULE)
        flight = NATIVE_FLIGHT.NativeFlight(cell, effect, candidate, unit, predecessor)
        NATIVE_FLIGHT.run_retained_transition(flight, NATIVE_BUILDER, observe, expected)
        return
    if cell["action"] == "remove":
        target["objects" if kubernetes else "configuration"] = False
        settings["aos"]["activation"] = {"retire": [effect]}
        expected = {"exists": False, "owners": []}
    else:
        prior = write_reference_worktree(
            f"/var/lib/aos/native-worktrees/{unit}-predecessor",
            extra_module=OBSERVER_HOST_MODULE + " imports = [ " + NATIVE_KUBERNETES_PREDECESSOR_SOURCE + " ];",
        )
        apply_reference(prior, unit + "-predecessor")
        baseline = observe()["selected"]
        if baseline == target_expected:
            raise RuntimeError("native update predecessor did not change the physical selected target")
        expected = target_expected
    candidate = write_reference_worktree(f"/var/lib/aos/native-worktrees/{unit}-candidate", settings, extra_module=OBSERVER_HOST_MODULE)
    flight = NATIVE_FLIGHT.NativeFlight(cell, effect, candidate, unit, predecessor if cell["action"] == "remove" else None)
    if scenario == "block-dependent-effect":
        marker = ("kubernetes" if kubernetes else "configuration") + ("-child" if cell["action"] == "apply" else "-parent")
        candidates = [key for key, node in predecessor["nodes"].items()
                      if node["identity"][-3:] == ["nativeDependencyBarrier", "ensure", marker]]
        if len(candidates) != 1:
            raise RuntimeError("Kubernetes fixture lacks its actual action-ordered dependency marker")
        foreign_marker = "/var/lib/aos/native-dependency-barrier/foreign-" + slug
        runtime.succeed(f"{COREUTILS}/printf '%s' 'independent foreign marker' > {shlex.quote(foreign_marker)}; {COREUTILS}/chmod 0600 {shlex.quote(foreign_marker)}")
        dependent_request = {"domain": "nativeDependencyBarrier", "selected": "/var/lib/aos/native-dependency-barrier/" + marker,
                             "foreign": foreign_marker}
        control = {}
        def inject():
            control.update(NATIVE_FLIGHT.arm_handler_response(cell["action"]))
        # Apply binds the already authenticated original target graph; removal
        # retains that same predecessor while its desired graph retires it.
        flight = NATIVE_FLIGHT.NativeFlight(cell, effect, candidate, unit, predecessor)
        NATIVE_FLIGHT.run_dependency_block(flight, NATIVE_BUILDER, observe, expected,
                                          candidates[0], lambda: observe_guest(dependent_request), inject)
        NATIVE_FLIGHT.captured_handler_response(control)
    elif scenario == "expire-invocation-deadline":
        control = {}
        def prepare_block():
            control.update(NATIVE_FLIGHT.arm_handler_response(cell["action"]))
        NATIVE_FLIGHT.run_pending_control(flight, NATIVE_BUILDER, observe, expected, prepare_block=prepare_block)
        # The barrier holds the real backend's captured response after its
        # physical mutation, exercising the manager's actual invocation budget.
        NATIVE_FLIGHT.captured_handler_response(control)
    elif scenario == "cancel-pending-invocation":
        NATIVE_FLIGHT.run_pending_control(flight, NATIVE_BUILDER, observe, baseline)
    elif scenario in {"fail-manager-after-dispatch-attempt", "reject-uncertain-recovery", "reject-foreign-resource-mutation"}:
        # This injection proves pending intent after a manager failure. It does
        # not infer that an attempt callback proves a backend invocation ran.
        expected = dict(expected if scenario == "reject-uncertain-recovery" and cell["action"] == "apply" else baseline)
        if kubernetes:
            expected["owners"] = [FOREIGN_OWNER]
            def inject():
                runtime.succeed(f"{KUBECTL} --kubeconfig {KUBECONFIG} --namespace default annotate configmap {SELECTED_OBJECT} aos.andyl.com/object-set-owner={FOREIGN_OWNER} --overwrite")
        else:
            expected["digest"] = "sha256:" + hashlib.sha256(b"foreign-selected-drift\n").hexdigest()
            expected["claimMatches"] = False
            def inject():
                runtime.succeed(f"{COREUTILS}/printf 'foreign-selected-drift\\n' > {SELECTED_CONFIGURATION}")
        NATIVE_FLIGHT.run_rejection(flight, NATIVE_BUILDER, observe, expected, inject,
                                  interruption_boundary="dispatch-started" if cell["action"] == "remove" else "dispatch-returned")
    else:
        NATIVE_FLIGHT.run(flight, NATIVE_BUILDER, observe, expected)
        runtime.succeed(f"{KUBECTL} --kubeconfig {KUBECONFIG} get --raw=/readyz")
