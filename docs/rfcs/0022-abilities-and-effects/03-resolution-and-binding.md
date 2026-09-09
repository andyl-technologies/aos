# Static matching and registry-driven late binding

## One contract at two binding times

| Stage | Source-defined output | Registry/APM deployment |
| --- | --- | --- |
| Inputs | Package/module source and selected target environment | Authenticated package/module artifacts, desired state, target inventory |
| Selection | Explicit Nix composition | Bounded Rust provider resolution within authorized candidates |
| Configuration | Evaluate with selected bindings | Evaluate authenticated modules with selected bindings |
| Validation | Nix assertions plus common AOS-built plan validator | The same semantic validator before activation |
| Result | Image/artifacts and pinned deployment contract | Candidate generation and pinned activation contract |
| Execution | Check deployment obligations and acquire handles | Revalidate inventory and acquire handles |

Static matching does not need to search for providers, but still checks ABI,
scope, ownership, conflicts, prerequisites, and guarantees. It proves
compatibility with the declared target, not with an arbitrary future launcher.

Late binding means delayed selection and effect execution, not arbitrary
post-install script execution. Downloading a module into the store is distinct
from selecting it in a live profile or activating its behavior.

## Registry flow

1. Authenticate the requested release, metadata, and referenced artifact graph.
2. Form a candidate desired package/instance set without changing live
   activation. Root downloaded candidate inputs against concurrent GC.
3. Read provider metadata and operator policy; distinguish explicit selections
   from providers eligible for resolution.
4. Fetch the exact restricted configuration modules needed for evaluation.
5. Evaluate concrete requests, including configuration-dependent requirements.
6. Select compatible authorized bindings and fetch newly required modules.
7. Repeat within explicit bounds until the request set and bindings stabilize.
8. Lower bound requests, validate the complete candidate, and compute its
   transition from current state.
9. Report the plan, missing deployment inputs, authority changes, and effects.
10. Acquire/revalidate resources, execute through the structured transaction,
    and record the actual outcome.

The existing resolve/evaluate loop is the starting point. Installing TLS-free
nginx should not require unused TLS credentials. Enabling TLS introduces those
requirements through evaluation. The same rule applies to configuration that
adds a device, endpoint, service dependency, or stronger enforcement request.

## Solver discipline

Provider selection uses finite authenticated candidates and a versioned,
bounded constraint language. Constraints cover interface compatibility,
platform, phase, environment, operations, guarantees, sharing/exclusivity, and
authorized resource scopes. Arbitrary Nix functions are not solver predicates.

Explicit bindings take precedence over search. A previously pinned binding is
preserved unless the requested transition changes it or makes it invalid.
Ambiguous eligible providers require explicit selection or a documented
operator selection policy; registry order and newest-version preference are
not implicit authority decisions.

Resolve against the complete candidate environment, not only additions. A
provider removal or upgrade can invalidate existing consumers. Resource
conflicts such as exclusive ports or storage slots are checked globally within
their actual scope. Explanation output identifies the smallest useful chain
of conflicting requirements, without promising a globally minimal proof.

Bound iterations, candidate expansion, graph depth, request count, serialized
size, and diagnostic size. Reject oscillation and impossible bootstrap cycles.
Requests whose presence depends on negating the provider selection require
explicit alternatives or rejection; they must not produce an unbounded
resolve/evaluate toggle.

## Provider state and bootstrap

A provider can be:

- **Declared:** its implementation and interface metadata are available.
- **Planned:** the deployment has a valid operation sequence to establish it.
- **Available:** a verified instance currently supplies the required facility.
- **Unavailable or stale:** its required resources or evidence are absent.

Installing systemd establishes a declared implementation, not an available
manager. A bootable system/container can plan to start a manager before its
consumers. An already-running application container cannot assume that
installing systemd changes PID 1 or grants cgroup control.

Every planned provider must have a bootstrap path grounded in existing or
explicitly promised environment resources. A requires B and B requires A is
not satisfied merely because both packages are in the store.

## Deployment obligations

Every required binding has an explicit result:

| Result | Meaning |
| --- | --- |
| Satisfied | Selected provider and environment implement the request |
| External obligation | Preparation may finish, but deployment must supply a specified resource |
| Unsupported | No authorized implementation satisfies the requirement |

A source-built OCI image can contain configuration and declare a runtime
secret or delegated cgroup requirement. Its launcher must supply and verify
those obligations before readiness. Missing inputs cannot trigger silent
selection of a weaker implementation.

An offline plan may use an explicit environment contract and report unverified
obligations. A cached observation has a scope, generation, and freshness
condition; it is not proof about another host or a later incarnation.

## Installation and activation behavior

Ordinary user-profile installation continues to make software available. It
does not automatically activate every exported service. Explicit workload
preparation can materialize a scoped environment without starting it.

Existing system desired-package operations remain high-level workflows that
also reconcile operator activation policy. Migration MUST preserve that
documented behavior rather than imposing a new confirmation ritual or silently
making previously enabled services inert.

The current desired-package code defers exposed-unit reconciliation while
adding/removing packages, but the new ability plan must validate the complete
candidate before changing the live activation selection. Store downloads and
candidate generation construction may precede this boundary. A failed
preflight must not partially apply package, credential, or service changes.

Container admission should eventually be operation-specific. A verified
container-local manager can authorize local package-service activation without
authorizing host reboot, TPM operations, module loading, or disk management.
Until those operation contracts are implemented and qualified, the current
blanket host-operation rejection remains in force. Unsetting a marker is not
a supported path to enable new behavior.

## Identity and reproducibility

Pin exact package and module artifacts, selected providers, handler versions,
interface contracts, source configuration, policy inputs, and target
environment commitments. Retain the derived binding plan with the generation.
Discovery must never detach a mapping from the release that authenticated it.

Reproducible planning means equal canonical inputs produce the same normalized
plan. Secret values and live descriptor numbers are not inputs to that public
plan identity. Their logical references and security requirements are retained;
private execution evidence is handled separately.

At execution, acquire resources under the relevant ownership/transaction
mechanism, then check preconditions immediately before effects. On drift,
replan or fail explicitly. A successful static check cannot waive a missing
runtime grant, and a past activation cannot authorize a future policy bypass.
