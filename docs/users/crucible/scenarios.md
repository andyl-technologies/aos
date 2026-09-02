# Scenarios

A scenario is an immutable, content-addressed test definition. It describes a
closed world and contains no live handles, host clocks, mutable process state,
or implicit host-tool lookup.

## The four layers

### World

The world declares VM nodes, logical links, deterministic link characteristics,
and device sub-nodes. Node configuration includes architecture, memory, vCPU
count, instruction-count shift, kernel command line, and ready-point policy.

The topology's objects are declared before the run. Signal bindings may change
route, association, availability, lifecycle, and isolation state during
execution, but they cannot create an undeclared VM, interface, segment, path,
or device.

### Plan

The plan declares the signal program, typed fault bindings, and timed or
condition-triggered control actions. Signals and mappings determine when an
effect contributes; control actions start or stop nodes, arm timers, create
savepoints, fork, log, or terminate the scenario. There is no separate fault
activation or healing command.

The plan is not the schedule. Probabilistic choices, competing events, and
exploration overrides are resolved into the schedule as the run executes.

### Properties

Properties are named temporal assertions over observations. The supported model
includes invariants and reachability-style quantifiers such as `Always`,
`Sometimes`, `Eventually`, `AfterQuiescence`, and `Reachable`.

The host assertion evaluator consumes deterministic observations such as node
lifecycle, modeled network events, guest console output, and structured
guest-assertion markers. Application and test code should normally report its
own semantic results with the static `crucible-guest` emitter (or its thin
library) and a declared `GuestMarker` property. The QEMU plugin records the
doorbell marker at its exact retired-instruction count and the same assertion
evaluator publishes its `AssertionState` transition.

Use `ConsoleMatch` when exercising an opaque or entirely prebuilt workload that
already prints a stable result. Use `NetworkMatch` for transport and topology
properties, not to infer an application result from plaintext protocol bytes.
This distinction keeps application assertions valid for encrypted protocols
while preserving a zero-guest-component black-box path.

The built-in partition-recovery, crash-restart, and fault-campaign examples use
this structured guest-assertion path for application semantics. Their host-side
graphs still own readiness, lifecycle, signal and binding state, timers, I/O
facts, and quiescence. The happy-path example remains the intentionally opaque
`ConsoleMatch` reference case.

### Seed

The seed is part of scenario identity and roots every deterministic random
stream. A different seed is a different scenario execution identity, even when
the topology and plan are otherwise unchanged.

## Authoring surfaces

Use the Rust model API when a scenario is generated, composed from templates,
or checked into a Rust test. Construct a `World`, `Plan`, and `Properties`, then
pass them to `ScenarioDefForm::from_components`. Its `to_canonical_toml` method
produces the exchange form accepted by the CLI. The
[Nginx/Curl tutorial](quickstart.md) provides a complete fault-free generator.
For signal-driven experiments, [Authoring fault scenarios](authoring.md) covers
the additional `WorldFaultTopology`, `SignalProgram`, `FaultBinding`, target
resolution, and artifact-store steps.

`ScenarioBuilder` is useful when code only needs an immutable `ScenarioDef`
identity. Its `build` method does not retain the full form needed for TOML
serialization, so file generators should use `ScenarioDefForm` directly.

Canonical TOML is the CLI and storage format. Its top-level sections are:

```toml
[scenario]
# Content identity, seed, and application-random draw cap.

[world]
# VM nodes, I/O sub-nodes, and links.

[plan]
# Signal programs, typed bindings, and an event graph.

[properties]
# Named assertions.
```

This is a structural sketch, not a complete scenario: canonical documents carry
derived IDs and complete content-addressed artifact references. Generate them
through the Rust model rather than inventing IDs by hand. The CLI currently has
no command that exports a built-in scenario as TOML.

## CLI input resolution

Commands that accept `SCENARIO` resolve it in this order:

1. `blake3:<hash>` loads a canonical scenario object from `--store`.
2. An existing regular file is parsed as canonical UTF-8 TOML.
3. A recognized built-in name is materialized in process.
4. Any other value is rejected as a missing scenario.

The older `crucible-hash:<hash>` spelling is rejected for scenario input. Use a
`blake3:<hash>` DAG-store reference.

The built-in scenario aliases are:

```text
builtin:happy-path.scn       happy-path.scn       happy-path
builtin:partition-recovery.scn
builtin:crash-restart.scn
```

`fault-campaign.fam`, `fault-campaign`, and `builtin:fault-campaign` identify
the built-in scenario family where a command accepts a family.

## Packaged guest assets

The current local QEMU lifecycle launches nodes with one packaged kernel and
one packaged root image. Override them process-wide with:

```text
CRUCIBLE_KERNEL
CRUCIBLE_ROOT_IMAGE
CRUCIBLE_RUN_STATE_ROOT writable durable directory
CRUCIBLE_INITRD          optional
CRUCIBLE_KERNEL_CMDLINE
```

The package supplies compile-time defaults for the kernel, root image, and
kernel command line. `CRUCIBLE_RUN_STATE_ROOT` has no ephemeral fallback: it
retains the per-run process manifest and lifecycle journal used to detect a
concurrent owner, contain an interrupted QEMU generation, and fail closed on a
corrupt recovery record. Per-node kernel and root-image references remain part of
scenario identity, but current production launch configuration does not select
different host files for different nodes. Do not document heterogeneous guest
images as an operationally supported workflow yet.

## Workloads belong in the guest

Put workload selection, request counts, rates, and workload-specific seeds in
content-addressed guest configuration or the kernel command line. Crucible
observes guest-originated network and I/O activity and applies modeled faults to
it. Host-side traffic generation would sit outside the deterministic execution
boundary.

## Validation

Scenario parsing validates the complete definition before execution. Typical
failures include:

- duplicate node IDs or invalid link endpoints;
- link latency below the deterministic minimum, or jitter that crosses it;
- invalid loss or bandwidth values;
- references to missing nodes, links, assertions, signals, or bindings;
- invalid ready-point, vCPU, or instruction-count configuration;
- malformed content-addressed artifact references; and
- mismatched derived IDs in canonical TOML.

Malformed derived-ID diagnostics name the offending field, such as `world.id`.
When a derived ID is well formed but stale, the diagnostic prints both the
serialized value and the recomputed content hash so an authoring tool can
identify exactly which generated section changed. Do not copy the recomputed
hash into a hand-authored sketch: regenerate the complete canonical document
from `ScenarioDefForm` so all dependent identities remain consistent.

An invalid scenario exits with status `5`. Fix the definition; do not treat the
error as a backend failure.
