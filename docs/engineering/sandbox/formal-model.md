# Formal model

The Lean project in `formal/sandbox/` is the specification of the local
sandbox's store updates, Nix daemon proxy, lifecycle, and request
authorization. It states each component's state and operations as
definitions, states the properties those components must keep as theorems,
and proves them. The proofs are checked whenever the project builds.

The model uses only Lean's core library. It is built by the AOS
[`lean4`](../../../pkgs/toolchain/lean4.nix) package and has no Lake
dependencies, so building it never reaches the network.

## Modules

| Module | Contents |
| --- | --- |
| `Sandbox.Relation` | Reflexive transitive closure of a step relation and its invariant principle. |
| `Sandbox.Store.Closure` | The store reference graph, the closure of a root list, closed mount sets, and the executable `closure?`. |
| `Sandbox.Store.Reconcile` | Mount changes, their safety guards, the dependency-ordered planner `plan`, and its soundness, completeness, and crash-restart theorems. |
| `Sandbox.Store.Update` | GC roots, the host state with a concurrent garbage collector, and the full update `procedure`. |
| `Sandbox.Proxy` | The closure-mode Nix daemon proxy. |
| `Sandbox.Lifecycle` | The sandbox phase table. |
| `Sandbox.Authz` | Request dispatch in `aos-sandboxd`. |
| `SandboxAudit` | Fails the build when a model declaration depends on a nonstandard axiom. |
| `Main` | `sandbox-model`, the executable reference model. |

## What is proved

The theorems an implementation relies on:

| Theorem | Statement |
| --- | --- |
| `closure?_spec` | Any closure `closure?` returns is exactly the set of paths reachable from the roots. |
| `plan_safe` | Every mount set an applied plan passes through is closed under references. |
| `plan_run` | An applied plan ends with exactly the target mounted. |
| `plan_complete` | On a store with ranked references, a plan from any mount set to any closed target exists. |
| `plan_restart` | A plan interrupted after any change leaves a closed mount set from which a new plan exists. |
| `procedure_exec` | Executing the update with any interleaving of garbage collection and builds keeps every mounted path valid and the mount set closed, and ends with exactly the desired roots and their closure. |
| `procedure_crash` | An update interrupted after any action, with any concurrent host steps, leaves a safe host from which a new update exists. |
| `realize_visible` | After the proxy acknowledges a build, every output's closure is mounted. |
| `handle_monotone` | The proxy never removes a desired root. |
| `copy_quiescent` | A snapshot or fork copies the writable layer only while no process can write it. |
| `dispatch_authorized` | A successful request was made by an authorized client. |
| `owner_stable`, `removed_permanent` | A sandbox's owner never changes, and a removed identifier is never reused. |

The module comments list each module's remaining theorems.

## Assumptions

The model takes these platform facts as given. Each is encoded in a
definition rather than an axiom, so the audit keeps the model axiom-free. The
runtime implementation must check each with a VM test.

| Fact | Where the model relies on it |
| --- | --- |
| A bind mount or unmount on the staging directory propagates into the sandbox as one atomic change. | One `Change` is one observable step in `Reconcile`. |
| A mount propagated into the sandbox's user-namespaced mount namespace is locked: the sandbox cannot unmount or replace it. | Only `Action`s change `Host.mounted`. |
| Nix fixes a path's references when it becomes valid, and the references of store paths have no cycles except self-references. | One `Graph` for the whole update; `Ranked` in completeness. |
| The garbage collector deletes no path a registered root reaches. | `Concurrent.collect`. |
| Registering a root through the daemon's realization holds a temporary root until the permanent one exists. | `Effect.addRoot`. |
| The daemon serializes requests and updates for one sandbox with a lock. | `dispatch` and `procedure` are single atomic steps. |
| `SO_PEERCRED` reports the connecting process's user ID. | `Peer.uid`. |
| systemd thaws a frozen unit before stopping it, and no transient unit survives a reboot. | `next` and `boot`. |

Lazily unmounting a path keeps already open files and running executables
working. The model does not depend on this; it only defines what new lookups
see.

## Limits

- `closure?` stops after a fixed number of expansion rounds and then returns
  `none`. The proofs show any answer it returns is exact; the bound that
  always suffices, more rounds than distinct paths, is argued in its comment
  rather than proved.
- The theorems are about the model's definitions. The vectors, not a proof,
  connect them to the implementation.
- Kernel, systemd, and Nix behavior is outside the model; it enters only
  through the assumptions above.

## Conformance vectors

`formal/sandbox/vectors/` holds update requests and the model's answers. Each
`NAME.input.json` lists a store graph and a sandbox's current roots, current
mounts, and desired roots; `NAME.expected.json` is what
`sandbox-model update` prints for it:

```text
input:    {"graph": [{"path": P, "refs": [P, ...]}, ...],
           "roots": [P, ...], "mounted": [P, ...], "desired": [P, ...]}
expected: {"target": [P, ...],
           "actions": [{"op": "addRoot" | "mount" | "unmount" | "dropRoot", "path": P}, ...]}
       or {"error": "closure" | "plan"}
```

An implementation of the store helper must replay every vector through its
planner and produce the same actions in the same order. A new vector's expected file is
generated with `sandbox-model update` and reviewed before it is committed.

## Building and checking

`nix-build -A checks.formal.sandbox` builds the project, which checks every
proof, treats every warning as an error (an unfinished `sorry` proof is one),
runs the axiom audit, and replays the vectors.

To iterate, build the Lean package once and run Lake in the project:

```sh
lean=$(nix-build -A pkgs.lean4 --no-out-link)
cd formal/sandbox
PATH="$lean/bin:$PATH" lake build
.lake/build/bin/sandbox-model update vectors/advance-environment.input.json
```

## Changing the model

Change a definition and its theorems in the same commit as the design change
they describe, and update the tables above. A new platform fact becomes a
definition or a theorem hypothesis, never an `axiom`, and gets a row in the
assumptions table.
