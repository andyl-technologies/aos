# Workflow Specification

The workflow spec is the blueprint for a distributed computation. It is a store
object containing a JSON-encoded protobuf (`WorkflowSpec`). The `workflow_id`
is the store hash of the spec object.

This document defines the spec format, step types, the type system, formal
semantics, and provides a concrete build example.

## Store Object Format

```
{store_hash}/
  workflow.json            # JSON-encoded protobuf WorkflowSpec
```

The workflow object contains only the workflow definition. All store objects
referenced by steps are separate store objects that must exist in the store
before the workflow starts (for `input` sources) or are produced during
execution.

Workflow definitions can be stored in two ways:
- **As a store object** (`workflow.json`): submitted via `/aos/workflow/run/1.0.0` for explicit one-time execution.
- **As a Statute mount value**: stored at `{mount_path}/definition` within a workflow mount. The mount evaluates the definition reactively -- when read dependencies change, new workflow runs are created automatically.

In both cases, the resolved WorkflowSpec is stored as a store object and referenced by its hash. The mount model is described in [mounts.md](mounts.md).

## Type System

Every step returns either `StoreRef` (a deterministic store object reference)
or `Promise<StoreRef>` (an opaque handle that must be resolved via `await`).

```
StoreRef         = blake3 hash of a store object (deterministic, immutable)
Promise<StoreRef> = opaque handle to a future StoreRef (must go through await)
```

The type checker enforces: **a `Promise` cannot be used where a `StoreRef` is
expected.** Promises MUST flow through `await` before they can be consumed
by downstream steps. This makes every non-deterministic boundary visible
in the workflow DAG.

## Deterministic Control Flow

Workflow control flow is fully deterministic. Given the same store state and
the same spec, every executor independently computes the same execution plan:

- All conditions are content-addressed (store hashes, pinned objects)
- All builds are deterministic (same .drv = same output)
- All fetches are content-verified (same hash = same content)
- All read steps are at fixed state roots (historical state is immutable)
- All non-deterministic results are explicitly materialized via await/record

## Step Types

### input

Assert a required store object exists. Validated at submission time.
Completes immediately at runtime.

```
input(store_hash) :: StoreHash → StoreRef
{P}  store_object_exists(store_hash)
{Q}  store_object_exists(store_hash)
Effect: ∅
```

### fetch

Download a content-addressed object from upstream mirrors.

```
fetch(urls, hash, output_hash) :: (URLs, Hash) → StoreRef
{P}  urls ≠ ∅ ∧ hash ≠ ""
{Q}  store_object_exists(output_hash) ∧ content_verified(hash)
Effect: store ∪= {output_hash}
```

If the output already exists, completes immediately (idempotent).

**Volumes:** FetchSpec jobs have no volumes. Fetches execute in the daemon's
fetch engine, not in containers.

### build

Submit a hermetic Nix build from a .drv store object.

```
build(drv_hash, output_hash) :: StoreRef → StoreRef
{P}  store_object_exists(drv_hash) ∧ ∀ i ∈ closure(drv_hash): store_object_exists(i)
{Q}  store_object_exists(output_hash) ∧ output_hash = nix_build(drv_hash)
Effect: store ∪= {output_hash}
```

If the output already exists, completes immediately (idempotent). Output
hashes match `nix build` exactly.

**Volumes:** The generated BuildSpec job automatically includes volumes: a
StoreVolume for the derivation's input closure and LocalVolumes for the overlay
upper and work directories. The workflow engine generates these volume requests
from the .drv parse -- the workflow spec author does not declare them.

### match

Exhaustive pattern matching with multiple branches and a decision table.
Evaluates conditions and activates the corresponding branch of the DAG.

```
match(conditions, cases) :: [StoreRef] → StoreRef(branch_result) + activate steps
{P}  all conditions evaluable
{Q}  exactly one case matched, corresponding steps activated, others skipped
Effect: ∅ (pure routing)
```

```
WorkflowStep {
    id: "route-build"
    action: match {
        conditions: {
            "gcc_exists":  store_object_exists("gcc-out-hash")
            "llvm_exists": store_object_exists("llvm-out-hash")
        }
        cases: [
            { when: { gcc_exists: true, llvm_exists: true },
              activate: ["skip-to-final"] },
            { when: { gcc_exists: true, llvm_exists: false },
              activate: ["build-llvm"] },
            { when: { gcc_exists: false },
              activate: ["build-gcc", "build-llvm"] },
        ]
    }
    deps: []
}
```

**Exhaustiveness:** CUE validates all condition combinations are covered at
submission time. Missing cases reject the workflow. Partial matches (e.g.,
`gcc_exists: false` without specifying `llvm_exists`) match regardless of
the unspecified condition's value.

**Output:** a StoreRef representing the match result
`{ branch: "build-llvm", conditions: { gcc_exists: true, llvm_exists: false } }`.
Steps NOT activated by the match are `skipped`.

### read

Read a value from historical Statute state at a specific state root.
Returns a StoreRef because Statute values ARE store objects.

```
read(state_root, key) :: (StateRoot, Key) → StoreRef
{P}  statute_state_exists(state_root)
{Q}  result = statute_read_at(state_root, key)
Effect: ∅ (pure read of immutable historical state)
```

```
WorkflowStep {
    id: "read-cluster-config"
    action: read {
        state_root: "abc123..."          # must exist before workflow start
        key: "/clusters/prod/config"
    }
    deps: []
}
```

The `read` step supports two path forms:
- **Absolute:** `read({ key: "/repos/my-project/refs/heads/main" })` -- reads from any mount in Statute.
- **Relative:** `read({ key: "./repo_ref" })` -- resolves relative to the workflow's mount path. Makes definitions portable across different mount locations.

When used in a reactive workflow mount, relative reads reference argument keys within the mount. Writing to those keys triggers workflow re-evaluation.

The `state_root` is the blake3 tree hash of the Statute state at a specific
committed block. Reading at a fixed state root always returns the same value.
If the key is a directory prefix, the returned StoreRef is a tree object
containing the entire subtree.

### run

Execute a non-idempotent job. Returns an opaque `Promise<StoreRef>` — the
workflow does NOT observe the job's result directly.

```
run(spec_hash) :: StoreRef → Promise<StoreRef>
{P}  store_object_exists(spec_hash) ∧ statute_claim_acquired(step_id)
{Q}  job_executed_exactly_once(spec_hash)
Effect: job started in job system
```

The Promise is an opaque handle containing the job's pre-computed ID
(deterministic from spec_hash + nonce). To observe the job's result, the
Promise must flow through `await`.

**Claiming mode:** Statute consensus (~1-3s) instead of gossipsub (~100ms).
Guarantees exactly-once execution under partition.

**Volumes:** The RunSpec store object referenced by `spec_hash` must include
volume requests in the parent JobSpec. The workflow engine does NOT generate
volume requests for run steps -- the spec author is responsible for including
appropriate StoreVolume and LocalVolume entries.

### await

Universal promise resolver. Takes any `Promise<StoreRef>` (from `run` or
`observe`) and materializes it as an input-addressed store object.

```
await(promise) :: Promise<StoreRef> → StoreRef
{P}  promise produced by a run or observe step
{Q}  store_object_exists(materialized_hash)
     ∧ statute["{mount_path}/runs/{wf}/transitions/{step_id}"] = materialized_hash
Effect: store ∪= {materialized_hash}, statute ∪= transition record
```

The materialized store object is input-addressed:
`hash = f(workflow_id, step_id)`. Known before the step runs. Other workflows
can compute this address and `observe` it.

```
WorkflowStep {
    id: "await-deploy"
    action: await { source: "deploy" }     # source must be a run or observe step
    deps: ["deploy"]
}
```

### record

Write a StoreRef to Statute at a deterministic transition point. Makes a
value available for other workflows to `observe`.

```
record(value, transition_name) :: StoreRef → StoreRef
{P}  value is a valid StoreRef
{Q}  statute["{mount_path}/runs/{wf}/transitions/{transition_name}"] = value
Effect: statute ∪= transition record
```

```
WorkflowStep {
    id: "publish-build-result"
    action: record {
        source: "build-gcc"              # step ID whose output to record
        transition: "gcc-ready"          # transition point name
    }
    deps: ["build-gcc"]
}
```

The transition point address is deterministic:
`{mount_path}/runs/{workflow_id}/transitions/{transition_name}`.
Other workflows compute this address and `observe` it.

### observe

Watch another workflow's transition point. Returns a `Promise<StoreRef>`
because the target may not have recorded yet.

```
observe(workflow_id, transition) :: (WorkflowId, TransitionName) → Promise<StoreRef>
{P}  true (address is computable, target may not exist yet)
{Q}  promise resolves when target writes the transition point
Effect: ∅ (subscription, no mutation)
```

```
WorkflowStep {
    id: "watch-toolchain"
    action: observe {
        workflow_id: "hash-of-toolchain-workflow"
        transition: "gcc-ready"
    }
    deps: []
}
```

The address `{mount_path}/runs/{target_wf}/transitions/gcc-ready` is
deterministic — computable before the target workflow has run. This enables
static validation at submission time.

`observe` returns a single result (not a stream). Once the transition point
is written to Statute, the promise resolves with the recorded StoreRef.

## Workflow Termination

Termination is a `record` step that writes the `_terminated` transition to
`{mount_path}/runs/{workflow_id}/transitions/_terminated`:

```
{ id: "_terminate",
  action: record {
      source: <final step>,
      transition: "_terminated"
  },
  deps: [all final steps] }
```

Other workflows await termination with:
```
observe(wf_id, "_terminated") → await → StoreRef(termination record)
```

## Two Claiming Modes

| Step type | Claim via | Promise? | Latency |
|---|---|---|---|
| input, fetch, build, match, read | GossipSub (fast) | No (StoreRef) | ~100ms |
| run | Statute (safe) | Yes (Promise) | ~1-3s |
| await | N/A (resolves promise) | No (StoreRef) | Depends on source |
| record | N/A (writes to Statute) | No (StoreRef) | ~1-3s |
| observe | N/A (watches Statute) | Yes (Promise) | Depends on target |

## Validation Rules

1. Every `await` step's `source` must reference a `run` or `observe` step.
2. Every `await` step must have its source step in `deps`.
3. No step may depend directly on a `run` step EXCEPT `await` steps
   (enforces: promises must be resolved before use).
4. Every `read` step's `state_root` must reference a committed Statute block.
5. Every `match` step must have exhaustive cases (all condition combinations covered).
6. Every `record` step's `source` must reference a step that produces a StoreRef.
7. Every `observe` step's target address must be well-formed.

## GC Pinning

GC pinning is closure-based: **pin the workflow spec store hash, and its
closure covers everything.** The spec contains all referenced store hashes
as literal strings — reference scanning records them in the store.

Materialized store objects from `await` steps are pinned via Statute
auto-pinning (their hashes are written to `{mount_path}/runs/{wf}/transitions/`
which is scanned by the GC).

## Spec Constraints

```toml
[workflows]
max_steps = 10000
max_depth = 500
max_concurrent = 100
sync_window = "60s"
```

## Example: Building GNU Hello from Nixpkgs

### Workflow Spec

```
WorkflowSpec {
    nonce: 1710288000000000
    deadline: 1710374400000000
    expiration: 1710460800000000

    steps: [
        # --- FOD sources ---
        { id: "src-gcc", action: fetch {
            output_hash: "gcc-src-hash",
            urls: ["https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz"],
            hash: "sha256-..." }, deps: [] },

        { id: "src-hello", action: fetch {
            output_hash: "hello-src-hash",
            urls: ["https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz"],
            hash: "sha256-..." }, deps: [] },

        # --- Derivation inputs ---
        { id: "drv-gcc", action: input { store_hash: "gcc.drv-hash" }, deps: [] },
        { id: "drv-hello", action: input { store_hash: "hello.drv-hash" }, deps: [] },

        # --- Route: skip builds if outputs exist ---
        { id: "route-gcc", action: match {
            conditions: { "exists": store_object_exists("gcc-out-hash") },
            cases: [
                { when: { exists: true }, activate: [] },
                { when: { exists: false }, activate: ["build-gcc"] },
            ] }, deps: [] },

        # --- Builds ---
        { id: "build-gcc", action: build {
            drv_hash: "gcc.drv-hash",
            output_hash: "gcc-out-hash" },
          deps: ["drv-gcc", "src-gcc", "route-gcc"], timeout: "2h" },

        { id: "build-hello", action: build {
            drv_hash: "hello.drv-hash",
            output_hash: "hello-out-hash" },
          deps: ["drv-hello", "src-hello", "build-gcc"], timeout: "10m" },

        # --- Record output for other workflows ---
        { id: "publish-output", action: record {
            source: "build-hello",
            transition: "hello-ready" },
          deps: ["build-hello"] },

        # --- Termination record ---
        { id: "_terminate", action: record {
            source: "build-hello",
            transition: "_terminated" },
          deps: ["publish-output"] },
    ]
}
```

## Formal Step Signatures

| Step | Signature | Output | Deterministic |
|---|---|---|---|
| `input` | StoreHash → StoreRef | StoreRef | Yes (identity) |
| `fetch` | (URLs, Hash) → StoreRef | StoreRef | Yes (content-addressed) |
| `build` | StoreRef(drv) → StoreRef | StoreRef | Yes (Nix guarantee) |
| `match` | [Conditions] → StoreRef + routing | StoreRef | Yes (on pinned objects) |
| `read` | (StateRoot, Key) → StoreRef | StoreRef | Yes (historical, immutable) |
| `run` | StoreRef(spec) → Promise | Promise | Yes (opaque handle) |
| `await` | Promise → StoreRef | StoreRef | Yes (materializes at deterministic address) |
| `record` | (StoreRef, Name) → StoreRef | StoreRef | Yes (writes known value to known address) |
| `observe` | (WorkflowId, Name) → Promise | Promise | Yes (address is deterministic) |

## Relationship to Other Docs

- [workflow.md](workflow.md) -- workflow execution model, state machine.
- ~~[workflow-templates.md](workflow-templates.md)~~ -- **Deprecated.** Parameterized workflows are now expressed as workflow mounts with `read(./arg)` steps. See [mounts.md](mounts.md).
- [workflow-validation.md](workflow-validation.md) -- validation rules.
- [statute.md](statute.md) -- Statute KV store, auto-pinning, transition points.
- [protocol.md](protocol.md) -- wire protocol index.
- [volumes.md](volumes.md) -- volume types and lifecycle.
- [../../tla/Workflows.tla](../../tla/Workflows.tla) -- TLA+ formal specification.
