# Workflow Specification

The workflow spec is the blueprint for a distributed computation. It is a store
object containing a serialized protobuf (`WorkflowSpec`). The `workflow_id` is
the store hash of the spec object — two identical specs with different nonces
produce different workflow IDs.

This document defines the spec format, the available step types, the
idempotency model, and provides a concrete example of a Nix build workflow.

## Store Object Format

The workflow spec is a self-contained store object:

```
{store_hash}/
  workflow.pb              # serialized WorkflowSpec protobuf
  drvs/                    # all derivation files referenced by steps
    {hash1}.drv
    {hash2}.drv
    ...
```

The object contains the workflow definition (`workflow.pb`) and every `.drv`
file referenced by `ensure_store_object` steps. This makes the workflow
atomic: if the workflow store object exists, all build instructions exist.
Executors read `.drv` files directly from the workflow object (via the local
store or FUSE view) — no separate fetch is needed for build plans.

The `.drv` files' inputs (source tarballs, dependency outputs) are separate
store objects fetched during execution. The workflow object contains the PLAN
(what to build and how), not the DATA (source code and build outputs).

The spec must be published to the store (via `start_providing`) before the
workflow can be announced on `aos/workflows/announce`. This ensures the spec
is replicated and available for catch-up by late-joining peers.

See [protocol.md](protocol.md) for the `WorkflowSpec` protobuf definition.

## Deterministic Control Flow

Workflow control flow is fully deterministic. Given the same store state (which
store objects exist) and the same spec, every executor independently computes
the same execution plan. This is possible because:

- **All conditions are content-addressed.** Store hashes are the only inputs to
  workflow decisions. The same hash always refers to the same content.
- **All builds are deterministic.** Nix derivations produce the same output hash
  regardless of which peer executes them. The output hash is known from the
  `.drv` file before the build runs.
- **Step dependencies are static.** The DAG structure is fixed at submission
  time. No runtime decisions alter the graph topology.

Actions (builds, fetches) may execute on different peers at different times,
but the workflow's control flow — which steps run, which are skipped, in what
order — is a pure function of the spec and the store state.

## Step Types

### ensure_store_object

The fundamental workflow operation: "make sure this content-addressed store
object exists." Every `ensure_store_object` step specifies HOW to produce the
object if it doesn't already exist, guaranteeing forward progress without
external intervention.

The `source` field is a oneof with two variants:

**Build from derivation** (`drv_hash`):

```
WorkflowStep {
    id: "build-gcc"
    action: ensure_store_object {
        output_hash: "gcc-out-hash"
        source: drv_hash: "gcc.drv"  # path within the workflow store object's drvs/ dir
    }
    deps: ["src-gcc", "build-glibc"]
    timeout: 7200000000              # 2 hours in μs
}
```

**Fetch from upstream mirrors** (`fetch`):

```
WorkflowStep {
    id: "src-gcc"
    action: ensure_store_object {
        output_hash: "gcc-src-hash"
        source: fetch {
            urls: [
                "https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz",
                "https://mirrors.kernel.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz"
            ]
            hash: "sha256-abc123..."
        }
    }
    deps: []
}
```

Execution:

1. **Check existence.** Query the store watcher for `output_hash`. If the
   object already exists (provider record on DHT, or local store), the step
   completes immediately — no build or download needed.
2. **Produce if needed.** If the object does not exist:
   - `drv_hash` source: the executor reads the `.drv` from the workflow store
     object's `drvs/` directory, constructs a `JobSpec`, submits it to
     `jobs/announce`, and waits for `JobExit` with the matching output hash.
   - `fetch` source: the executor downloads from the URLs in priority order,
     verifies the content against the SRI hash, chunks the result, and
     publishes it to the store. This is how FODs (fixed-output derivations)
     are handled — source tarballs are downloaded from upstream mirrors by the
     cluster, not uploaded by the client.

**Progress guarantee:** every step can self-resolve. Build steps have the
derivation embedded in the workflow object. Fetch steps have upstream URLs.
The cluster never depends on an external client to upload content — it
can always produce the required store objects independently.

**Idempotency:** fully idempotent. If the output already exists, the step is a
no-op. If the build runs twice (e.g., after a partition heal), both runs
produce the same output hash (Nix builds are deterministic). Duplicate fetches
produce the same content (verified by hash). Content-addressed deduplication
means the store only holds one copy.

**Output hash source:** for Nix derivations, the output hash is computed from
the `.drv` file before the build runs. For FODs, the hash is the content hash
of the source tarball (specified in the Nix expression). Both are known at
workflow creation time.

### await_workflow

Wait for another workflow to complete or reach a specific step.

```
WorkflowStep {
    id: "wait-for-toolchain"
    action: await_workflow {
        workflow_id: "hash-of-toolchain-build"
        step_id: "final-output"      # optional; omit to wait for full completion
    }
    deps: []
}
```

The executor subscribes to the target workflow's state topic and watches for
the referenced step (or overall workflow) to reach `completed`. If already
complete (checked via `/aos/workflow/info/1.0.0`), the step completes
immediately.

**Idempotency:** fully idempotent. Checking completion status is a read-only
operation.

### decision

Evaluate a condition and skip downstream steps if the condition is false.

```
WorkflowStep {
    id: "check-gcc-exists"
    action: decision {
        condition: store_object_exists {
            store_hash: "abc123"     # output hash to check
        }
    }
    deps: []
}
```

If the condition is true, the step completes with `completed` status. If false,
the step completes with `skipped` status. Downstream steps that depend on a
`skipped` decision step are also `skipped`.

This enables short-circuiting: if a build output already exists in the store,
the entire build subgraph below it can be skipped.

**Available conditions:**

| Condition | Input | Description |
|---|---|---|
| `store_object_exists(hash)` | store hash | True if a provider record exists on the DHT. |

All conditions are deterministic — they depend only on content-addressed store
state, not on peer-specific or time-dependent values.

**Idempotency:** fully idempotent. Conditions are pure checks with no side
effects.

## GC Pinning

GC pinning for workflows is simple: **pin the workflow spec store object.**
Everything else follows from the closure.

The workflow spec protobuf contains store hashes as literal strings —
`output_hash`, `drv_hash`, `store_hash` fields in step definitions. When the
daemon ingests the spec store object and runs reference scanning, it finds all
these hashes and records them in `closure_db`. The spec's transitive closure
(via `closure_db` walk) automatically includes:

- All FOD source hashes (from `ensure_store_object` steps without `drv_hash`)
- All derivation hashes (from `ensure_store_object.drv_hash`)
- All expected output hashes (from `ensure_store_object.output_hash`)
- All decision check hashes (from `store_object_exists` conditions)
- All dependent workflow spec hashes (from `await_workflow.workflow_id` — which
  are themselves store hashes, since `workflow_id = store_hash(spec)`)

No separate per-step tracking is needed. The daemon pins the spec's store hash,
and the standard closure-based GC pinning (see [gc.md](gc.md)) protects
everything transitively referenced.

**Output hashes that don't exist yet** (builds haven't run) are in the closure
but don't exist in the store. This is fine — you can't GC something that
doesn't exist. When the build completes and the output appears, it's already
covered by the closure pin.

**Cross-workflow pinning is free:** if W2's spec contains
`await_workflow(W1_id)`, W1's ID is a store hash (it's the hash of W1's spec).
Reference scanning finds W1's ID in W2's protobuf. W2's closure includes W1's
spec. W1's spec's closure includes all of W1's store objects. Pin W2's spec →
transitively pins W1's entire tree. No explicit cross-workflow dependency
tracking is needed for GC — the closure walk handles it.

Pins are held from workflow creation until the workflow reaches a terminal
state (completed, failed, cancelled, expired) AND is garbage-collected
(at `expiration` time).

## Spec Constraints

Each daemon enforces limits on workflow specs at announcement time:

```toml
[workflow]
max_steps = 10000          # max total steps per workflow
max_depth = 500            # max steps through longest path
max_active_workflows = 100 # max concurrent active workflows
```

- **max_steps**: total number of `WorkflowStep` entries. Rejects oversized specs.
- **max_depth**: longest path through the step dependency DAG. Bounds the
  transition log size and the maximum sequential latency of the workflow.
- **max_active_workflows**: concurrent workflows tracked by this daemon.

The daemon validates these limits before subscribing to the workflow's state
topic. Workflows exceeding limits are silently ignored (the daemon does not
track them).

## Example: Building GNU Hello from Nixpkgs

A concrete example of a Nix build workflow. GNU Hello is a simple package with
a modest dependency chain, representative of a typical nixpkgs derivation.

### Dependency Graph

```
hello-2.12.1 (the final output)
├── hello-2.12.1.tar.gz (FOD source tarball)
├── gcc-14.2.0 (compiler)
│   ├── gcc-14.2.0.tar.xz (FOD)
│   ├── glibc-2.39 (runtime dep)
│   │   ├── glibc-2.39.tar.xz (FOD)
│   │   └── linux-headers-6.6 (build dep)
│   │       └── linux-6.6.tar.xz (FOD)
│   └── gmp-6.3.0, mpfr-4.2.1, mpc-1.3.1 (build deps)
│       └── (each has its own FOD source)
├── make-4.4.1 (build tool)
│   ├── make-4.4.1.tar.gz (FOD)
│   └── glibc-2.39 (shared dep, already in graph)
└── coreutils-9.4 (build tool)
    ├── coreutils-9.4.tar.xz (FOD)
    └── glibc-2.39 (shared dep)
```

### Workflow Spec

The client evaluates the flake, computes all derivation and output hashes, and
produces this spec. Output hashes are known from the `.drv` files — no
builds have run yet.

```
WorkflowSpec {
    nonce: 1710288000000000
    deadline: 1710374400000000       # 24 hours from submission
    expiration: 1710460800000000     # 48 hours from submission

    steps: [
        # --- FOD sources (fetched from upstream mirrors) ---

        { id: "src-linux-headers",
          action: ensure_store_object {
              output_hash: "linux-6.6.tar.xz-hash",
              fetch: { urls: ["https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz"],
                       hash: "sha256-..." }
          }, deps: [] },

        { id: "src-glibc",
          action: ensure_store_object {
              output_hash: "glibc-2.39.tar.xz-hash",
              fetch: { urls: ["https://ftp.gnu.org/gnu/glibc/glibc-2.39.tar.xz"],
                       hash: "sha256-..." }
          }, deps: [] },

        { id: "src-gmp",
          action: ensure_store_object {
              output_hash: "gmp-6.3.0.tar.xz-hash",
              fetch: { urls: ["https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz"],
                       hash: "sha256-..." }
          }, deps: [] },

        { id: "src-mpfr",
          action: ensure_store_object {
              output_hash: "mpfr-4.2.1.tar.xz-hash",
              fetch: { urls: ["https://ftp.gnu.org/gnu/mpfr/mpfr-4.2.1.tar.xz"],
                       hash: "sha256-..." }
          }, deps: [] },

        { id: "src-mpc",
          action: ensure_store_object {
              output_hash: "mpc-1.3.1.tar.gz-hash",
              fetch: { urls: ["https://ftp.gnu.org/gnu/mpc/mpc-1.3.1.tar.gz"],
                       hash: "sha256-..." }
          }, deps: [] },

        { id: "src-gcc",
          action: ensure_store_object {
              output_hash: "gcc-14.2.0.tar.xz-hash",
              fetch: { urls: ["https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz",
                              "https://mirrors.kernel.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz"],
                       hash: "sha256-..." }
          }, deps: [] },

        { id: "src-make",
          action: ensure_store_object {
              output_hash: "make-4.4.1.tar.gz-hash",
              fetch: { urls: ["https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz"],
                       hash: "sha256-..." }
          }, deps: [] },

        { id: "src-coreutils",
          action: ensure_store_object {
              output_hash: "coreutils-9.4.tar.xz-hash",
              fetch: { urls: ["https://ftp.gnu.org/gnu/coreutils/coreutils-9.4.tar.xz"],
                       hash: "sha256-..." }
          }, deps: [] },
          deps: [] },

        { id: "src-hello",
          action: ensure_store_object {
              output_hash: "hello-2.12.1.tar.gz-hash",
              fetch: { urls: ["https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz"],
                       hash: "sha256-..." }
          }, deps: [] },

        # --- Decision: skip builds if outputs already exist ---

        { id: "check-glibc",
          action: decision { condition: store_object_exists { store_hash: "glibc-2.39-out-hash" } },
          deps: [] },

        { id: "check-gcc",
          action: decision { condition: store_object_exists { store_hash: "gcc-14.2.0-out-hash" } },
          deps: [] },

        { id: "check-hello",
          action: decision { condition: store_object_exists { store_hash: "hello-2.12.1-out-hash" } },
          deps: [] },

        # --- Builds (only run if decision steps did not skip) ---

        { id: "build-linux-headers",
          action: ensure_store_object {
              output_hash: "linux-headers-6.6-out-hash",
              drv_hash: "linux-headers-6.6.drv-hash"
          },
          deps: ["src-linux-headers"],
          timeout: 600000000 },       # 10 min

        { id: "build-glibc",
          action: ensure_store_object {
              output_hash: "glibc-2.39-out-hash",
              drv_hash: "glibc-2.39.drv-hash"
          },
          deps: ["src-glibc", "build-linux-headers", "check-glibc"],
          timeout: 3600000000 },      # 1 hour

        { id: "build-gmp",
          action: ensure_store_object {
              output_hash: "gmp-6.3.0-out-hash",
              drv_hash: "gmp-6.3.0.drv-hash"
          },
          deps: ["src-gmp", "build-glibc"],
          timeout: 600000000 },

        { id: "build-mpfr",
          action: ensure_store_object {
              output_hash: "mpfr-4.2.1-out-hash",
              drv_hash: "mpfr-4.2.1.drv-hash"
          },
          deps: ["src-mpfr", "build-gmp"],
          timeout: 600000000 },

        { id: "build-mpc",
          action: ensure_store_object {
              output_hash: "mpc-1.3.1-out-hash",
              drv_hash: "mpc-1.3.1.drv-hash"
          },
          deps: ["src-mpc", "build-mpfr"],
          timeout: 600000000 },

        { id: "build-gcc",
          action: ensure_store_object {
              output_hash: "gcc-14.2.0-out-hash",
              drv_hash: "gcc-14.2.0.drv-hash"
          },
          deps: ["src-gcc", "build-glibc", "build-gmp", "build-mpfr", "build-mpc", "check-gcc"],
          timeout: 7200000000 },      # 2 hours

        { id: "build-make",
          action: ensure_store_object {
              output_hash: "make-4.4.1-out-hash",
              drv_hash: "make-4.4.1.drv-hash"
          },
          deps: ["src-make", "build-glibc"],
          timeout: 600000000 },

        { id: "build-coreutils",
          action: ensure_store_object {
              output_hash: "coreutils-9.4-out-hash",
              drv_hash: "coreutils-9.4.drv-hash"
          },
          deps: ["src-coreutils", "build-glibc"],
          timeout: 1200000000 },      # 20 min

        { id: "build-hello",
          action: ensure_store_object {
              output_hash: "hello-2.12.1-out-hash",
              drv_hash: "hello-2.12.1.drv-hash"
          },
          deps: ["src-hello", "build-gcc", "build-make", "build-coreutils", "check-hello"],
          timeout: 600000000 },
    ]
}
```

### Execution Flow

Assuming a cold cluster (no outputs exist yet):

1. **FOD fetches** (all `ensure_store_object` steps with `fetch` source run
   in parallel): executors download 9 source tarballs from upstream mirrors.
   Each step completes as the download finishes and the content hash is
   verified. No client upload needed — the cluster is self-sufficient.

2. **Decision steps** (`check-glibc`, `check-gcc`, `check-hello`):
   all return false (outputs don't exist) — no steps are skipped. These
   complete in ~5ms (store watcher DHT check).

3. **First wave** (no build deps, only source deps):
   `build-linux-headers` starts as soon as `src-linux-headers` completes.

4. **Second wave**: `build-glibc` starts when linux-headers completes.
   `build-gmp` starts when glibc completes.

5. **Pipeline continues**: mpfr → mpc → gcc (sequential chain).
   Meanwhile, `build-make` and `build-coreutils` start as soon as glibc is
   done (parallel with the gcc chain).

6. **Final build**: `build-hello` starts when gcc, make, and coreutils are all
   done.

**With a warm cluster** (gcc and glibc already exist):

- `check-glibc` and `check-gcc` return true.
- `build-glibc`, `build-linux-headers`, `build-gmp`, `build-mpfr`, `build-mpc`,
  and `build-gcc` all complete immediately (output already exists).
- `build-make` and `build-coreutils` may still need building (or also exist).
- `build-hello` starts as soon as its deps are resolved — potentially within
  seconds of workflow submission.

### Critical Path

Cold cluster: `src-linux-headers → build-linux-headers → build-glibc → build-gmp → build-mpfr → build-mpc → build-gcc → build-hello`

This is 8 sequential builds. With the gcc build at ~2 hours, the critical path
is dominated by gcc. Parallel branches (make, coreutils) complete during the
gcc build and don't extend the critical path.

Warm cluster (gcc exists): `src-hello → build-hello` — one build, ~10 minutes.

## Relationship to Other Docs

- [workflow.md](workflow.md) -- workflow execution model, state machine,
  transition ordering, catch-up.
- [protocol.md](protocol.md) -- `WorkflowSpec`, `WorkflowStep`, `StepAction`
  protobuf definitions.
- [store.md](store.md) -- store object existence checks, provider records.
- [jobs.md](jobs.md) -- job submission and completion lifecycle.
- [gc.md](gc.md) -- workflow GC pinning model.
- [storage.md](storage.md) -- WorkflowDB schema.
