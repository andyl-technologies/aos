# Dispatch

Dispatch computes resource-assignment proposals from immutable problem snapshots.
It describes items, eligible destinations, resource demands, topology, constraints,
and ordered objectives using portable data. A session performs bounded solving
through an explicitly selected backend and execution provider. Dispatch evaluates
returned assignments independently before classifying them as feasible or as an
explicitly permitted repair proposal.

Applications retain ownership of inventory, observation freshness, reservations,
and execution. A proposal is bound to its input snapshot. Applying it requires the
application to check that snapshot and acquire its normal authority.

## Choose the interface

| Interface | Use |
| --- | --- |
| `dispatch-model` | Portable types, structural validation, exact evaluation, and verification |
| `dispatch` | Fluent construction, policy recipes, comparison, explanation, and optional runtime access |
| `dispatch-runtime` | Sessions, bounded admission, reusable workers, cancellation, and providers |
| `dispatch-protocol` | Strict JSON import, canonical commitments, and versioned framed process messages |
| `dispatch` executable | JSON validation, evaluation, verification, request export, solving, explanation, comparison, and benchmarking |

Pure library operations need no systemd service or native solver. Rust consumers
can depend on `dispatch` with `default-features = false` for pure operations, then
enable `runtime` when they need session execution. The `cli` feature builds the
standalone executable and enables the runtime.

The `protocol` feature re-exports `SolveRequest` and `SearchRequestOptions` for
portable request import and export; `runtime` enables it automatically. A request
contains the complete problem, backend name, exact original search options, and
an optional independent hint. It carries no executable paths or execution
authority. The [request schema](../../protocol/dispatch/request.schema.json) defines
its machine representation.

The portable interfaces do not depend on application-specific records or an AOS
deployment. The [Rust packing example](../../crates/dispatch/examples/packing.rs)
uses only the public facade. The [Python comparison example](../../crates/dispatch/examples/compare.py)
uses the machine JSON CLI instead of a Rust API.

## Build a problem

An item is indivisible: a candidate binds it once to one real target or to
`Deferred`. Each item explicitly permits or prohibits deferral. Replicas therefore
need distinct item identifiers and a group describing their relationship.

Resource inputs are nonnegative 64-bit quantities. JSON carries quantities as
canonical decimal strings, such as `"4096"`. Objective arithmetic uses exact reduced
rationals with decimal-string numerators and denominators. A dimension's unit and
quantum are explicit; unit names do not imply conversion rules. The semantic model
version is represented as `"1"` in JSON.

Every target has explicit fixed loads and finite or unbounded capacities. Every
item has explicit demands and historical ordinary charges. Demand defaults and
sparse overrides preserve target-dependent costs without forcing a dense matrix.
An omitted demand does not mean zero. Declared target capacities help construct
policies; the actual capacity requirements contain explicit limits.

```rust
use std::collections::BTreeMap;
use dispatch::{
    AccountingPhase, Capacity, Enforcement, Item, Observation,
    ObservedBinding, ProblemBuilder, Quantity, Target, recipes,
};

let builder = ProblemBuilder::new()
    .observation_basis("inventory", "revision-1")
    .dimension("slots", "worker slots", 1)
    .target("host", Target {
        capacities: BTreeMap::from([
            ("slots".into(), Capacity::Finite { limit: Quantity::new(8) }),
        ]),
        fixed_load: BTreeMap::from([("slots".into(), Quantity::new(0))]),
    })
    .domain("eligible", vec!["host".into()])
    .item("job", Item {
        domain: "eligible".into(),
        deferrable: false,
        demands: BTreeMap::from([("slots".into(), recipes::uniform_demand(2))]),
    })
    .observed("job", Observation {
        binding: ObservedBinding::Unplaced,
        charges: BTreeMap::from([("slots".into(), Quantity::new(0))]),
    });

let limits = recipes::packing_capacity(
    "placement", builder.as_problem(), &["slots".into()],
    AccountingPhase::Final, Enforcement::Hard,
)?;
let problem = builder.policy(limits).build()?;
```

The builder rejects duplicate definitions rather than replacing earlier data.
`as_problem()` exposes assembled policy for inspection, `into_problem()` returns
draft data, and `build()` validates and freezes it. Validation checks references,
accounting, topology, cost coverage, and policy parameters. It does not require a
known feasible assignment; valid requirements can be contradictory.

## Compose explicit policies

Constraints include eligibility, fixed placement, capacity, admission, atomic
admission, colocation, spread, and movement budgets. Scope families partition
targets into submitted failure or locality domains. Named target sets can overlap.

The facade's recipes expand into `PolicyExpansion`, containing ordinary public
target sets, constraints, and objective tiers. They are inspectable and serializable:

- `packing_capacity` creates finite per-target capacity requirements using an
  explicitly selected accounting phase and enforcement mode.
- `replica_spread` creates hard admission and spread requirements over a supplied
  group and scope family. It does not infer independent failure domains.
- `evacuate` restricts final eligibility while preserving observed source targets,
  charges, and holdings.
- `freeze_observed` creates explicit fixed bindings, including `Deferred` for an
  unplaced observation. It does not override mandatory admission.
- `minimize_used_targets` adds one explicit objective tier. It does not claim that
  destinations lacking modeled items can be shut down.

Applying an expansion checks identifier collisions before changing the problem.
Recipes add no implicit admission or migration authority.

Objective tiers are compared lexicographically. Terms within a tier specify their
direction, weight, and normalization divisor. Earlier tiers outrank all later
tiers. Balance, packing, locality, and movement preference are consumer policy;
they do not override constraints.

### Final capacity and overlap

Final accounting includes fixed consumption, proposed placements, and additional
holdings retained at the final boundary. Conservative overlap includes all
additional observed holdings and the maximum of historical and proposed ordinary
charge at each item-target pair. A relocation therefore charges its source and
destination during overlap. An unchanged placement is counted once using its
larger ordinary charge.

Ordinary holding fragments are part of the historical charge and are not added a
second time. Additional holdings are separate consumption. Consumers must also
avoid double charging inclusive parent grants and their child use.

A final-capacity result does not establish temporary headroom. An overlap-capacity
result does not establish transfer ordering, copy completion, or quorum safety.

### Explicit repair

`Enforcement::Hard` requires zero violation. `Enforcement::Repair` is available
for numeric capacity, admission, and spread obligations. Each repair component
gets its own baseline debt from the observation. A candidate can retain or reduce
that debt but cannot create new debt in another component to compensate.

Consumers declare repair objectives explicitly. Zero remaining debt yields a
feasible result. Permitted nonzero debt yields a repair proposal. Eligibility,
fixed placement, atomic admission, and colocation remain hard requirements.

## Evaluate and inspect without a solver

```rust
use dispatch::{Assignment, Binding, evaluate, verify};
use std::collections::BTreeMap;

let assignment = Assignment {
    bindings: BTreeMap::from([
        ("job".into(), Binding::Target { target: "host".into() }),
    ]),
};
let evaluation = evaluate(&problem, &assignment)?;
let verified = verify(&problem, assignment)?;
```

Evaluation reports exact loads, hard violations, repair debt, movement categories,
objective vectors, and named term contributions. `verify` returns a locally
constructed `VerifiedAssignment` or an explicit rejection. Serialized evaluations
and flags do not preserve verification authority.

`analysis::compare` evaluates two assignments against one problem and reports
binding changes and exact objective preference. That preference remains separate
from feasibility. `analysis::explain` recomputes a supplied candidate's report.

`analysis::what_if` clones a validated problem, applies a consumer transformation,
and validates the changed snapshot. It rejects a transformation that makes no
semantic change. `analysis::compare_problems` identifies changed inputs using JSON
Pointer paths and evaluates each assignment under its own problem. It omits
objective preference when the models differ, so changed units or policy are not
implicitly treated as comparable scores.

Pure operations run in the caller's resource context. Use the session execution
boundary when substantive model materialization and verification need independent
supervision or memory containment.

## Open a bounded session

Execution providers and solvers have separate roles. The provider supervises the
worker environment and reports resource guarantees. The backend searches for
assignments. Rebalancer runs in a native process behind the trusted Rust runner;
applications do not link its C++ implementation.

```rust
use std::{path::PathBuf, sync::Arc, time::Duration};
use dispatch::runtime::{
    CloseMode, ExecutionProfile, SessionBuilder, SolveOptions,
    SubprocessProvider, WorkerLaunch,
};

let session = SessionBuilder::new(
    Arc::new(SubprocessProvider::new()),
    WorkerLaunch {
        runner: PathBuf::from("/trusted/path/dispatch-worker"),
        native_backend: PathBuf::from("/trusted/path/dispatch-rebalancer"),
        native_arguments: Vec::new(),
        session_generation: 0,
        worker_generation: 0,
        max_frame_bytes: 16 * 1024 * 1024,
    },
)
.profile(ExecutionProfile::Warm)
.start().await?;

let job = session.submit(problem.problem().clone(), SolveOptions {
    deadline: Duration::from_secs(10),
    ..SolveOptions::default()
})?;
let result = job.wait().await?;
let cleanup = session.close(CloseMode::Drain, Duration::from_secs(5)).await?;
```

Executable paths come from trusted caller configuration, never the problem.
The runtime assigns session and worker generations; zero values in the launch
template are replaced during initialization and worker creation. Initialization
negotiates live backend identity and capabilities. An optional
`expected_backend_build` requirement pins the accepted build.

Warm execution reuses workers within a stable ownership boundary. Fresh execution
retires a worker after each solve. Each worker executes one request at a time.
Reusing a process does not promise retained native expression graphs or incremental
search. A backend must advertise those capabilities separately.

Session limits bound concurrency, pending requests, retained input bytes, prepared
inputs, terminal records, frame sizes, and cleanup. Cloned session handles share
those limits. Admission returns overload promptly instead of retaining unlimited
work. Deadlines cover accepted solve execution, including queue waiting and
verification. `Job::cancel()` requests cancellation; completion can win the race.
Losing a result watcher does not cancel the job.

Close stops admission across every handle. `Drain` permits accepted work until the
close deadline; `Cancel` requests termination immediately. Inspect the returned
cleanup report for unconfirmed jobs or workers. Dropping a Rust handle does not
guarantee asynchronous cleanup.

### Resource guarantees

The subprocess provider inherits application accounting. On Unix, it uses a
private process group for hard termination of ordinary descendants. It does not
create an independent memory or OOM boundary. Its grant identifies those limits.

The Linux systemd provider establishes managed worker services before model
allocation and places the runner and native engine in the same budget. Trusted
platform policy selects the application solver slice and resource settings.
Application-level aggregate limits prevent opening extra sessions from increasing
the application's entitlement. CPU weights express relative importance during
contention; they do not promise a completion deadline. Hard memory limits do not
reserve physical memory.

Use `RequiredGuarantees` when independent memory containment, hard cancellation,
aggregate accounting, or owner-loss cleanup is mandatory. Initialization rejects
a provider that cannot meet those requirements instead of silently downgrading
them. Cooperative thread settings are not CPU quotas.

Custom providers implement `ExecutionProvider` and report their concrete grant.
An embedded provider must disclose shared memory and cooperative cancellation.
Remote supervision can implement the same boundary with authenticated ownership,
grants, and finite cleanup; no shared daemon is required for local execution.

### Configure managed execution in AOS

Enable `aos.dispatch` and bind a profile to an existing controller service. This
example assigns `batch-controller.service` an application budget shared by every
session it opens, with a smaller shared solver budget and per-worker limits:

```nix
aos.dispatch = {
  enable = true;
  applications.batch = {
    ownerService = "batch-controller";
    aggregate = {
      cpuWeight = 400;
      memoryHighBytes = 1073741824;
      memoryMaxBytes = 1610612736;
      tasksMax = 256;
    };
    solvers = {
      memoryHighBytes = 536870912;
      memoryMaxBytes = 1073741824;
      tasksMax = 128;
    };
    worker = {
      cpuQuotaPercent = 100;
      memoryHighBytes = 201326592;
      memoryMaxBytes = 268435456;
      tasksMax = 32;
    };
  };
};
```

The module installs the tools and `/etc/dispatch/systemd-profiles.json`, creates
the application and solver slices, and places the controller in its application
slice. Enable the facade's `systemd` feature (or the runtime crate's matching
feature) to select that trusted profile:

```rust
use dispatch::runtime::{
    RequiredGuarantees, SessionBuilder,
    providers::systemd::{SystemdProfile, SystemdProvider},
};

let configuration = tokio::fs::read("/etc/dispatch/systemd-profiles.json").await?;
let profile = SystemdProfile::from_configuration(&configuration, "batch")?;
let provider = SystemdProvider::connect(profile).await?;
let session = SessionBuilder::new(Arc::new(provider), launch)
    .required_guarantees(RequiredGuarantees {
        hard_cancellation: true,
        independent_memory: true,
        aggregate_accounting: true,
        owner_cleanup: true,
    })
    .start().await?;
```

Here `launch` supplies the trusted executable paths as in the session example.
The controller or its supervisor must already be authorized to use the selected
systemd manager. Profile configuration supplies resource policy; it does not
grant D-Bus permissions. Standalone consumers can use a user-manager profile or
provide their own supervisor through the same execution-provider interface.

## Use the command-line JSON interface

The following examples use the [packing fixtures](../../crates/dispatch/examples/fixtures/packing.problem.json):

```text
dispatch validate --problem packing.problem.json
dispatch evaluate --problem packing.problem.json --assignment packing.before.json
dispatch verify --problem packing.problem.json --assignment packing.after.json
dispatch compare --problem packing.problem.json --before packing.before.json --after packing.after.json
dispatch request --problem packing.problem.json --deadline-ms 10000 --output request.json

dispatch solve --problem packing.problem.json --profile warm \
  --runner /trusted/path/dispatch-worker \
  --backend /trusted/path/dispatch-rebalancer \
  --deadline-ms 10000 --result result.json

dispatch explain --problem packing.problem.json --result result.json
dispatch solve --request request.json --profile warm \
  --runner /trusted/path/dispatch-worker \
  --backend /trusted/path/dispatch-rebalancer --result result.json
dispatch benchmark --problem packing.problem.json --profile warm \
  --runner /trusted/path/dispatch-worker \
  --backend /trusted/path/dispatch-rebalancer --iterations 10
```

`DISPATCH_WORKER` and `DISPATCH_BACKEND` provide trusted defaults for executable
paths; explicit flags override them. `--profile` is required for solving and
benchmarking. `--mode local-search` is the default algorithm; `--mode mip`
requires a backend advertising that capability. Literal `--backend-argument`
values are passed directly without shell evaluation. `--threads`, `--seed`, and
`--expected-backend-build` configure search and identity without changing the model.

`request` exports a structurally validated problem and explicit options without
starting a worker. Its `--hint` input may violate constraints but must be a complete
well-formed assignment; it does not change observations. `--backend-name` records
the logical backend policy. `solve --request` preserves those options and verifies
that the configured worker advertises the selected backend. It rejects conflicting
search flags. Edit or export a distinct request to change the search policy.
Cooperative memory, CPU-time, and iteration options that the local session does not
implement produce an unsupported-capability error instead of being ignored.

The CLI's local execution uses the subprocess provider. Applications selecting
systemd or another custom supervisor use the runtime provider interface.

Commands emit one JSON document on stdout, or to `--output`/`--result`. Diagnostics
are separate JSON error documents on stderr. A file named `-` means stdin for input
or stdout for output. Commands needing several input documents should use stdin
for at most one of them. Input is bounded before decoding; `--max-input-bytes`
defaults to 64 MiB. Strict decoding rejects duplicate keys, unknown typed fields,
floating-point values, excessive nesting, and excessive decoded storage.

| Exit status | Meaning |
| --- | --- |
| 0 | Operation succeeded; solve returned a feasible candidate or repair proposal |
| 2 | Invalid input or command arguments |
| 3 | Unsupported model version, backend capability, or execution configuration |
| 4 | Session admission overload |
| 5 | Execution, I/O, cleanup, or exact numeric exhaustion failure |
| 6 | Search ended without an accepted candidate, or verification rejected a candidate |

A limit-reached search may still have an accepted candidate; inspect `termination`
and `candidate` independently. Exit status 6 does not establish infeasibility.
`explain` checks that a saved result identifies the supplied problem, then
recomputes its candidate's evaluation. Saved classification and evaluation fields
are not trusted.

Benchmarking uses the same session and backend contract as solving. It reports
initialization wall time separately from each complete request wall time, with
nanoseconds represented as decimal strings. Unavailable CPU measurements are
`null`. Warm and fresh runs must be compared explicitly; a seed does not guarantee
identical search trajectories across builds, thread counts, or execution limits.

## Interpret results and capabilities

A result reports termination independently from candidate validity. Completed
search, limit reached, cancellation, rejection, and execution failure are distinct.
A candidate can be absent, rejected, fully feasible, or a repair proposal. Backend
infeasibility or optimality evidence is distinct from the runner's independent
verification of a particular assignment.

Rebalancer local search supplies heuristic search results. Failure to find a
candidate is not a proof that the full problem is infeasible. The adapter rejects
unsupported constraints, objective combinations, numeric ranges, and search
options. It never drops hard requirements to make a model fit a backend.

Exported artifacts should retain the immutable problem and options alongside the
result, backend build, and grant. Prepared handles are scoped runtime references;
they do not substitute for the input needed to evaluate an artifact offline.
Capabilities and generation checks prevent a stale handle or replaced worker from
silently changing the meaning of a solve.

Consumers sharing physical capacity need a partitioning rule or common reservation
authority. Shared solver code alone does not make concurrent proposals atomic.
