# 8. Solver backends

## 8.1. Selected engine and trust boundary

Rebalancer is Dispatch's selected assignment engine. Its reusable specification
language, expression graph, and local-search algorithms fit resource placement
and repeated rebalancing. Meta describes its deployment experience in the
[OSDI paper](https://www.usenix.org/conference/osdi24/presentation/kumar) and
[open-source announcement](https://engineering.fb.com/2026/09/21/open-source/rebalancer-generic-high-performance-library-assignment-problems/).
That experience motivates selection; it does not establish performance or
correctness guarantees for a particular Dispatch model.

The C++ executable `dispatch-rebalancer` MUST implement the backend protocol
and compile Dispatch specifications into native Rebalancer constructs. A
trusted Rust runner MUST supervise the executable and independently verify its
candidates. Native code MUST execute in a separate process. The Rust SDK's
backend abstraction describes a protocol client; it is not a Rust ABI that
C++ implements, and it MUST NOT require direct C++ FFI in consumers.

The backend MUST NOT acquire placement authority, access domain credentials,
or execute assignment changes. Its output is untrusted placement data. The
runner's verification MUST use the immutable Dispatch problem rather than
native expressions or backend-reported feasibility values.

## 8.2. Compiler capabilities

A backend MUST advertise a versioned capability profile bound to its compiler
and engine build. The profile MUST identify supported constraints, objectives,
enforcement modes, combinations, accounting forms, number ranges, and size
limits. Listing individual supported operations MUST NOT imply support for
every combination. Model validation and backend compatibility validation are
distinct operations.

Compilation MUST preserve candidate domains, target-dependent demand, explicit
deferral, fixed load, groups, topology, and concurrent occupancy. Internal
synthetic containers MAY represent deferral, but MUST disappear from returned
assignments and MUST NOT gain capacity, locality, or failure-domain meaning.
Compiler-generated entities MUST have an unambiguous mapping back to submitted
identifiers and constraint components.

The compiler MUST reject unsupported semantics before search with a structured
error identifying the operation, combination, or numeric limit. It MUST NOT
drop a constraint, substitute a weaker scope, truncate a candidate domain, or
interpret absent demand as zero. Conservative domain restriction changes the
problem and therefore requires an explicit new problem identity.

Units and integer quanta MUST remain explicit. Before converting quantities to
floating-point native values, the compiler MUST check its declared guard for
individual values, aggregate loads, coefficients, scaling, and intermediate
expressions. Passing an individual representability check alone is
insufficient. Rounding upward demands or downward capacities changes the
problem; such transformations MUST NOT be hidden behind a capability claim.
Unrepresentable models MUST fail closed.

Approximate search arithmetic MUST NOT redefine exact feasibility or objective
equality. The runner MUST recompute both using the model's exact evaluator.
Solver bounds and optimality claims MUST identify their numerical assumptions
and MUST NOT be presented as independently verified mathematical proofs merely
because the final assignment passes verification.

## 8.3. Constraints, repair, and objectives

Hard Dispatch obligations MUST compile with explicit Rebalancer `HARD`
enforcement or an equivalent native hard expression. The adapter MUST NOT use
upstream default softening to implement hard constraints. Rebalancer's
[constraint policies](https://github.com/facebook/rebalancer/blob/8a3f38401a92458f47909972e17a756c3c317acc/website/docs/reference/constraint-policy.md)
distinguish hard enforcement from best-effort repair of initial violations.

Dispatch repair MUST compile as its declared componentwise nonworsening debt
envelopes and explicit objective terms. The observation-derived debt vector
MUST survive preprocessing unchanged. Repair priorities MUST NOT inherit
native default penalties or a global summed-debt approximation. Eligibility,
atomicity, co-location, and fixed-placement obligations MUST retain their
version 1 hard semantics.

Objective tiers MUST map to lexicographic boundaries; terms within a tier MUST
retain their explicit weights and normalizers. A large weighted sum MUST NOT
replace strict tier priority. Upstream
[goal boundaries](https://github.com/facebook/rebalancer/blob/8a3f38401a92458f47909972e17a756c3c317acc/website/docs/reference/goal-priorities.md)
provide the corresponding modeling construct. The runner MUST compare
accepted candidates with exact rational objective values, regardless of native
tolerance-based ties. A bounded solve need not prove any tier optimal.

Movement specifications MUST preserve physical cost, charged categories, and
the observed baseline. The adapter MUST disable implicit normalization when
using native movement expressions, or implement an explicitly equivalent
formula. Retirement, new placement, and source-dependent transfer costs MUST
be represented faithfully. An unsupported cost formula MUST be rejected.

Observed placement and a search hint have distinct meanings. A hint MUST NOT
replace the baseline for movement, repair, fixed placement, or overlap. The
adapter MUST reject a requested hint form if its native integration cannot
preserve that separation. Retaining a previous candidate as a new hint MUST
NOT silently update observations.

Native `DURING` utilization MAY help implement overlap capacity only when its
accounting matches the submitted holdings and charges. It does not establish
migration ordering, copy completion, ownership transfer, or quorum safety.
The compiler MUST reject overlap forms it cannot represent faithfully.

## 8.4. Search and lifecycle capabilities

The Rebalancer adapter MUST support final-result solving through the selected
local-search mode. A separately advertised MIP mode MAY use HiGHS; its
capability profile MUST describe the compatible expressions and combinations.
Backend selection MUST be explicit and recorded. Failure to load a requested
mode MUST NOT silently substitute another mode or engine.

The base local execution profile MUST provide a final result and externally
enforced hard cancellation. Hard cancellation is a provider guarantee, not a
claim that Rebalancer supports cooperative interruption. The runner MUST keep
control handling responsive during native search and MUST terminate the worker
tree when required. Graceful cancellation, incumbent streaming, progress
metrics, retained materialization, and model updates are optional negotiated
capabilities. An adapter MUST NOT advertise them without passing their
conformance cases.

Preparation MUST promise storage of validated immutable input within session
limits. It MUST NOT imply preservation of native expression graphs, MIP search
trees, or efficient incremental updates. Backend-local handles MUST bind to
the session, worker generation, semantic digest, and capability profile.
Runtime session-input handles have the broader lifetime specified in Section
6.7 and MUST be materialized into a worker before native use. A backend MAY
cache native representations only under declared ownership and memory limits.

A terminal outcome MUST distinguish candidate availability from stopping
reason. Timeout with a candidate, timeout without a candidate, cancellation,
worker failure, and an infeasibility claim are different outcomes. Heuristic
exhaustion MUST NOT become a proof of infeasibility. A candidate MUST be
verified before it is eligible for a successful Dispatch result.

## 8.5. Provenance and source builds

Backend identity MUST include engine revision, adapter revision, capability
version, native dependency identities, and effective search configuration.
Replay records MUST also preserve problem identity, seed where applicable,
thread settings, tolerances, and selected mode. A seed MUST NOT imply
deterministic output unless that complete execution configuration has a tested
determinism contract.

For AOS distribution, the Rebalancer package and all build and runtime
dependencies MUST be built hermetically from pinned source through AOS
packages. Host tools, upstream nixpkgs dependencies, binary wheels, and
upstream system-package installers
MUST NOT enter the derivation. Native code generation MUST use source-built
tools. The dependency closure MUST include required libraries without
disabling supported features merely to simplify packaging.

The native build environment MUST supply the compiler standard and dependency
closure required by the pinned engine revision, including its code generators.
The [Rebalancer build definition](https://github.com/facebook/rebalancer/blob/8a3f38401a92458f47909972e17a756c3c317acc/CMakeLists.txt)
identifies the upstream build contract. The package MUST retain applicable
licenses, notices, pinned sources, and AOS patches for its full dependency
closure. Optional components MAY be separate packages with explicit
capabilities. Commercial solver integrations MUST NOT be prerequisites for
the selected open-source execution profile.

## 8.6. Alternatives

These comparisons explain the engine selection; they do not require every
alternative backend to exist.

| Alternative | Useful fit | Dispatch consequence |
|---|---|---|
| Rebalancer | Assignment specifications and graph-assisted local search | Selected engine; requires semantic compilation and independent verification |
| Direct HiGHS | [Sparse LP and MILP](https://ergo-code.github.io/HiGHS/stable/) with explicit mathematical models | Bounded MILP search with incumbent and bound reporting; Dispatch must supply the modeling layer |
| OR-Tools CP-SAT | [Integer constraints and distinct feasible/optimal statuses](https://developers.google.com/optimization/cp/cp_solver) | Candidate for Boolean-rich admission and placement; requires checked coefficient scaling and its own compiler |
| Minimum-cost flow | [Restricted assignment problems](https://developers.google.com/optimization/flow/assignment_min_cost_flow) expressible as capacitated networks | Efficient specialized mode; general resource and group constraints need a faithful reduction or rejection |
| Hashing and CRUSH-style placement | [Topology-directed distributed storage mapping](https://docs.ceph.com/en/latest/rados/operations/crush-map/) | Useful domain placement policy or initial assignment; does not supply the full submitted objective and constraint model |
| Timefold | [Java planning with ordered constraint scores](https://docs.timefold.ai/timefold-solver/latest/introduction) | Alternative modeling ecosystem and runtime; requires the same portable semantics and verifier boundary |
| SCIP | [Constraint integer programming](https://www.scipopt.org/) | Alternative for richer mathematical models; adds compiler and native dependency maintenance |

Selection of a specialized mode MUST remain subordinate to compatibility
checks. A faster reduction MUST NOT weaken the submitted problem. Engine
history, language, or licensing alone does not establish compatibility.

# 9. Conformance

## 9.1. Base profile and extensions

Base conformance MUST cover the complete version 1 evaluator, the session
lifecycle, the local backend protocol, and the Rebalancer adapter's advertised
model subset. A backend need not solve every valid model, but MUST reject
unsupported models explicitly. Local operation MUST NOT require a shared
daemon or remote service.

Execution providers MUST pass the cases for their advertised guarantees.
Systemd, embedded, remote, streaming, graceful cancellation, retained native
state, and updates have separate capability suites; absence of an optional
capability MUST NOT invalidate base conformance.

Adding a semantic operation requires its versioned schema, exact evaluator,
compiler support or explicit rejection, canonical vectors, and conformance
fixtures. An opaque native callback MUST NOT bypass these requirements.

## 9.2. Semantic and compiler fixtures

The suite MUST use an independent small-instance oracle, such as exhaustive
enumeration, rather than rely solely on the verifier or compiler under test.
It MUST check assignment completeness, eligibility, capacity, group admission,
atomicity, co-location, failure-domain spread, fixed placement, movement,
concurrent occupancy, repair debt, and objective ordering.

Fixtures MUST include overlapping groups and target sets, sparse/default
expansion, target-dependent demand, empty domains, zero and unbounded capacity,
unknown topology, mandatory and deferrable items, and contradictory valid
constraints. They MUST distinguish invalid input, unsupported backend input,
infeasibility, and failure to find a candidate.

Numeric fixtures MUST cover maximum quantities, aggregation overflow, rational
denominators, unit mismatches, floating-point guard boundaries, and a small
demand alongside a large load. Repair fixtures MUST reject new debt in a
previously satisfied component even when aggregate debt decreases. Hint
fixtures MUST detect any change to the observed baseline.

When any search mode claims an optimum on a small supported problem, its exact
objective vector MUST agree with the independent oracle. Different modes'
assignments need not match when several optima exist. Heuristic modes MUST
return verified candidates and meet declared quality criteria; they MUST NOT
be required to produce identical plans or exact optima.

## 9.3. Protocol, failures, and containment

Cross-language vectors MUST cover canonical encoding and digests, identifier
ordering, numeric boundaries, errors, and complete request/result exchanges.
Protocol fuzzing MUST exercise malformed frames, excessive nesting and sizes,
unknown mandatory fields, duplicate identifiers, invalid state transitions,
stale handles, and mismatched model or capability identities.

Fault tests MUST cover native crashes, stalled input or output, runner failure,
memory exhaustion, oversized diagnostics, deadline expiry in every stage, and
completion/cancellation races. They MUST establish one terminal outcome,
bounded cleanup, and handle invalidation after worker replacement. Unverified
native output MUST never survive as a successful result.

Resource suites MUST measure aggregate accounting across sessions and cloned
handles, thread/task limits, bounded queues, retained input, and worker memory.
Providers claiming cgroup containment MUST exercise worker and ancestor OOM
behavior. Warm execution MUST exercise residual state, retained charges,
recycling, and stable profile placement. Best-effort controls MUST remain
distinguishable from enforced limits.

## 9.4. Performance and replay evidence

Qualification MUST measure cold process startup, input transfer, validation,
materialization, search, verification, and terminal construction separately.
It MUST report warm-process behavior without assuming warm materialization.
Measurements MUST identify hardware, resource profile, concurrency, engine
build, model dimensions, and sparse/dense representation.

Reports SHOULD include wall time, CPU consumption, peak and retained memory,
deadline completion, verified candidate rate, movement cost, and exact
objective quality against small-instance optima or declared baselines.
Consumers MUST choose budgets from representative fixtures rather than
upstream deployment anecdotes. Any determinism claim MUST survive replay
under its declared build, ordering, seed, and execution conditions.
