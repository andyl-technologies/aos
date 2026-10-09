# Dispatch Rebalancer worker

`dispatch-rebalancer` is the source-built C++ process adapter for Meta's
Rebalancer engine. Its standard input and output carry the versioned protobuf
worker protocol, framed with a four-byte big-endian length. Logs use standard
error. A process can serve repeated requests and retain bounded portable models;
retention does not cache native materialization or introduce a persistent daemon.

The Rust runner validates and commits the model before forwarding it. The worker
echoes its canonical model and request commitments, binds prepared handles to
their worker generation and model commitment, and returns candidates. The Rust
reference evaluator independently determines feasibility and objective values.
Native success never certifies feasibility, optimality, or infeasibility.

The compiler explicitly uses HARD constraints. It supports domains, fixed
bindings, final and overlap resource ceilings, admission counts, atomic
admission, co-location, spread, and explicit physical movement ceilings. Capacity,
admission, and unconditional spread can use componentwise nonworsening repair
envelopes derived from historical charges and placements. Overlap accounting
uses historical source charges plus target-dependent destination charges, with
the maximum of old and new charges for unchanged placements. Ordinary holding
fragments are counted once; additional holdings remain explicit. This occupancy
envelope is not a safe migration schedule.

Admitted-count, admitted-priority, assignment-cost, movement-cost, used-target,
utilization, absolute-deviation, and repair-debt objectives compile into
lexicographic goal tiers. Maximum and range utilization require disjoint target
sets sharing one dimension and accounting phase; absolute deviation supports
arbitrary selections. Integer scaling preserves each tier's rational ordering.
Movement categories and destination costs remain
relative to immutable observations; native movement normalization and magic
scaling are not used. Quantities, scaled coefficients, denominators, and
conservative expression sums must fit the declared exact binary64 integer range.
Native comparison operands, resource expression sums, repair bounds, and
combined scaled tier magnitudes additionally stay below `2^51`; the adapter
sets the engine's relative comparison tolerance to machine epsilon so adjacent
integer tier values retain their ordering. The engine's positive absolute
tolerance remains below one accounting quantum. Native numerical search still
does not replace independent exact evaluation.
Compilation admits at most one million item/destination coefficient pairs and
four million nonzero dimension and objective entries. Identical resource
dimensions, group count dimensions, scopes, and the common object partition are
shared within a solve. Singleton capacity selections use the native container
scope directly. The capability tokens expose the `profile.rebalancer.v1`
restrictions: `repair.capacity_admission_spread`,
`spread.positive_conditional_minimum_requires_mandatory_or_empty`,
`utilization.maximum_range_disjoint_single_dimension_phase`, both
`compilation.maximum_*` limits, `control.seed_signed32`,
`objective.maximum_scaled_tier_magnitude.2251799813685247`,
`comparison.maximum_scaled_magnitude.2251799813685247`,
`control.maximum_threads.128`, `control.mip_minimum_wall_time_millis.1000`,
`control.iterations.unsupported`, `assignment_hint.unsupported`, and
`prepared.portable_input_only`. Supported kind lists do not override these
combination restrictions; compilation remains the authoritative acceptance check.
Unsupported constraint combinations, unsupported utilization selections, lossy numbers,
assignment hints, and iteration budgets are rejected explicitly.

Local search and the source-built HiGHS backend are selectable. Native seed
handling does not promise deterministic output. The public engine API cannot
provide a sound stop reason or search certificate for every solve, so the adapter
does not claim either. It does not stream incumbents, support graceful
cancellation, or modify prepared models. The execution provider owns wall-time,
memory, CPU, and hard cancellation enforcement; a killed worker invalidates all
its handles. Subsecond local search budgets can return the initial candidate;
native MIP requires at least one second of remaining search budget.

The AOS package builds the pinned engine, adapter, protobuf bindings, and all
dependencies from source. CMake builds focused native conformance tests covering
real search, numeric and semantic rejection, warm sessions, prepared models,
request replay, and stale handles. Engine and dependency licenses and complete
source outputs accompany distribution.

An independently source-built development closure must pass an explicit build
identity covering the adapter, protocol, engine revision, and dependency versions
or content identities: `cmake -DDISPATCH_BACKEND_BUILD_ID=<closure-identity> ...`.
CMake rejects an absent identity. The AOS package supplies its source and
dependency closure identity automatically.
