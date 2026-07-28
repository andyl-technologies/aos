# Evaluator benchmark integrity

Performance credit applies only to general evaluator mechanisms. An
optimization must not recognize a benchmark or repository workload through:

- an embedded Nix source file or exact source bytes;
- a source pathname, source slice, or benchmark derivation;
- fixed module, IR, frame, span, execution-ordinal, or completion coordinates;
- a workload-specific environment switch; or
- a measured benchmark constant used to select evaluator behavior.

The same prohibition applies when a benchmark is disguised as an opaque
source/IR fingerprint, serialized semantic certificate, canonicalized-subgraph
hash, or embedded reference program. Fingerprints are valid cache identities;
they must not select an execution plan. Executable optimization admission must
instead implement a documented, parameterized rewrite law over local semantic,
effect, and runtime-value properties.

The exact-source `finalConfig` trie and string-list deduplication canaries
violated this rule. So did the execution-176 weak-cache mutation and the
ordinal-selected packed-portal cutover. The numbered FinalForce
suspend-and-replay portal was another instance: it changed evaluator control
flow at a selected final-config completion. They and their
workload-recognition hooks have been removed. Their historical performance
numbers demonstrate only that those particular computations admit specialized
implementations; they provide no evidence about general evaluator performance
and receive no credit toward the RFC targets.

Read-only profiling may label a workload in an external harness. Production
evaluator code must instead expose general counters and semantic statepoints.
Reclamation policy may respond to allocation and resident-memory budgets, but
not to a benchmark completion number.

Any future structural optimization must be admitted by semantics available to
arbitrary programs and must pass:

- alpha-renaming, formatting, source-path, and unrelated-IR-renumbering tests;
- independently authored equivalent and near-miss programs, with generated
  variation in size, names, layouts, and irrelevant surrounding structure;
- cache-on/cache-off and collector-on/collector-off parity;
- Nix 2.24 and 2.34 compatibility parity; and
- an acceptance binary containing no experimental workload gate.

The `benchmark_integrity` integration test supplies a source-level backstop for
the removed mechanisms. Acceptance runs must additionally record the Cargo
feature set and result-affecting environment fingerprint.
