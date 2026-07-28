# Module IR and source lifetime

## Why this is on the acceptance path

The exact system-toplevel accounting attributes approximately 326,130,731
bytes to resident module IR and at least 46,594,467 bytes to retained source.
Together they exceed 355 MiB. Even perfect heap collection cannot meet the
414,326 KiB peak-RSS ceiling while these representations remain unchanged.

`TreeWalk.modules` is append-only. Each `TreeWalkModule` owns an `Ir` and a
`ModuleSource`; imported ASTs are consumed by lowering, but executable IR and
source bytes remain for the evaluator's lifetime. Heap code references already
use stable `(EvalModuleId, IrId)` pairs, so module IDs must stay stable while
the backing representation may be compacted, paged, or evicted.

## Current representation costs

Exact layout inspection gives these important fixed costs:

```text
IrNode       40 bytes
IrBinding    24 bytes
FrameInfo    24 bytes
```

The dense `IrFacts` representation costs at least 42 bytes per node before
nested allocations:

- three bytes of expression facts;
- three boxed boolean arrays;
- a 24-byte optional capture plan; and
- a 12-byte optional flat-capture access.

Nodes plus base facts therefore consume at least 82 bytes per node before
children, bindings, frames, shapes, attr paths, and nested capture arrays.
The measured IR total would correspond to at most about four million nodes if
those were the only costs; a component census is required before assigning an
exact node count or savings.

The source owner stores name bytes, the complete source byte snapshot, and a
lazy boxed line-start table. The existing census counts name/source capacity
but omits initialized line-start storage, so 46.6 MB is a lower bound.

## Source snapshot paging

Raw source remains useful for:

- source identity hashing;
- exact error snippets; and
- bounds/newline lookup for `unsafeGetAttrPos`.

Reopening an impure source path after lowering is unsound because the file may
have changed or disappeared. Instead, eagerly freeze the content identity and
line-start table, append the exact bytes to a per-run sealed file-backed source
pack, and retain:

```text
(name, byte_length, digest, line_starts, pack_offset)
```

Cold pack pages can be advised away and faulted back from the same immutable
intra-run snapshot when an error needs exact bytes. This obeys strict-cold
semantics: no data is imported from another run, and no mutable external source
is reread. The normal evaluator hot path pays no source lookup after identity
freezing. The upper-bound resident saving is about 46.6 MB plus avoided
duplicate/error buffers.

Required tests cover exact diagnostic snippets, invalid UTF-8/source bytes,
deleted or mutated impure files after lowering, `unsafeGetAttrPos`, source
identity, and both Nix 2.24 and 2.34 modes.

## Packed facts

The lowest-risk IR compaction target is an authoritative `PackedIrFacts`:

- pack strictness, cardinality, escape, barrier, eager, and total flags into a
  word or compact bit lanes;
- store one kind-disjoint auxiliary index per relevant node; and
- move capture slots into a contiguous side pool.

Capture plans and flat-capture accesses are relevant to different node kinds;
paying both optional-enum layouts for every node is unnecessary. A 4-12 byte
per-node packed representation would save roughly 30-38 bytes per node. At
three to four million nodes, the plausible saving is about 86-145 MiB.

This canary must replace, not duplicate, the dense facts. Every current
analysis accessor and parse-cache round trip remains authoritative and receives
exact 2.24/2.34 differential coverage.

## Packed nodes

The next representation is an authoritative packed operation lane:

```text
op/flags/effect | operand a | operand b | operand c
```

A 16-byte operation record with a separate eight-byte span lane saves about
16 bytes per node relative to the current 40-byte `IrNode`, or approximately
46-61 MiB at three to four million nodes. A first oracle adapter may decode a
node by value for tree-walk execution. The old `IrNode` lane must then be
removed; retaining both is instrumentation, not a memory improvement.

Prior profiles put direct node lookup at a small percentage of execution, so
decode overhead may be affordable and denser cache locality may offset it.
The gate is exact output/error behavior and at most a 2% instruction
regression. The factor-level endpoint is direct execution from the packed lane
or complete packed bytecode, with tree-walk decode retained only as an oracle.

## Module liveness and eviction

Cold module eviction depends on complete heap/root liveness and therefore
follows collectible composite epochs. At a collection statepoint:

1. mark code-live modules from surviving thunks, lambdas, active
   continuations, and all explicit evaluator roots;
2. distinguish executable-IR references from source-provenance-only
   references;
3. retain stable module slots as
   `Resident(PackedIr) | Evicted(ArtifactRef)`; and
4. store exact packed IR in the same per-run file-backed artifact pack before
   advising or dropping resident pages.

Mapped packed IR with page advice is preferable to repeatedly deserializing
into heap allocations. Reload remains intra-run and byte-stable.

The packed artifact schema must record every lowering input. Force-cache
identity already includes the selected `NixCompatProfile` and reported Nix
version. Syntax artifacts may be shared across 2.24 and 2.34 only while
lowering is proven profile-invariant; as soon as a compatibility switch changes
IR shape or facts, the profile/version belongs in the packed-artifact key.

Before implementation, add a report-only component and hotness census:

- node/child/fact/binding/frame/path/shape capacities;
- nested capture and summary bytes;
- source name/raw/line-index bytes;
- duplicate source digest/path-base pairs;
- module node-read counts and last-read epochs; and
- precise code-live and provenance-live module sets at collector checkpoints.

## Parallel duplication

`TreeWalkModule: Clone` is currently a deep clone. Parallel registry
synchronization and worker construction can duplicate root and imported module
IR/source per worker. The primary serial benchmark does not receive this
multiplier, but any parallel experiment must first share immutable modules as
`Arc<TreeWalkModule>` or an equivalent immutable registry. Otherwise parallel
speed results purchase approximately worker-count-proportional IR memory.

## Ordered implementation

1. Component/hotness census to replace projections with exact counts.
2. File-backed exact source snapshot and eager identity/line-index freezing.
3. Authoritative packed facts.
4. Authoritative packed nodes plus resident span lane.
5. Complete packed executor/bytecode representation.
6. Code/provenance-aware module eviction at proven collection statepoints.
7. Shared immutable module registry before parallel acceptance testing.

These changes are additive to composite epoch collection. Neither family alone
is sufficient for the final memory target.
