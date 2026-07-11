# RFC-0007 - Unexplored performance levers

> Every lever in docs [01](01-motivation-and-goals.md)–[30](30-flat-value-architecture.md)
> makes the evaluator *compute* faster. This document is about the wins
> that come from not computing, not re-reading, not re-hashing, and not
> re-starting.

This document records a survey (2026-07-10) of performance levers that
are **absent from the RFC-0007 corpus** — verified by inventorying docs
[01](01-motivation-and-goals.md)–[30](30-flat-value-architecture.md),
the pass catalog ([26](26-optimization-pass-catalog.md) §2.1–§2.14), the
tier stack ([08](08-execution-tiers-and-cranelift.md) §2), the memo
tiers ([29](29-tiered-content-keyed-memoization.md) §5), and the
decision register ([19](19-decision-register.md)). It is a later
addition to the set in the same manner as
[29](29-tiered-content-keyed-memoization.md)–[30](30-flat-value-architecture.md):
written against the shipped vocabulary and grounded in the campaign's
measured evidence, not speculation about where time might go.

Each lever states what it is, why the existing corpus does not cover
it, the measured evidence that makes it attractive *for this workload*,
its prerequisites, and its acceptance gate. Nothing here weakens the
byte-parity contract of [02](02-compatibility-constraints.md): every
lever is representation- or schedule-internal and lands behind the same
`.drv` byte-parity and `nix-bench` gates as everything else
([15](15-differential-testing-and-benchmarking.md)).

Ordering context: at survey time the native evaluator measures a
**0.44x geomean** cold `native/oracle` ratio (~2.3x faster than C++
Nix) across the explicit 17-attr suite on darwin, byte-parity green
with `AOS_NIX_JIT=1`, against the declared 10x-cold goal. The remaining
committed multipliers (L2 parallel forcing, the persistent
compiled-body cache) are in flight; this document is the inventory of
what exists *beyond* them.

---

## 1. Evaluator heap-image snapshots (V8 startup snapshot / JVM CDS)

**What.** Serialize the *evaluated heap itself* — the prelude fixpoint
(`lib`, `pkgs/default.nix` scaffolding, stdenv wiring) already forced
into flat values — as an mmap-able, rebasable image. A cold eval then
begins from `mmap(2)` of the snapshot: no parse, no lowering, no
re-forcing of the shared prefix, pages faulted lazily. This is V8's
startup-snapshot / custom-snapshot mechanism and the JVM's CDS/AppCDS
applied to Nix evaluation.

**Why the corpus doesn't cover it.** The persistence story in
[29](29-tiered-content-keyed-memoization.md) is *per-record*: each memo
record is independently keyed, fetched, and revalidated, and each hit
still pays lookup + reconstruction per record. A heap image is one
artifact with zero per-value reconstruction cost. All `snapshot`
occurrences in [06](06-memory-management-and-gc.md) and
[30](30-flat-value-architecture.md) are GC-internal (collector-poll
edge snapshots, dirty-card views), not startup images.

**Evidence.** The measured tier-up economics show the hot prelude
structures are bit-identical across the whole package set (top hot
lambda bodies identical across zlib/openssl/coreutils/bash/jq;
296 of 375 source-keyed def-sites shared by all five). The same is true
of the *values* those bodies produce: every package eval re-derives the
same prelude graph. A snapshot converts that re-derivation into page
faults.

**Prerequisites — largely already being built.** Position-independent
flat values ([30](30-flat-value-architecture.md)) and the relocation
work landed alongside them (relocation-sensitive identity
classification and repair, precise stack-map roots) are exactly the
substrate a dumpable, rebasable heap needs. The remaining design
surface: a snapshot boundary definition (what is "the prelude" — likely
the post-`import <repo>/default.nix` fixpoint before any
package-specific demand), an invalidation key (the parse-cache
fingerprints of every file the snapshot observed, per
[29](29-tiered-content-keyed-memoization.md) §3.1), and a rebase step
if the mapping address differs (or compressed 32-bit indices from
[30](30-flat-value-architecture.md) §2, which make the image
address-free by construction).

**Expected magnitude.** The largest single unclaimed step toward 10x
cold: it moves the shared-prefix portion of cold eval (the dominant
portion, by the def-site sharing evidence) into warm-class territory.

**Gate.** Byte-parity x corpus with snapshot on/off; `nix-bench`
cold-eval delta; a CHECK mode that re-evaluates the prelude and
byte-compares against the mapped image (same pattern as
[29](29-tiered-content-keyed-memoization.md) §7.1).

## 2. Process-model exploitation: zygote fork, CoW variant eval, shm sharing

**What.** Use Unix process semantics as a caching layer:

- **Zygote**: a resident template process holds the warmed state
  (parse cache, JIT code pages, prelude heap, symbol table);
  each eval request is served by `fork()` — copy-on-write isolation
  for free, no warmup, crash isolation per request.
- **CoW variant eval**: evaluate the shared prefix once, then fork per
  system variant (`edge`/`dev` x `x86_64`/`aarch64`); the common
  majority of the heap stays physically shared.
- **shm heap sharing**: expose the flat-value prelude heap as a
  read-only shared-memory segment so concurrent `aos` processes on one
  CI builder share a single copy.

**Why the corpus doesn't cover it.** "Daemon mode" exists in the GC
design ([01](01-motivation-and-goals.md) §GC choice,
[03](03-architecture-overview.md) §arena table) purely as a *GC-policy
distinction* (generational copying vs bump-arena). No document uses
`fork`, CoW, or shared memory as an evaluation-state reuse mechanism;
`zygote` appears nowhere.

**Evidence.** Same sharing evidence as §1; additionally the CI usage
pattern (many evals of near-identical closures per builder, RFC-0007
motivation §1) is the textbook zygote workload.

**Prerequisites.** Flat values (position independence for shm), and for
the zygote a fork-safety audit of the runtime (no live threads across
`fork` — coordinate with the rayon pool of
[13](13-parallel-evaluation.md) §5.5: quiesce workers before forking,
or fork from a dedicated single-threaded template).

**Expected magnitude.** Marginal cost per additional variant/eval drops
toward the demand-front-only work; multi-variant system builds and CI
matrices benefit most.

**Gate.** Byte-parity per forked child vs a fresh process; RSS
accounting demonstrating physical sharing (PSS per child).

## 3. A threaded-code baseline tier for the unpromotable tail

**What.** Compile IR once into a compact register bytecode executed by
a computed-goto (threaded) dispatch loop with interpreter-level inline
caches and fused superinstructions (`force+select`, `force+apply`,
`force+binop`), replacing the tree walk as the *production* baseline
tier. The tree walk remains the differential oracle, unchanged.

**Why the corpus doesn't cover it.** The tier stack in
[08](08-execution-tiers-and-cranelift.md) §2 is tree-walk -> Cranelift
baseline -> Cranelift optimized (-> LLVM AOT, P7.5). Bytecode appears
in the corpus only as prior art (`snix-eval`'s VM,
[16](16-prior-art-and-references.md)). No document proposes making the
baseline interpreter itself faster via dispatch/representation
techniques.

**Evidence.** This is the lever the JIT-economics measurements point at
*by elimination*: the measured per-eval profile has 797 def-sites at
2–9 calls each carrying ~29% of body time, and the cost decomposition
proved tiny-body JIT promotion loses to the dispatch harness — the tail
is structurally unreachable by tiering up. A 1.5–3x faster baseline
(typical for tree-walk -> threaded-bytecode conversions) attacks
exactly the fraction the JIT cannot.

**Prerequisites.** The IR is already scope-resolved de Bruijn form with
a serialization contract ([25](25-intermediate-representation.md)), so
lowering to bytecode is a straight pass; the parse/compile cache can
persist the bytecode alongside (or instead of) the lowered IR.
Superinstruction selection should come from the existing
dispatched-primop histogram evidence (e.g. `stringLength`-class
dominance), not intuition.

**Expected magnitude.** ~10–15% of end-to-end eval if the tail's 29%
body-time share speeds 1.5–2x; more once other overheads shrink and
interpretation re-dominates.

**Gate.** Byte-parity x corpus with the bytecode tier as producer and
the tree walk in CHECK mode; per-dispatch microbenchmarks; the
file-size and unsafe-fence standards of
[27](27-engineering-standards.md) apply to the dispatch loop.

## 4. A VFS snapshot layer for path primops

**What.** One persistent source-tree manifest — stat metadata + content
hashes for every file the evaluator can observe, keyed by the git index
state — batch-refreshed with `io_uring` on Linux (`getattrlistbulk` on
darwin), invalidated by a filesystem watcher in daemon/zygote mode. All
path primops (`import`, `pathExists`, `readFile`, `readDir`,
`builtins.path`) and all memo-key derivation resolve against the
manifest; the kernel is consulted once per tree state, not once per
primop call.

**Why the corpus doesn't cover it.** File-system access appears in the
corpus only as *semantics* (impure-observation slices,
[29](29-tiered-content-keyed-memoization.md) §2.3) and as ad-hoc memos
in the campaign log (import-symlink-stat memoization). `io_uring`
appears nowhere; no document proposes a systemic VFS snapshot.

**Evidence.** The round-8 cold-eval profile attributes ~9% of wall to
the file-I/O/stat cluster *after* the ad-hoc memos landed; each
remaining stat is also a serialization point on the demand front.

**Prerequisites.** None architectural. The impure-observation slice
machinery of [29](29-tiered-content-keyed-memoization.md) already
defines what "the evaluator observed path P" means; the manifest is a
faster oracle for the same observations, so CHECK mode comes free
(compare manifest answers against live syscalls).

**Expected magnitude.** Most of the ~9% cluster, plus latency-hiding on
the parallel demand front (L2, [13](13-parallel-evaluation.md)).

**Gate.** Byte-parity with manifest on/off; a staleness CHECK sampling
live stats against manifest entries; correct behavior under mid-eval
mutation (define: manifest is a snapshot, mutation during eval is
already out of contract per pure-eval scope,
[23](23-scope-platform-and-modes.md)).

## 5. Vectorized and incremental hashing

**What.** Two independent halves:

- **Multi-buffer SHA-256**: hash many small independent inputs in
  interleaved SIMD lanes per core (Intel ISA-L style), beyond
  single-stream SHA-NI. Memo-key derivation
  ([29](29-tiered-content-keyed-memoization.md) §3) produces exactly
  this shape — thousands of small independent digests per eval.
- **Merkle-incremental `.drv` hashing**: cache ATerm subtree digests
  content-keyed, so a one-line version bump re-hashes the changed spine
  only, not every unchanged input-drv subtree; render the ATerm through
  a streaming writer with cached subtree lengths (subsumes the known
  drv-serialize BTreeMap-churn queue item).

**Why the corpus doesn't cover it.** [11](11-derivation-and-store-compatibility.md)
§9 specifies *which* hashes exist and what they key — never their
computation cost. No document mentions SHA-NI, multi-buffer hashing, or
incremental ATerm digests.

**Evidence.** Content-keyed memoization moves SHA-256 onto the per-record
hot path by design; the more §29 lands, the more this lever pays.
(Unmeasured share — the first deliverable is an `AOS_NIX_EVAL_STATS`
hashing-time counter, per the measure-first rule.)

**Prerequisites.** None. Both halves are drop-in behind existing hash
call sites.

**Gate.** Byte-parity (digests must be bit-identical — this is pure
implementation substitution); hashing-time counter before/after.

## 6. Store-validity as an mmap'd perfect-hash snapshot

**What.** Materialize valid-store-path membership into an mmap'd
minimal-perfect-hash (or bloom) filter, regenerated lazily from the
store DB; the hot path answers `isValidPath` with one probe and no
SQLite query, falling back to SQLite only on maybe-hits and on filter
staleness.

**Why the corpus doesn't cover it.** Store interaction in
[11](11-derivation-and-store-compatibility.md) and
[14](14-integration-with-aos.md) is about *what* is asked, not how fast.
The campaign already moved from subprocess-per-query to in-process
SQLite (measured at 89% of wall before the fix); the endgame — no query
at all — is nowhere proposed.

**Evidence.** The magnitude of the previous step on the same path; the
remaining SQLite cost is measurable via the existing eval-stats
counters before committing.

**Prerequisites.** A cheap store-generation stamp to key filter
staleness (the store DB's schema/version row or the DB file's change
counter).

**Gate.** Byte-parity; false-positive handling proven by CHECK-sampling
filter answers against SQLite.

## 7. Binary-level tuning: PGO, BOLT, LTO, allocator

**What.** Profile-guided optimization of the evaluator binary itself
(rustc `-Cprofile-generate`/`-Cprofile-use` driven by a corpus eval),
post-link layout with BOLT/Propeller, fat LTO for the release binary,
and an allocator swap (mimalloc/jemalloc) for the non-arena allocation
traffic.

**Why the corpus doesn't cover it.** [27](27-engineering-standards.md)
covers performance *practices* in code; no document mentions PGO, BOLT,
link-time layout, or allocator selection. (Huge pages for the arena are
already noted in [06](06-memory-management-and-gc.md) and excluded
here.)

**Evidence.** Interpreter-heavy, branch-dense binaries are the best
case for PGO+BOLT (typically 10–20% in comparable runtimes); the
round-8 profile attributes ~24% of on-CPU to allocation traffic, part
of which is malloc-path cost an allocator swap addresses independently
of the flat-value/arena work.

**Prerequisites.** CI plumbing only: a representative profiling
workload (the explicit `nix-bench` suite is exactly that) and a
two-stage build. Zero design risk; composes multiplicatively with every
other lever.

**Gate.** `nix-bench` before/after on the same commit; byte-parity is
unaffected by construction but runs anyway.

## 8. Trace-driven prewarming (distinct from C-19)

**What.** Persist the previous eval's *demand trace* (the order in which
thunks were forced and files/memo-records were read) and replay it on
idle workers at the start of the next eval: prefault L2 memo records,
prewarm the VFS manifest and parse cache, and speculatively pre-force
pure thunks ahead of the demand front.

**Why the corpus doesn't cover it.** C-19/M-23
([19](19-decision-register.md), [04](04-frontend-parser-and-ir.md)
§9.6) commit speculative *parse/compile* prefetch along
statically-known import edges. This lever is different on both axes:
the signal is the *previous run's dynamic trace* (not static edges) and
the object is *values and records* (not parses). It is a scheduling
policy over machinery L2 parallelism already provides.

**Evidence.** Warm-adjacent evals in CI repeat their demand order
almost exactly (same corpus, small diffs); the L2 work
([13](13-parallel-evaluation.md)) supplies the safe concurrent forcing
substrate, and pre-forcing a pure thunk is semantically invisible by
construction (same error-quarantine discipline as C-19: a speculative
failure is stashed and raised only on genuine demand).

**Prerequisites.** L2 parallel forcing landed; a compact trace record
(def-site/thunk identity sequence — the tier-up counters already
compute the identities).

**Gate.** Byte-parity with prewarming on/off; wall-clock delta on
one-line-bump re-eval (the [12](12-incremental-evaluation-cache.md) §7
scenario); mis-speculation (wasted pre-force) rate counter.

---

## 9. Ordering and phasing

By cost/risk against the measured profile:

1. **§7 (PGO/BOLT/LTO/allocator)** and **§5 (hashing)** first: no
   design coupling, measure-first counters land with them, each is
   days not weeks.
2. **§4 (VFS manifest)** and **§6 (store-validity filter)** next: each
   kills a known, measured hot cluster behind a CHECK mode.
3. **§1 (heap snapshots)**, **§2 (process model)**, **§3 (bytecode
   baseline)** are RFC-grade campaign additions in their own right —
   §1 first, because the flat-value + relocation work already being
   landed is quietly building its prerequisite, and it is the largest
   single unclaimed step toward the 10x-cold goal. §8 waits for L2.

Every lever enters through the standard regime: byte-parity supremacy
([02](02-compatibility-constraints.md)), per-lever CHECK modes
([29](29-tiered-content-keyed-memoization.md) §7.1 pattern), and
`nix-bench` admission with the perf-win gate
([15](15-differential-testing-and-benchmarking.md)).

## Candidate decision-register entries

For folding into [19](19-decision-register.md) when individual levers
are taken up (numbers to be assigned there):

| Candidate | Decision needed | Gating measurement |
|-----------|-----------------|--------------------|
| Heap snapshot boundary (§1) | What constitutes "the prelude" snapshot point; address-free image via compressed indices vs rebase step | Share of cold eval spent inside the snapshot boundary |
| Zygote fork safety (§2) | Quiesce-workers-then-fork vs single-threaded template process | Fork latency + PSS sharing under concurrent evals |
| Bytecode baseline scope (§3) | Replace tree walk as producer vs sit beside it as tier 0.5 | Tail (sub-promotion-threshold) share of body time after other levers land |
| VFS manifest staleness contract (§4) | Snapshot-per-eval vs watcher-maintained; mid-eval mutation stance | Stat-cluster share of wall; staleness CHECK hit rate |
| Trace prewarming aggressiveness (§8) | Pre-force depth; purity classification source | Mis-speculation rate vs idle-worker availability |
