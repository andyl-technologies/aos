# Threaded-bytecode production baseline plan

**Status:** active implementation plan. The instruction-budget result at
`2ad401ad1` opens doc 31 section 3's measure gate: the remaining cold system
toplevel gap is a uniform interpreter-loop tax, not an import, environment-depth,
or JIT-coverage problem.

## 1. Decision and evidence

Adopt a compact register bytecode as the production baseline below Cranelift.
Keep the safe tree walker unchanged as the semantic oracle and fallback for
instructions not yet admitted to the bytecode producer.

The builder measurements in `instruction-bloat-perf-attribution.md` make this
an implementation decision rather than speculative architecture work:

- native and C++ execute the same number of function calls on the system
  toplevel (within 0.4%);
- native retires 4.56 times as many instructions per call at similar IPC;
- a file-free lambda interpreter pays the same per-operation tax, excluding
  imports, derivations, and module fixpoints as the cause;
- JIT promotion cannot cover enough sub-microsecond bodies to close the gap;
- the safe instruction-diet levers reduce the count by only 3.86%, with an
  optimistic floor still about three times C++.

The bytecode tier attacks the missing dimension: it turns a tree of Rust calls,
`Result` boundaries, node lookups, and repeated force wrappers into one dispatch
loop with explicit value and continuation stacks. The user-visible contract is
unchanged: byte-identical derivations, the same error classes and spans, and C++
Nix as the permanent final fallback.

## 2. Non-negotiable invariants

1. **Tree walk remains the oracle.** Bytecode never replaces the reference
   implementation. CHECK mode evaluates through both engines and compares raw
   values or final derivation bytes, depending on the boundary.
2. **Effects execute at most once.** A bytecode decline happens before executing
   an effectful instruction. There is no replay-from-root fallback after an
   effect has run.
3. **Laziness is preserved.** Bytecode thunks use the existing `EvalThunk` and
   force-state protocol. The VM changes how a thunk body executes, not when it
   becomes demanded or how blackholes and publication work.
4. **One runtime value ABI.** The selected Candidate-C `Value` and `EvalHeap`
   remain the only value carrier and allocator. The VM does not introduce an
   operand representation that needs conversion at every helper call.
5. **Memory cannot regress.** Bytecode and side tables are compact immutable
   module artifacts. Per-eval stacks are bounded by live expression depth and
   reused; they may not retain heap values beyond the corresponding tree-walk
   lifetime.
6. **No new unsafe zone.** The compiler and VM are safe Rust. Computed-goto is
   not required for the first implementation; a dense `match` loop establishes
   semantics and measurements before any dispatch variant is considered.
7. **Diagnostics retain source identity.** Every instruction can recover its
   originating `IrId` and `Span`. A runtime helper error is decorated through
   the existing current-module source path exactly once.

## 3. Placement and artifact model

The language-agnostic bytecode vocabulary and compiler live in
`ratchet-core::bytecode`. They consume lowered, annotated Core IR and produce a
`BytecodeModule` containing:

- a dense instruction vector;
- an `IrId -> entry pc` table for thunk bodies and callable expressions;
- compact side tables for constants, attribute paths, call sites, and spans;
- a compiler version and dialect ABI version for durable-cache identity;
- a coverage bitmap recording which entries are executable without fallback.

The executor lives in `ratchet-oracle::eval::bytecode` initially because it must
reuse the oracle's heap, environments, thunk protocol, builtin registry, and
typed errors. Once the runtime helper boundary is complete it can move to a
focused `ratchet-bytecode` crate without changing the artifact format.

Each `TreeWalkModule` owns an `Arc<BytecodeModule>`. Imports compile once when
their lowered IR is admitted. The existing parse-artifact bundle later persists
the bytecode next to the IR, keyed by compiler version, dialect ABI, value ABI,
and simplifier pass-set version.

## 4. Initial instruction families

The VM is register based. Registers are frame-local indices into a reusable
`Vec<Value>`; instructions name destination and source registers explicitly.
Control flow uses instruction offsets. Runtime helpers return
`Result<Value, TreeWalkError>`, but only helper boundaries carry `Result`; the
ordinary instruction-to-instruction path stays inside one VM call.

The first complete vocabulary is grouped by semantic admission order:

1. **Scalar and environment:** integer/float/bool/null constants, string/path
   constants through existing allocators, local/upvalue/global loads, move,
   force, and return.
2. **Control:** unconditional jump, truth-test branch, assert, and the boolean
   short-circuit forms.
3. **Calls and laziness:** allocate existing thunk payloads with bytecode entry
   identities, construct existing lambda payloads, apply, enter/leave lexical
   frames, and tail apply.
4. **Operators:** unary/binary operations lowered to typed runtime helpers,
   retaining existing coercion and error behavior.
5. **Collections:** list/attrset construction, select/has-attr inline-cache
   sites, update, interpolation, and formal-set binding.
6. **Dialect and primops:** direct builtin calls and dialect operations through
   stable registered helper IDs. Effectful helpers are terminal admission
   boundaries and cannot be followed by a decline.
7. **Measured superinstructions:** only after the baseline census, fuse the
   modal sequences (`load+force`, `force+apply`, `force+select`, and
   branch-on-forced-bool) when they reduce retired instructions on the system
   toplevel without increasing code size enough to regress I-cache behavior.

## 5. Staged implementation

### BC-0 - format, verifier, and compiler skeleton

- Define fixed-width instruction, register, PC, and helper-ID types.
- Compile scalar literals and lexical loads.
- Verify register bounds, branch targets, entry points, and effectful-decline
  placement before a module can execute.
- Add deterministic format/render tests and malformed-program rejection tests.
- Record bytecode compiler/version identity in module metadata without changing
  the durable cache key while the tier remains opt-in.

Gate: workspace unit tests; bytecode rendering deterministic across repeated
compiles; zero production behavior change.

### BC-1 - executable straight-line and control-flow slice

- Add the VM loop for scalar/environment/control instructions.
- Select it with `AOS_NIX_BYTECODE=1` only for fully admitted entries.
- CHECK mode runs admitted pure entries through both VM and tree walk.
- Add instruction, helper-call, decline, and maximum-stack telemetry behind
  `AOS_NIX_EVAL_STATS`.

Gate: language corpus for the admitted slice, raw-value CHECK equality, and no
RSS regression on `bench.wide-eval`.

### BC-2 - thunk, lambda, and apply spine

- Reuse existing thunk/lambda payloads with an execution-entry discriminator.
- Implement lexical frame enter/leave and argument-thunk creation.
- Move the modal force+apply+local-var path wholly inside the dispatch loop.
- Retain tree-walk execution for a thunk whose entry is not admitted; choose the
  executor before beginning the force so an effect cannot be replayed.

Gate: lambda-interp and attr-fixpoint byte parity; full strict-JSON corpus;
`loom` tests for the unchanged thunk publication protocol; retired instructions
per call at least 1.5 times lower than tree walk before proceeding.

### BC-3 - full producer coverage

- Add collections, interpolation, primops, dialect operations, imports, and
  derivation construction.
- Require every lowered executable `IrKind` to compile or carry an explicit,
  tested decline reason.
- Persist bytecode artifacts and validate their versioned cache identity.

Gate: 100% AOS closure producer coverage, 546/546 derivation-byte parity,
strict-JSON parity, error-class parity, and bytecode/tree-walk CHECK mode.

### BC-4 - dispatch and superinstruction optimization

- Use the BC-1/BC-3 census to rank sequences by retired-instruction mass.
- Compare dense-match dispatch, direct handler table dispatch, and selected
  superinstructions. Keep only measured winners.
- Apply PGO/LTO after instruction shape stabilizes.

Gate: native system-toplevel wall time at or below C++ Nix while preserving the
existing memory advantage. Package and compute suites must show no material
regression; JIT-hot shapes may continue to promote above bytecode.

### BC-5 - production rollout

- Make bytecode the native baseline; retain `AOS_NIX_BYTECODE=0` tree-walk
  escape hatch and sampled CHECK mode.
- Feed bytecode counters into tier promotion and compiled-body persistence.
- Update the RFC phase tables and default-on readiness packet with live-CI
  evidence.

Gate: bytecode parity and memory/performance checks required in CI, followed by
the existing staged native-default rollout.

## 6. Benchmark and memory protocol

Every performance commit uses the same Linux builder and an interleaved A/B
sequence against its immediate parent:

- cold-only `perf stat` for `systems.server.build.toplevel`, `pkgs.zlib`,
  `lambda-interp`, and `attr-fixpoint`;
- normal `nix-bench` parity runs for representative packages and compute shapes;
- full derivation or strict-JSON parity at semantic milestones;
- `bench.wide-eval` peak and retained RSS, plus arena peak and allocation counts;
- instruction count, cycles, IPC, wall time, function calls, forces, VM
  instructions, helper calls, declines, and maximum register/continuation depth.

A speedup that raises the established wide-eval memory ratio does not ship until
the retention is explained and removed. A noisy wall-clock result is decided by
retired instructions first and rerun under controlled load.

## 7. Relationship to the remaining RFC

Bytecode is not a substitute for unfinished committed phases. It supplies the
fast production floor that makes their economics honest:

- Cranelift tier 1/2 and LLVM AOT still promote hot bytecode entries;
- heap snapshots mmap bytecode plus position-independent prelude values;
- the concurrent collector scans VM registers using verified live-register maps;
- full-laziness, strictness, scalar replacement, and region inference reduce the
  bytecode emitted;
- persistent memoization bypasses bytecode entirely on valid hits;
- parallel evaluation schedules independent bytecode thunks without changing
  the VM's single-thunk semantics.

The implementation order after BC-3 returns to the phase checklist: finish the
general tier-2 deopt/OSR contract, LLVM AOT, concurrent moving GC, full region
inference, and the CI/default-on rollout. Performance work remains interleaved
where a phase exposes a measured regression or misses its stated target.
