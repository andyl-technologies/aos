# Internalized fold loop (loop-in-CLIF) — SHELVED (measured economics)

Status: **SHELVED.** #32's remaining core was moving the fold iteration loop into
the emitted CLIF function (one FFI entry per fold instead of one per element).
Measurement shows the win is ~1.5-3x on fold-bound microbenches — NOT the task's
10-100x — because the native fold loop already banked the boundary win; and there
is no fold-bound real workload demanding it, against a safepoint-inside-loop
safety surface and a new reviewed FFI boundary. Both increments below are shelved.
Kept as the evidence that stops a re-proposal from the stale 10-100x framing.

The 10-100x framing was an extrapolation from the 1113 ns/element figure, which
this measurement shows was the **apply-seam per-dispatch cost the native fold loop
already eliminated** (it pins the context/trap scope once and does bare per-element
calls). Per-element cost today is ~6.6 ns, not 1113 ns.

## Premise correction (measured)

The task description cites "boundary overhead ~99% of per-element wall time,
baseline 1113 ns/element vs ~5 ns arithmetic, 1.5M crossings → 10-100x absolute."
That 1113 ns/element is the **apply-seam per-dispatch cost** (context pin + trap
scope + environment clone, ~1 µs — see `tier2_fold.rs` module docs), which the
**native fold loop already eliminates**: it pins the context and trap scope ONCE
per fold and pays only a bare native call + a thread-local trap probe per element.

Measured per-element marginal cost of the current native i64-acc fold loop
(genList fold, `AOS_NIX_JIT=1`, variant release, warm):

| elements | warm mean | 
|---|---|
| 1,000,000 | 6.93 ms |
| 4,000,000 | 26.85 ms |

Slope = (26.85 − 6.93) ms / 3.0M = **~6.6 ns/element** (linear ⇒ folding
natively, no deopt tail). So per element today ≈ ~6.6 ns, of which the arithmetic
+ generator body is roughly half and the **boundary residual** (Rust per-call
dispatch: `require_supported_native_value_abi` + artifact-kind match + transmute;
the native call prologue/epilogue; the trap probe) is the other ~2-3 ns.

**Therefore the internalized loop is a ~1.5-1.7x fold lever, not 10-100x.** The
big boundary win the task imagined was already banked by the native fold loop.

## Options ladder

**Increment 0 (hoist per-element checks) — also marginal, shelved.** The idea:
do `require_supported_native_value_abi` + artifact-kind validation + the
code-pointer transmute ONCE before the loop; call the raw `JitFoldStepI64AccFn`
per element. But the hoistable work is ~1 ns/element:
`require_supported_native_value_abi` is a compile-time `cfg!(...)` constant (folds
to zero instructions on a supported host) and the kind check is one enum compare.
And it is NOT free on the safety surface: the reviewed native CALL currently lives
in `ratchet-jit` (`jit_cranelift_call_context_finalized_fold_step_i64acc_entry` →
`unsafe { fold_step_entry(...) }`), so hoisting relocates the per-element call
across the crate boundary into `native_call.rs`, which re-pins boundaries in BOTH
the ratchet-jit and ratchet-runtime-ffi safety allowlists (not a within-file
transmute move). ~1.1x for a two-allowlist security-sensitive edit is a poor
trade; shelved with Increment 1.

**Increment 1 (complex, ~2-3 ns/element more):** full loop-in-CLIF. New entry
`fold_loop_i64acc(rt, env, seed: i64, start/elems_ptr, count) -> (acc: i64,
consumed: i64)` that iterates internally. Removes the per-element native
call + trap probe entirely. Subtleties:
- **Per-element force in CLIF.** genList inline-int elements need no force (fast
  path is a WHNF check); a materialized-list (Slice) element that is a thunk needs
  an `aos_force` call INSIDE the loop body, bracketed by stack-map enter/exit —
  the loop-carried `(acc, index)` must be in the stack map at that safepoint so a
  GC during the force sees them. This is the hard part.
- **Deopt-branch in CLIF.** A `to_int` guard failure (wide/non-integer element) or
  an operator deopt must BREAK the loop, exiting with `(current_acc,
  consumed = current_index)` — the same contract as the current Rust fallback, so
  the interpreted resume from element `consumed` stays oracle-identical. The loop's
  deopt block records the trap (`aos_deopt`) and jumps to a loop-exit block that
  returns `(acc, index)`.
- **Two-value return.** Cranelift returns `(i64, i64)`; the Rust caller re-encodes
  `acc` once and resumes interpreted at `consumed` if `consumed < count`.
- **Reuses** the FoldStep inner body (emitted as the loop body over the counter),
  the i64-acc register thread, and the FoldI64Acc/FoldGenI64Acc cache roles.
- **One new reviewed safety boundary** (the `fold_loop_i64acc` entry transmute +
  call) via the helper-addition process, same shape as the fold-step entry.

## Recommendation — both shelved

Increment 0 buys ~1.1x (the hoistable checks are compile-time-cheap) for a
two-allowlist security-sensitive edit. Increment 1 (loop-in-CLIF) buys ~1.5-3x on
fold-bound microbenches for meaningful emitter complexity plus a new
safepoint-in-loop safety surface and a new reviewed FFI boundary. The
C++-relative compute targets are already far exceeded (fib ~34x the oracle) and
neither is a promotion blocker, so both are shelved. Re-open only if a concrete
fold-bound real workload demands the absolute per-element cost — the acc-i64
increment (landed) is the final state of the fold seam for now.
