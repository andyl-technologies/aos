# `cranelift.rs` §2-cap split — LANDED

Status: LANDED (batched with the `safety.rs` re-home). The 3389-line
`ratchet-jit/src/cranelift.rs` is split into six concern submodules under
`cranelift/`, each under the §2 1000-line cap. The safety-gate re-home (which
pins the reviewed `unsafe`/`transmute` boundaries by filename) was done in the
same commit as a deliberate, reviewed security-sensitive change.

## Split shape (contiguous verbatim line-range moves)

`cranelift.rs` keeps the head (imports, `mod`/`pub use`, version pins,
`JitCraneliftDependencyPin`) and the `#[cfg(test)] mod tests;` tail, and
re-exports `pub use <sub>::*;` for all six submodules (external API unchanged).
Each submodule starts with `//! <concern>` + `use super::*;`.

| submodule | 1-indexed source range | lines | concern |
|---|---|---|---|
| (keep in `cranelift.rs`) | 1..159 | — | imports, `mod`/`pub use`, version pins, `JitCraneliftDependencyPin` |
| `preflight_a` | 160..1004 | 845 | imported/defined symbol + stack-map + registered-symbol + artifact-definition/finalization/native-thunk/tier-1 slot/promotion preflight records |
| `preflight_b` | 1005..1476 | 472 | promotion error, module-declaration/artifact-definition preflights, module-setup + native-call error, and their `Display`/`Error`/`From` impls |
| `preflight_fns` | 1477..2026 | 550 | artifact declaration/definition/finalization preflight builders + the no-import / registered native thunk-call entrypoints |
| `context` | 2027..2258 | 232 | `JitModuleContext` + `JitModuleContextInner` + `JitModuleContextFinalizedBody` + impls + the context-finalized thunk-entry dispatch |
| `tier1` | 2259..2861 | 603 | tier-1 slot + promotion preflight builders, the `JitThunkFn` transmute helper, and the force-aware registered native thunk-call preflights |
| `module_setup` | 2862..3387 | 526 | module setup, symbol declare/define, ISA construction, reachable stack-map assembly |
| (keep in `cranelift.rs`) | 3388..3389 | — | `#[cfg(test)] mod tests;` |

Visibility fixes (E0451/E0624/E0616/E0603): `pub(super)`→`pub(crate)` in the
submodules; cross-referenced private free functions, `new` associated functions,
and struct-literal fields bumped to `pub(crate)`; `JitModuleContextInner` bumped
to `pub(crate)` (exposed through a `pub(crate)` field). No reviewed line changed.

## Reviewed-boundary re-home — ACTUAL per-file pin map (both safety scans)

The contiguous split places each reviewed boundary in the submodule whose range
covers it (not the pre-split doc's approximate map — e.g. the `JitThunkFn`
transmute helper sits after the `context` block and lands in `tier1`). Every
reviewed line is byte-identical; the total pin count is preserved.

- **`context.rs`** (2 pins): `jit_cranelift_call_context_finalized_thunk_entry`
  entrypoint; `let context_dispatched = unsafe { thunk_entry(rt, env) };`.
- **`preflight_fns.rs`** (5 pins):
  `jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates` and
  `jit_cranelift_call_finalized_thunk_entry` entrypoints;
  `let value = unsafe { thunk_entry(ptr::null_mut(), ptr::null_mut()) };`;
  `let value = unsafe { thunk_entry(rt, env) };`;
  `let dispatched = unsafe { thunk_entry(rt, env) };`.
- **`tier1.rs`** (5 pins, one with count 2):
  `jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates`
  and `..._for_lowered_ir_root_with_candidates` entrypoints;
  `let promotion_gated_registered_native_thunk_invocation = unsafe {` (×2);
  `let entry = unsafe { mem::transmute::<*mut u8, JitThunkFn>(code_ptr.as_ptr()) };`.

`safety.rs` changes: `is_allowed_native_thunk_call_token` gains three
file-specific blocks (`context.rs`/`preflight_fns.rs`/`tier1.rs`) mirroring the
`candidate_b.rs`/`candidate_c.rs` pattern, each allowing only its own boundaries;
`assert_reviewed_unsafe_boundary_counts` re-points each occurrence check from
`cranelift.rs` to the owning submodule. All three destination basenames are
unique in `ratchet-jit/src`, so basename matching (the existing convention) is
unambiguous.
