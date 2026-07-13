# `cranelift.rs` §2-cap split — replayable plan (deferred)

Status: DEFERRED. The mechanical 6-way concern-split of `ratchet-jit/src/cranelift.rs`
(3387 lines) was implemented and reverted (tree clean) because it relocates ~11
reviewed `unsafe`/`transmute` boundaries out of `cranelift.rs`, which the
`safety.rs` review gate pins to that file by name. Per the lead, the safety.rs
re-home is a deliberate security-sensitive edit to be batched (with force.rs's
test-mod extraction) into one reviewed change, not a side effect of a mechanical
move. This note records the split shape so it is replayable once the safety gate
is re-homed.

## Split boundaries (verbatim moves, doc-comment-aware line ranges)

The split keeps the head (imports, existing `mod`/`pub use`, version pins) and the
`#[cfg(test)] mod tests;` tail in `cranelift.rs`, and moves six concern blocks into
`cranelift/` submodules. Each submodule gets a copied `use` block + `use super::*;`;
private items referenced cross-module bump to `pub(crate)`; `cranelift.rs` re-exports
`pub use <sub>::*;` (all six blocks contain ≥1 pub item). Cross-module struct-literal
fields and private `new`/methods bump to `pub(crate)` (E0451/E0624/E0616 fixes).

| submodule | 1-indexed line range | concern |
|---|---|---|
| (keep in `cranelift.rs`) | 1..158 | imports, `mod`/`pub use`, version pins, `JitCraneliftDependencyPin` |
| `preflight_a` | 159..1003 | symbol/function/stackmap/registered/definition/finalization/native-thunk/tier1-slot/tier1-promotion preflight types |
| `preflight_b` | 1004..1475 | promotion error + module-declaration/artifact-definition/module-setup preflights + native-call error + `JitCraneliftModuleSetupError` (all Display/Error/From impls) |
| `preflight_fns` | 1476..2025 | artifact declaration/definition/finalization preflight builders + `jit_cranelift_native_thunk_call_for_artifact` |
| `context` | 2026..2257 | `JitModuleContext` + `JitModuleContextInner` + `JitModuleContextFinalizedBody` + impls |
| `tier1` | 2258..2860 | tier-1 slot + promotion + force-aware preflight builders |
| `module_setup` | 2861..3385 | module setup, symbol declare/define, `compiled_user_stack_maps`, ISA construction |
| (keep in `cranelift.rs`) | 3386..end | `#[cfg(test)] mod tests;` |

Resulting sizes: cranelift.rs ~173, preflight_a 891, preflight_b 518, preflight_fns 596,
context 278, tier1 649, module_setup 571 — all under the 1000-line cap.

## The ~11 reviewed unsafe/transmute boundaries and their destinations

`safety.rs::current_jit_sources_keep_unsafe_boundaries_allowlisted` +
`assert_reviewed_unsafe_boundary_counts` currently gate these to `file_name ==
"cranelift.rs"`. After the split they live in:

- **`context`** — `jit_cranelift_call_context_finalized_thunk_entry` (dispatch
  entrypoint), its `let context_dispatched = unsafe { thunk_entry(rt, env) };`, and
  the `JitThunkFn` `mem::transmute` on the finalized code pointer.
- **`preflight_fns`** — `jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`
  (native thunk-call entrypoint), `jit_cranelift_call_finalized_thunk_entry`, and their
  `let value = unsafe { thunk_entry(...) };` / `let dispatched = unsafe { thunk_entry(rt, env) };`
  calls.
- **`tier1`** — `jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates`
  and `..._for_lowered_ir_root_with_candidates`, their
  `let promotion_gated_registered_native_thunk_invocation = unsafe {` calls (count 2),
  and the associated transmute.

Safety-gate edits required (the batched re-home): change the `file_name ==
Some("cranelift.rs")` guard in `is_allowed_native_thunk_call_token` to accept the three
destination files (`context.rs`, `preflight_fns.rs`, `tier1.rs`), and re-point each
`assert_reviewed_unsafe_boundary_counts` occurrence check from `cranelift.rs` to the
submodule file that now owns the line. The reviewed lines are byte-identical; this is a
1:1 re-pin, to be reviewed by the lead.
