# Simplifier default-on evidence packet (2026-07-14)

> Evidence packet for promoting the doc-26 simplifier pass set (task #7) from
> `AOS_NIX_SIMPLIFY` opt-in to default-on, gathered at branch head `388fcc57a`
> (the flag-segregation commit). **Ruling: HOLD** — the pass set is
> byte-parity-green everywhere but measures perf-neutral, so it stays opt-in
> until a pass with measured profit lands (§4). This note records the evidence
> and the exact flip recipe so the promotion, when ruled, is a mechanical
> commit. Companion: the
> [simplifier implementation plan](simplifier-implementation-plan.md) (§4
> staging, §8 decisions, §9 measured status).

Pass set under test (`REGISTERED_PASSES`,
`crates/ratchet-core/src/ir/simplify.rs`): `ConstFold`, `CaseOfKnown`,
`BetaReduceApply`, `InlineSingleUse`, `DeadBindingElim`, plus the
facts-refresh substrate (driver-refreshed facts persisted at the real
`IR_ANALYSIS_VERSION`). `PASS_SET_VERSION = 0`, flag keyed into the
parse-cache entry (`ParseCacheFlags::simplify`).

## 1. Byte-parity (the hard gate) — fully green

Builder `builder-hil1-87eb5b00`, clone `~/rfc0007-simplify` @ `388fcc57a`,
pinned oracle `nix-2.24.12` `nix-instantiate`, `AOS_NIX_NATIVE=1`,
`AOS_NIX_SIMPLIFY=1` throughout:

| Battery | Result |
|---------|--------|
| {`pkgs.zlib`, `pkgs.openssl`, `pkgs.bash`, `pkgs.coreutils`} x {serial `AOS_NIX_JIT=0`, JIT `AOS_NIX_JIT=1`} x {baseline carrier, `candidate_c_value` carrier} | **16/16 PASS** (byte mode) |
| Full corpus `aos nix-diff --all --mode byte`, JIT on, baseline carrier | **matched 546/546** |
| Full corpus `aos nix-diff --all --mode byte`, JIT on, `candidate_c_value` carrier | **matched 546/546** |

No pass produced a `.drv` divergence on any leg.

## 2. Local suites (darwin, both carriers, `AOS_NIX_SIMPLIFY=1`)

`ratchet-core` (385) and `aos-nix` `lang_conformance` (38) fully green on both
carriers. The flag-on-only failures are **14 tests, all triaged to
test-expectation collisions with the flag — no soundness bug**; the parity
matrix above is the semantic verdict. A flag-off control run reproduces none
of them.

### 2.1 Stat-expectation family (4 tests)

`aos-nix` `native::tests::expr_eval::{native_expression_eval_refreshes_parse_cache_analysis_facts, native_expression_eval_persists_refreshed_analysis_facts_without_source_path}`
and `ratchet-oracle` `eval::tree_walk::tests::parse::part_1::{ordinary_filesystem_import_refreshes_parse_cache_analysis_facts, ordinary_filesystem_import_persists_refreshed_analysis_facts}`
assert `stats.thunks_elided() > 0` on `(x: x + 1) (1 + 2)`. Under the flag the
redex reduces **statically** (beta -> single-use inline -> const-fold ->
dead-binding elision), so zero *runtime* elisions is the correct outcome — the
optimization the stat observes moved to compile time. Verified by dumping the
persisted IR: the `LocalVar` use is inlined to a `ThunkAlloc` of the same
value and the dead binding's value is elided to `Null`; values and captured
payloads (e.g. the search-path literal) are intact.

### 2.2 Facts-lifecycle family (10 tests)

`ratchet-oracle` `cache::parse::tests::{chunk_e::chunk_e_parse_entry_ignores_structurally_invalid_fact_sidecar, part_1::{load_cached_bytes_ignores_corrupt_fact_sidecars, write_resolved_commits_mandatory_artifacts_when_fact_sidecar_write_fails}, part_2::{cached_parse_ensure_facts_skips_reanalysis_on_version_current_sidecar, cached_parse_refresh_and_store_facts_updates_memory_and_sidecar, load_or_parse_analyzed_bytes_keeps_analysis_when_fact_storage_fails, load_or_parse_analyzed_bytes_refreshes_existing_cache_hits, lowered_ir_roundtrip_preserves_captured_search_path_literal, write_fact_sidecar_persists_refreshed_analysis_facts, write_fact_sidecar_rejects_ir_for_different_artifact}}`
assert the flag-off facts lifecycle: conservative in-memory facts after a
parse, `!facts_current`, "a refresh changes at least one fact", and
raw-`nix_lower` output == persisted `ir.bin`. Under the flag the persistence
seam runs the driver and persists refreshed facts at the real
`IR_ANALYSIS_VERSION` (the plan's §9 substrate working as designed), so each
assertion flips. These are behavior-contract updates for the flip commit, not
pass defects.

**Vacuous-vector finding.** Three of these
(`chunk_e_parse_entry_ignores_structurally_invalid_fact_sidecar`,
`load_cached_bytes_ignores_corrupt_fact_sidecars`,
`write_resolved_commits_mandatory_artifacts_when_fact_sidecar_write_fails`)
injected corruption via `entry.facts_path()` — a legacy per-file path the v12
single-bundle read path (`bundle.bin`,
`crates/ratchet-oracle/src/cache/parse/entry.rs` `decode_ir_with_facts`)
never consults — so they passed flag-off **vacuously**. Restored in the
follow-up commit to corrupt the bundle's facts section (the surface actually
read); the third is renamed
`read_ir_serves_mandatory_artifacts_despite_corrupt_bundle_fact_section`
because its pre-v12 vector (a blocked separate `facts.bin` write) is
unrepresentable under the atomic single-bundle commit. All three are now
flag-agnostic and out of the flip worklist, which drops to **11 tests**
(4 of §2.1 + the remaining 7 of §2.2).

### 2.3 Pre-existing, flag-independent (not simplifier findings)

- `aos-nix` `native::tests::fv6_payloads::native_expression_retains_only_thunk_state_sidecar_arcs`
  fails on darwin with the flag off too (both carriers) — I2 (`df0bf4b23`)
  collateral, owned separately.
- `no_source_file_exceeds_line_cap` — the held-for-fv5/snapshot oracle split
  debt (heap/arena, roots, parallel, ...).
- The two known parallelism-flaky memory tests behave as documented (pass
  isolated, flag-on).

## 3. Perf A/B — NEUTRAL

Same baseline-carrier release binary, `AOS_NIX_SIMPLIFY` off vs on,
interleaved rounds (3x for attrs, 2x for the compute micros), `--samples 3`,
temperatures read from nix-bench's per-temperature `benchmarks[]` records
(never `[0]`). Medians:

| Workload | cold off -> on (ratio) | warm off -> on (ratio) |
|----------|------------------------|------------------------|
| `pkgs.zlib` | 63.4 -> 63.6 ms (1.003x) | 62.3 -> 62.8 ms (1.007x) |
| `pkgs.openssl` | 65.8 -> 65.8 ms (1.000x) | 65.6 -> 65.4 ms (0.997x) |
| `systems.server.build.toplevel` | 3641 -> 3686 ms (1.012x) | 3620 -> 3587 ms (0.991x) |
| 9 `bench.compute` micros (fib, tak, sum-fold, qsort, string-builder, attr-fixpoint, lambda-interp, hash-loop, all-any) | 0.996x-1.021x | 0.997x-1.015x |

One noise outlier (string-builder cold 1.052x at n=2). Verdict: neutral
within noise everywhere — including cold parse/lower and the
post-beta-reduction pass set — consistent with the plan's §9 "measured
neutrality". The passes fire too rarely on real package graphs to move
end-to-end eval.

## 4. Ruling and flip recipe

**HOLD (ruled 2026-07-14): the pass set stays `AOS_NIX_SIMPLIFY`-gated.**
The correctness case is complete (16/16 + 546/546 x 2), but the perf case is
zero; flipping today buys nothing and costs a `PASS_SET_VERSION` bump
(universal parse-cache cold miss), a 14-test mode-aware update commit, and
default-on risk surface with no payoff. Measured-neutral => stay opt-in.

When a pass with measured profit lands, the flip is exactly:

1. `PASS_SET_VERSION` `0 -> 1` (`crates/ratchet-core/src/ir/simplify.rs`) —
   folds into the lowered-IR fingerprint domain, cleanly superseding all
   simplify-off artifacts.
2. Update the remaining 11 tests of §2.1/§2.2 to the flag-on contract
   (mode-aware or rewritten against the new lifecycle; never weakened).
3. Re-run this packet's batteries as the gate: local suites both carriers,
   16-leg parity matrix, full 546-corpus byte gate on both carriers.
