# Heap-image snapshot: production wiring spec (doc 31 §1 step 4)

**Status: SPEC, with a STOP-CONDITION FINDING. The storage tier, flag gate,
and capture seam are cleanly codeable today. The restore seam — the part that
banks the cold-start win — does NOT fit cleanly into the evaluator init path:
it is blocked on four evaluator-identity gaps enumerated below, the largest of
which is the cross-evaluator symbol re-intern workstream the step-3 spec
already recorded as a deliberate boundary. Per the lead's ruling ("stop and
report the shape rather than forcing it"), increments W3+ do not land until
W1/W2 are ruled and built.**

## Goal

The step-3 serializer proves capture→restore: the real forced stdenv prelude
captures zero-refused and re-derives its `.drv` byte-identical through a heap
swap **in the same evaluator**. The production prize is the cold-start
prelude-force wall (measured 39-85% of cold depending on corpus): a cold
evaluator should *restore* a persisted prelude image instead of re-forcing.

Wiring surface (the lead's step-4 scope):

1. image storage under `AOS_NIX_CACHE` (`snapshots/` tier);
2. capture seam: persist post-eval, off the hot path;
3. restore seam: at evaluator init, restore instead of re-forcing;
4. flag gate `AOS_NIX_SNAPSHOT=1`, default OFF (the doc-14 opt-in pattern);
5. paired cold A/B measurement + byte-parity battery with the flag ON.

## The stop-condition finding: what a fresh evaluator does not share

Step 3's acceptance restores into the *same* `TreeWalk` that captured (heap
swapped under it). A production restore target is a **fresh evaluator in a
fresh process**, and four pieces of identity the restored values depend on are
per-evaluator state, not heap state:

1. **Module table.** `TreeWalk.modules` starts with only the root expression's
   module. Every closure code ref then fails fingerprint resolution and
   restore refuses with `ClosureCodeDrift` — safe, loud, and total. Restore
   must first *reload* the captured modules (parse/lower each manifest entry,
   parse-cache-backed) so the resolver can re-link fingerprints to live ids.
2. **Symbol table.** `TreeWalk.symbols = ir.symbols.clone()`
   (`eval_core.rs`): interning history is per-evaluator and depends on the
   root expression, so a fresh evaluator assigns different ids to the same
   names. Raw symbol ids ride in attrs entry keys (arena-inline and
   owned-attrs segments), primop payload symbols, and builtin-attr thunk
   symbols. Restoring them un-rewritten **silently rebinds attribute names** —
   the exact hazard the step-3 spec's cross-process section documented and
   deferred. This is the prerequisite workstream, not an integration detail.
3. **Import cache.** `TreeWalk.import_cache` maps import paths to evaluated
   values. Even with a perfectly restored heap, a fresh eval of
   `import ./lib` re-forces from scratch unless the restore seam seeds the
   import cache with the captured prelude entry values. The image must
   therefore carry `(import path identity, root value word)` seeds.
4. **Shape table.** The default `AttrShapeMode::Transient` gives every
   evaluator a live `ShapeTable`, and heap attrs metadata carries projected
   `ShapeId`s. Shape ids are assigned per-evaluator by transition-tree walk
   order, so restored metadata ids are foreign in a fresh table: shaped select
   paths would resolve against the wrong (or absent) shapes. Options: a
   serialized shape-log replica adoption (the parallel-mode prefix-replica
   mechanism is precedent), a shape-id rewrite pass alongside symbols, or
   restoring with shape projection off for restored objects (metadata reset to
   unshaped, falling back to flat selects — semantically safe, costs the
   shaped-select optimization on restored attrs).

Gap 1 fails loud today (the drift-refusal tests prove it). Gaps 2 and 4 fail
*silently* if forced — which is why the seam is not forced.

## Increment map

1. **W1 — symbol identity across evaluators.** *(LANDED 0be22f15d; the
   unsafe call site and the position ruling below are lead-approved.)* Serialize the capture-time
   symbol table (names in id order; a `symbols` segment or manifest field).
   Restore builds `old id -> new id` by interning each name into the fresh
   table, then rewrites every symbol-carrying location: arena-inline attrs
   entry keys (a keys-variant of the reviewed
   `FlatAttrs::rewrite_entry_values` door — same exclusivity contract, same
   pin-map treatment), owned-attrs segment keys (plain data, rewritten at
   decode), primop payload symbols, and builtin-attr thunk symbols (rewritten
   at decode). Lexicographic iteration permutations are byte-order over
   *names* and names are unchanged, so permutations survive; entry arrays are
   sorted by symbol *id*, so rewritten entries must be re-sorted and the
   inverse source permutation recomputed at decode (bounded, restore-only
   cost). Acceptance: capture in evaluator A, restore into a fresh evaluator
   B with a different root expression; attribute selection and `attrNames`
   over the restored prelude are byte-identical to B's cold eval.
   **Position degradation (v1, lead-accepted with a condition):** an attr
   position whose module has no counterpart in the consuming evaluator
   degrades to *no position* instead of refusing (provenance of a module
   that no longer exists); keys and primop-arg provenance refuse hard.
   Positions are observable through `unsafeGetAttrPos`, so the W2/W5 parity
   battery MUST include a position-observability probe: over the restored
   prelude, no *reachable* attr entry may carry a degraded position —
   degradation must stay confined to warmer-internal attrs user evals never
   read. A reachable degraded position is a stop-and-revisit (candidate
   fixes: manifest-pin the warmer root as a real module, or capture-time
   refusal keyed on position-module escape into user-reachable attrs).
2. **W2 — module manifest + import seeding.** The snapshot file wraps the
   heap image with a manifest: `(source name, path, fingerprint)` per
   captured module (capture-time `snapshot_code_identity` already holds the
   fingerprints) and `(import path identity, root value word)` per prelude
   import entry. Restore-at-init parses/lowers each manifest module
   (parse-cache-backed — this is the S0-optimized share, not the force wall),
   builds the resolver from the *fresh* module table, restores the heap, and
   seeds the import cache. Shape metadata: v1 restores with the safe fallback
   (unshaped metadata reset) unless the shape-log adoption is ruled in.
3. **W3 — storage tier + flag + capture seam.** `AOS_NIX_CACHE`-rooted
   `snapshots/v<IMAGE_VERSION>/<key>.aosimg`, keyed by
   `(prelude entry fingerprint domain, eval-system, carrier)`; the key only
   *locates* a candidate — staleness is enforced by refuse-on-drift at
   restore, never by trusting the key. Capture runs post-eval (write-behind
   worker or post-outcome hook — never the hot path) in a dedicated
   prelude-warmer flow first (the probe flow productized: force prelude,
   collapse, capture), gated by `AOS_NIX_SNAPSHOT=1` (default OFF).
4. **W4 — restore seam at init.** Flag-gated: locate candidate image, run W2
   restore; any refusal (drift, malformed, version) falls back to the normal
   cold path with a counter, never an error. Byte-parity battery runs with
   the flag ON both legs.
5. **W5 — the measurement.** Paired cold A/B (flag off vs on, warm image) on
   `systems.server.build.toplevel` and a package attr; report honest numbers
   either way against the 39-85% prelude-force share. This is the ROI gate
   for keeping the tier.

## W5 verdict (2026-07-14, release build, warm parse cache, tree-walk path)

Paired adopted-vs-cold decomposition (darwin, candidate-c, n=4 stable
samples per target, byte-parity asserted every sample; probes in
`heap_snapshot/production.rs`):

| target | adopt | adopted eval | cold eval | eval delta | net |
|---|---:|---:|---:|---:|---:|
| `stdenv.stdenv.drvPath` (the warmer's own attr) | 26ms | 74ms | 96ms | -23% | ~+4ms |
| `pkgs.coreutils.drvPath` | 25ms | 95ms | 117ms | -19% | ~+3ms |
| `pkgs.systemd.drvPath` | 25ms | 167ms | 184ms | -9% | ~+8ms |
| pure `deepSeq lib` | 25ms | 5.6ms | 7.6ms | -26% | ~+23ms |

Adopt decomposition: manifest module reload 19.7ms (76%; 466 modules at
parse-cache-hit cost), identity snapshot 1.2ms, image restore + re-intern
3.8ms (the 5.3MB heap machinery itself is fast), seeds ~1ms.

**Verdict: the tier stays default-OFF.** The eval-side win is real and
consistent — a ~20ms absolute reduction, which is the lib/stdenv
*file-forcing* share left after the parse cache — but two structural facts
cancel it: (1) the `import root { system }` **application re-runs** in every
consumer (the import cache seeds files, not applications), so the pkgs
fixpoint and derivation hashing dominate adopted evals exactly as they
dominate cold ones; (2) the ~25ms adopt cost (dominated by the eager
466-module reload) equals or exceeds the banked delta on every target. The
S0-era 39-85% prelude-force share has largely been eaten by the parse cache
and the earlier cold-eval campaign — the snapshot's addressable remainder
measured 9-26% of eval, ~20ms absolute.

**Recorded follow-on** (lead-directed citation): value-level seeding at the
*applied-pkgs boundary* through the existing MEMO-2/L2 memo layer (doc 29 —
the persist/memo machinery already keys forced expressions durably) is the
lever that addresses the fixpoint re-run ceiling; the snapshot tier's heap
image and identity re-interning remain the substrate any such value-level
restore would ride.

**Measurement exclusion, pre-existing bug found:**
`systems.server.build.toplevel` could not be measured — its evaluation trips
`flat_capture.rs:121` (`debug_assert!(replaced, "unique pending closure
must remain replaceable")`: a pending flat-capture publication meets an
already-`Arc`-shared thunk) on a COLD debug-build eval, reproduced at
pre-campaign commit 388fcc57a. Module-system evaluation sits outside the
546-package parity corpus. Release builds compile the assert out, so a
pending capture may silently publish nothing — this needs its own
investigation, independent of the snapshot campaign.

## Non-goals (recorded)

- Restoring arbitrary (non-prelude) heaps across evaluators.
- Trusting the storage key for validity: refuse-on-drift stays the only
  staleness authority.
- Cross-machine image portability beyond what W1's re-intern already grants
  (endianness/layout are pinned by the wire format; carrier is in the key).
