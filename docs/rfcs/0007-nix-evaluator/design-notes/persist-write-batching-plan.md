# Persist-write batching campaign — design (design-only)

Owner: fv5. Status: DESIGN-ONLY (both code lanes occupied; implementation
when a lane frees). Born from the task-#14 write-amplification finding:
cache-enabled cold eval is **6.2-7.7x slower** than cache-less cold on leaf
packages, and the buggy default-config run measured `bench.compute.tak` cold at
**158 s vs ~17 ms cache-less** (~10M forces => ~15 µs/force of cache overhead).

This note maps the durable write path with verified `file:line` evidence,
reframes the finding based on that code (see the headline below), designs the
batching/deferral campaign, states the target and the exact A/B harness, and
orders the landing. It **gates the default-cache-root product decision**: we
cannot make `native_cache_root` on by default until cache-enabled cold is within
~1.2x of cache-less cold.

---

## 0. Headline finding (a reframing the code forces)

The name "persist-**write** batching" assumes the ~15 µs/force is durable disk
writes. **The code says that is not what a cache-*cold* eval pays.** Durable
writes are gated behind a cross-run demand cost model:

- `crates/ratchet-oracle/src/cache/persist/cache/node_demand.rs:41-42`:
  > "…current payloads are **kept in memory until a previous run has demanded
  > the same node** and the caller-supplied cost model says writing is
  > profitable."
- Decision site: `crates/ratchet-oracle/src/eval/tree_walk/eval_core/force_persistence.rs:240`
  (`node_materialization_signals`) → `:252` (`signals.decide()`) → `:254`
  (`if decision == KeepInMemory { return None; }`).

On a fresh empty cache (exactly what the v4 cache-enabled cycle produces —
a fresh temp dir per cold sample), **no node has prior-run demand, so the
decision is `KeepInMemory` and the pack/trace/metadata writes below never
fire.** Therefore the measured cold slowdown is almost certainly **not** disk
writes. By inspection it is the per-force **eval-cache OBSERVE tax**, paid
unconditionally on every force whenever `set_eval_cache_enabled(true)` (which
`set_native_cache_root` turns on):

1. `force_persistence.rs:55` — `force_cache_payload_for_value(value)` builds a
   `CachedExpressionValue` for the forced value: a **recursive heap walk +
   custom-codec encode + BLAKE3 hash**, per force
   (`eval/tree_walk/eval_core/force_payload.rs:6`). This is built **before** the
   materialization decision at `:240`, so we pay encode+hash for every force and
   then usually throw the payload away (`KeepInMemory`).
2. `force_persistence.rs:74` — `prepare_observable_payload_for_subject`
   (position remap), per force.
3. `force_persistence.rs:85` — `self.eval_cache.lock()` (a `Mutex`, per force).
4. `force_persistence.rs:96`/`:108` — `observe_inline_expression_payload[_with_impure_inputs]`
   → in-memory demand-graph (DCG) node insert/reconsider
   (`cache/runtime/eval_cache.rs:667`/`:763`).

For tak's ~10M forces, ~15 µs/force of "encode + hash + remap + lock + DCG
insert" is a plausible ~150 s. **So the campaign's true target is the per-force
eval-cache observe cost on cache-enabled evals, with durable-write batching a
secondary lever for the warm/materializing runs.** The Explore pass could not
run a profiler to confirm which term dominates, so **increment 0 is a
disambiguating measurement** (§4.0). The rest of the design covers both the
observe tax (primary hypothesis) and the write path (secondary), because if
increment-0 shows materialization *is* firing on our runs, the per-record write
path in §1 is the culprit and its batching design in §3 applies directly.

---

## 1. Write-path anatomy (file:line)

### 1.1 Two cache layers

Per-force entry: `observe_forced_inline_expression_result_with_eval_work_units`
(`force_persistence.rs:44`), called from the tree-walk force sites
`eval_primop_apply.rs:562`, `eval_import_root_cache.rs:93`,
`alloc_intern.rs:1956`.

- **In-memory eval-cache / DCG** — `self.eval_cache` (`Mutex`), delegating to
  `EvalCacheRuntime` operating on an in-memory demand graph
  (`cache/runtime/eval_cache_runtime.rs:575`). No disk.
- **L0/L1 content memo** — `eval_core/memo.rs:781-802`, `Arc`-wrapped entries in
  `memo_l0` + a `SharedMemoTable`. **In-memory only; never writes disk.**
- **Persistent cache (`PersistCache`)** — `self.persist_cache`, opened lazily
  (`force_persistence.rs:1136`). The only disk tier, gated by §0's cost model.

### 1.2 The durable write path (fires only when the cost model says `Materialize`)

Per admitted+materialized record, `materialize_cached_expression_node_value_indexed`
(`cache/persist/cache/indexed_values.rs:391`) touches **~4 files, each opened
and appended individually — per-record, not batched**:

1. value pack — `indexed_values.rs:403` encode (`value.encode_persistent_payload()`)
   → `:407` `materialize_blob_indexed`; append bottoms out in
   `crates/ratchet-cache/src/blob_pack/appender.rs:84` `append_payload`:
   - `appender.rs:103-106` — `OpenOptions::new().read(true).append(true).open()`
     (one open per append; `ensure_blob_pack_file` at `:89` opens+locks+stats
     *again* just before).
   - `appender.rs:111` — `lock_blob_pack_file(Exclusive)` (an OS flock per append).
   - `appender.rs:128-130` — `write_all(header) ; write_all(payload) ; flush()`.
     **Buffered append, no `fsync`/`sync_all`** — the appender doc says so
     (`appender.rs:18-19`). The only production `sync_all` is the
     compaction atomic-replace at `ratchet-cache/src/store.rs:181`, off the
     per-force path.
2. blob-index sidecar — `ratchet-cache/src/blob_index.rs:224-234`
   (`append`/`write_all`/`flush`, no fsync). Content-dedup checked before append
   (`indexed_values.rs:216-232`).
3. node-metadata sidecar — `ratchet-cache/src/node_metadata.rs:216-231`
   (opens the file **twice**, append, no fsync).
4. node-trace log — `force_persistence.rs:566` `record_node_trace` →
   `cache/persist/cache/node_io.rs:75/83`.

**Serialization:** custom length-prefixed codec (not bincode/narinfo),
`cache/runtime/inline_value_payload.rs:396/921-935`; the encoded bytes are the
BLAKE3 preimage of the value hash (`cache/runtime/expression_value.rs:356-362`),
i.e. content-addressed. `value_hash()` is O(1) (precomputed, `expression_value.rs:336-340`).

**Locking:** every persist write takes **both** an OS advisory flock **and** an
in-process `Mutex` (`cache/persist/cache/store_io.rs:137-150`, `:25-38`,
`:381-389`, `:401-409`), on top of the appender's own flock (`appender.rs:111`).
Several flock round-trips + several `Mutex` per materialized record.

### 1.3 Root-cutoff records — one write per instantiate root, at end-of-eval

`crates/aos-nix/src/native/mod.rs:591` `store_root_cutoff(...)` runs after the
whole closure evaluates (`native/mod.rs:588`), via
`native/root_cutoff.rs:384` → `:408` `store_root_instantiation(...)`. Key is a
single BLAKE3 over (salt, versions, entry-file real-path+content, attr, options
fingerprint) — `root_cutoff.rs:64-80`. **One write per `instantiate(file,attr)`.**
Cheap; the design keeps it synchronous.

---

## 2. Where the ~15 µs/force goes (code reading; profile pending)

On a genuinely cache-**cold** populate run (our measurement), descending by
likely cost:

1. **Per-force payload encode + BLAKE3** (`force_payload.rs:6`, called at
   `force_persistence.rs:55`) — CPU, unconditional, **thrown away** when the
   node is `KeepInMemory`. Prime suspect.
2. **Per-force Mutex + in-memory DCG observe** (`force_persistence.rs:85`,
   `:96`/`:108`).
3. **One `fs::metadata` stat per reconsidered node** (`node_materialization_signals`
   → `lookup_node_metadata` → `node_metadata.rs:280-300`) — the one unconditional
   disk *touch*, but a cheap stat with no open.
4. Position remap (`force_persistence.rs:74`, `:222`).

So on cold: **CPU (encode/hash) + in-memory DCG under a Mutex + one stat/node,
not write syscalls, not fsync (there is none), not durable serialization.** The
per-record `open+flock+write × ~4 files` only dominates on **warm/materializing**
runs. Category when writes *do* fire: **syscall-dominated** (many open/flock/write
per record, no fsync) + per-record custom-codec encode + BLAKE3.

---

## 3. The batching / deferral design

Two levers, matching the two cost regimes.

### 3.1 Primary lever — defer the per-force payload build (the observe tax)

The payload (`force_cache_payload_for_value`, encode+BLAKE3) is built at
`force_persistence.rs:55` **before** the `KeepInMemory` decision at `:240-254`,
then discarded for most nodes. Make it **lazy**: compute a cheap node identity
first, take the materialization decision, and only run the full encode+hash when
the node will be materialized **or** when the DCG observe genuinely needs the
content hash for change detection.

- Design question to resolve in the spike: does the in-memory DCG observe
  (`eval_cache.rs:667/763`) require the full content hash, or can it key on a
  cheaper identity (heap address / precomputed value_hash which is already O(1)
  at `expression_value.rs:336-340`)? If `value_hash()` is O(1) and sufficient
  for DCG change-detection, the recursive *encode* (the expensive part) can be
  deferred to materialization time entirely.
- If the DCG needs the encoded payload, cache it lazily keyed by value identity
  so repeated forces of the same canonical value (very common — shared lib
  scaffolding) encode once.

This is the lever that plausibly moves cold from 6-8x toward ~1.2x, because it
removes work paid on **every** force regardless of disk.

### 3.2 Secondary lever — write-behind buffer for the durable path

For warm/materializing runs, replace the per-record inline
`open+flock+write × ~4 files` with a **write-behind buffer** flushed at the run
boundary:

- Buffer payloads/traces/metadata in memory keyed by their content/node keys;
  coalesce duplicates (last-wins for node metadata/traces).
- Flush once at `advance_persist_eval_cache_run_boundary`
  (`force_persistence.rs:1101`) — the existing end-of-run hook that already
  flushes the buffered *demand* map (`force_persistence.rs:1078` →
  `run_scope.rs:112 flush_buffered_node_demands`). This is the natural seam;
  no `Drop`-based flush exists today, so flushing stays explicit at this hook.
- One flush amortizes the flock/open cost across all records (open each pack/
  sidecar once, append the whole batch, one flush) instead of per record.

**Thresholds and the memory ceiling (hard constraint from the 0.5x-of-C++ RSS
goal).** The write-behind buffer holds records in memory until flush, so it adds
directly to peak RSS — and the memory target is **≤38 MiB wide-eval RSS (half of
C++'s ~77 MiB)**. A batching design that trades latency for a fat buffer would
fight that goal. Therefore:

- **Buffer cap: single-digit MiB (target 4 MiB, hard ceiling 8 MiB) OR a few
  thousand records, whichever first.** Flush mid-eval when the cap is hit, and
  always at the run boundary. This keeps the buffer a rounding error against the
  38 MiB budget while still amortizing the open/flock cost across a large batch.
- The buffer only exists on **materializing (warm-populate)** runs; on the cold
  run that the memory target is measured against, the cost model keeps nodes in
  memory and nothing is buffered for write, so the buffer adds **zero** to the
  headline cold RSS number.
- Note the interaction with the primary lever (§3.1): deferring the per-force
  payload build is **memory-positive** too — today `force_cache_payload_for_value`
  allocates an encoded payload for every force and discards most of them
  (`force_persistence.rs:55` before the `KeepInMemory` decision), which is
  transient allocation churn the 38 MiB goal wants gone. So §3.1 helps both axes;
  §3.2's buffer must be capped so it does not give the memory back.
- Latency is irrelevant for a batch benchmark tool; for a long-lived daemon a
  periodic flush timer can bound staleness.

**Content-addressing makes the buffer safe against duplicates**: value payloads
are keyed by `PersistBlobKey::for_value(value_hash)` whose bytes are the BLAKE3
preimage (`expression_value.rs:356-362`), and `ensure_blob_indexed` already
dedups by content hash before append (`indexed_values.rs:216-232`). Node
metadata/traces are append-only logs with newest-record-wins semantics
(`node_io.rs:63`), so a `(node_key)`-keyed buffer writing the last record at
flush matches the on-disk contract.

### 3.3 Crash semantics — argue the cache is advisory

A deferred/lost batch is **always safe**:

- The persist cache is a **memo of a pure computation**: any record it would
  have written is reproducible by re-evaluating. A lost write-behind batch (crash
  before flush) means the next run re-derives those values — a re-eval, never
  corruption or a wrong answer. The parity contract is unaffected: `.drv` bytes
  come from the eval, not the cache.
- There is already **no `fsync` on the per-record path** (§1.2), so the current
  code makes no crash-durability promise about individual writes — batching does
  not weaken an existing guarantee; it makes explicit what is already true.
- Append-only logs with newest-wins and content-addressed value packs mean a
  torn/partial flushed record is detectable and discardable (the reader already
  tolerates this on the append logs); the buffer should flush whole records and
  can write a batch to a temp file + atomic-rename (the `store.rs:181`
  `sync_all`+rename pattern) if we want per-batch atomicity.

### 3.4 What MUST stay synchronous

- **The just-finished-root cutoff record** (`native/mod.rs:591`,
  `root_cutoff.rs:408`): it is one write per `instantiate` at end-of-eval, and it
  is the record that makes the *next* warm run's root-cutoff hit fast. It is
  already at the outermost completion point; write it synchronously (after
  flushing the write-behind buffer, so the cutoff record never references
  unflushed payloads). Keeping it sync costs one write per root — negligible.

---

## 4. Measurement harness (the v4 cache-enabled companion IS the A/B)

### 4.0 Increment 0 — disambiguate observe-tax vs write-tax (do this FIRST)

Confirm §0's hypothesis before building anything. On a quiet machine, profile a
cache-enabled **cold** `bench.compute.tak` and attribute the time:

```text
# Build the release binary (mimalloc default), then:
env AOS_NIX_ORACLE=/nix/var/nix/profiles/default/bin/nix-instantiate \
    AOS_NIX_NATIVE=1 AOS_NIX_JIT=1 AOS_NIX_CACHE="$(mktemp -d)" \
    crates/target/release/aos --eval-system x86_64-linux nix-bench \
    --file ./default.nix -A bench.compute.tak --samples 1 --no-record
```
Profile it (samply/Instruments/perf) and read the on-CPU split: if
`force_cache_payload_for_value` / `observe_inline_expression_payload` dominate
=> observe tax (build §3.1 first). If `append_payload` / `write_all` / flock
dominate => materialization IS firing on cold => build §3.2 first and file a
separate "cost model admits on first demand" bug.

### 4.1 The A/B for every increment

The task-#14 cache-enabled companion is exactly the A/B. Two legs, interleaved
A,B,A,B per the measure-first discipline (judge native median, not the
oracle-noisy ratio):

- Cache-enabled cold/warm (the subject):
```text
env AOS_NIX_ORACLE=.../nix-instantiate AOS_NIX_NATIVE=1 AOS_NIX_JIT=1 \
    AOS_NIX_CACHE="$(mktemp -d)" \
    crates/target/release/aos --eval-system x86_64-linux nix-bench \
    --file ./default.nix -A pkgs.zlib -A pkgs.openssl -A pkgs.curl -A pkgs.git \
    -A bench.compute.tak -A bench.compute.sum-fold --samples 3 --no-record
```
- Cache-less baseline (the target floor): same command **without** `AOS_NIX_CACHE`.

Read `native_summary.median_seconds` per `(attr,temperature)` from `--json`;
compare cache-enabled cold to cache-less cold (the 6-8x that must shrink), and
confirm cache-enabled warm stays 23-35 ms (the cutoff-answered repeat must not
regress). Parity must stay byte-green in both legs.

---

## 5. Target (both axes)

The user's program-level targets are **10x C++ performance** (v4 honest cold
baseline is 0.515x native/oracle geomean = ~1.9x; 10x = a 0.1x geomean) and
**half of C++'s RSS** (wide-eval ≤38 MiB vs C++'s ~77; today's native is
140-190 MiB — task #15 owns the memory ladder). This campaign's local targets
must not fight either:

- **Latency:** cache-enabled cold within **~1.2x of cache-less cold** (from
  6.2-7.7x today on leaf packages; from the ~150s tak pathology to a small
  multiple of ~17 ms). This removes the cache from *blocking* the default-on
  decision; the cold-latency scoreboard number (§5.1) is what the 10x goal is
  measured against, cache on or off.
- **Memory:** the write-behind buffer is capped at ≤8 MiB (§3.2) so it never
  eats into the ≤38 MiB wide-eval RSS budget; the lazy-payload lever (§3.1) is
  net memory-*positive*. No landing here may move the wide-eval RSS scoreboard
  number (§5.1) up.
- **Preserve cache-enabled warm at 23-35 ms** (the root-cutoff-answered repeat).
- **Byte-parity green** throughout (representation/schedule-internal only).

### 5.1 Canonical target measurements — the 0.5x/10x scoreboard

The two canonical scoreboard numbers (`cold_geomean` for the 10x-perf goal,
`wide_mem_ratio` for the 0.5x-memory goal) now live in
[doc 15 §5.4](../docs/rfcs/0007-nix-evaluator/15-differential-testing-and-benchmarking.md)
as the standalone canonical definition every RFC-0007 campaign cites. This
campaign additionally reports one **local** number in its scoreboard line —
cache-enabled cold vs cache-less cold (goal ≤1.2, from 6-8x today) — since it is
specific to the persist-cache path:
```text
scoreboard: cold_geomean=<x> (goal <=0.10; v4 baseline 0.515)
            wide_mem_ratio cold=<x> warm=<x> (goal <=0.50; native <MiB> vs C++ <MiB>)
            persist-local: cache-enabled cold vs cache-less <x> (goal <=1.2)
```

---

## 6. Staged landing order

1. **Increment 0 — disambiguating profile** (§4.0). Decides the order of 2 vs 3.
   No code; a measurement + a one-paragraph finding.
2. **Primary: lazy per-force payload build** (§3.1). Defer encode+BLAKE3 past the
   `KeepInMemory` decision; key any needed lazy encode by value identity. A/B on
   the cache-enabled cold leg; expect the bulk of the win here if increment-0
   confirms the observe tax.
3. **Secondary: write-behind buffer + run-boundary flush** (§3.2-3.3), keeping
   the root cutoff synchronous (§3.4). A/B on the cache-enabled **warm-populate**
   leg (a second cold run against a cache one run behind) where materialization
   fires.
4. **Buffer bounds + optional per-batch atomic-rename** (§3.2/§3.3) — daemon
   residency + crash-atomicity hardening.
5. **Re-measure the full companion**; if cache-enabled cold is within ~1.2x,
   feed the result into the default-cache-root product decision (§8).

## 7. Follow-up increment — the cutoff-hit boolean (deferred from task #14)

Record, per warm sample, whether the eval was answered by a root-cutoff hit vs a
full eval, so a silent cutoff miss cannot masquerade as a warm eval regression.

- Surface a boolean from the eval: the root-cutoff read site is
  `native/root_cutoff.rs` (the `load_root_cutoff`/lookup counterpart to
  `store_root_cutoff` at `:384`); thread a "cutoff hit" flag out through the
  `instantiate` result into `NativeBenchmarkSample` (new
  `#[serde(default)] cutoff_hit: Option<bool>` in
  `crates/aos/src/commands/nix_bench/record.rs`), set in
  `capture_native_sample` (`crates/aos/src/commands/nix_bench.rs`).
- Its own small increment: needs the eval API to report cutoff-hit (a few lines
  of plumbing in aos-nix + aos-core + the record), which is why it was deferred
  from #14. The warm leg already tracks cutoff *health* inherently (a miss shows
  as a warm regression); the boolean makes it unambiguous.

## 8. This gates the default-cache-root product decision

Today `native_cache_root` is off by default (production runs cache-less;
`NixEvalConfig::default()` `native_cache_root=None` at
`crates/aos-core/src/nix/eval.rs:1422`, only set from `AOS_NIX_CACHE`). Turning
it **on by default** — so users get the docs-29/31 persistence + root-cutoff
speedups without opting in — is blocked precisely by this campaign: a
default-on cache that makes every cold eval 6-8x slower is a net regression for
the common single-eval case. Once cache-enabled cold is within ~1.2x of
cache-less, the default-on decision becomes a clear win (small cold tax, large
warm/repeat win) and can be taken with data.

## 9. Increment-0 profile findings (2026-07-12, candidate-b, macOS `sample`)

Measured on this darwin box (release + mimalloc), cache-enabled cold vs
cache-less cold, `nix-bench` native median, plus a `sample` profile of a
true-cold single `nix-diff --attr=pkgs.zlib` (fresh `mktemp` cache, no warm
cycle). Three findings; §0's primary hypothesis holds, §0's write-on-cold
premise is confirmed *correct* (my first read of the profile misattributed it —
see finding 3).

**Finding 1 — pathology confirmed, LARGER than stated, and reframed as
encode-size- not force-count-bound.** Cache-enabled cold: `pkgs.zlib`
80.7 → 1353.7 ms = **16.8x**, `pkgs.openssl` 80.3 → 1418 ms = **17.7x**,
`bench.compute.tak` 16.4 → 34.2 ms = **2.1x**. Warm (root-cutoff hit) healthy:
zlib 24.6 ms, tak 0.56 ms. The tax scales with per-force *value encode size*, not
force count: `tak` forces ~10M tiny ints (cheap encode → 2x), leaf packages force
big derivation values (huge recursive encode+BLAKE3 → 16-18x). **So `tak`
UNDERSTATES the pathology; leaf packages are the real target.** §0's "6-8x" was
conservative.

**Finding 2 — the observe tax dominates (confirms §0/§3.1).** On true cold the
on-CPU cost is BLAKE3 hashing (~364 leaf samples) + recursive payload encode
(`force_payload`/preimage ~118) via `force_cache_payload_for_value`
(`force_persistence.rs:55`), built before the `KeepInMemory` decision and
discarded for most nodes. → §3.1 (defer/memoize the per-force payload build) is
the primary lever.

**Finding 3 — CORRECTED: there is NO cold value-materialization bug; the value
cost model is correct.** My first pass read `indexed_values` write frames on true
cold as per-node value materialization and reported a "cost model admits on
first demand" defect. That was wrong. The value cost model
(`cache/policy.rs`: `MaterializationReuse` gates `decide()` on
`previous_run_demands > 0`, i.e. genuine *cross-run* reuse; `record_current_demand`
only bumps `current_run_demands`, promoted to `previous` by `advance_run` at the
run boundary) correctly returns `KeepInMemory` on a fresh cache, and the profile
confirms the value path (`materialize_persist_forced_expression_payload` /
`materialize_cached_expression_node_value_indexed`) is ~absent on true cold
(0-2 frames). The `node_demand.rs:41-42` "previous RUN" comment is accurate.
**What the ~124 cold write frames actually are: the parse/import artifact cache**
— `materialize_persist_cached_import` (77) + `materialize_parse_artifact_entry_indexed`
(54) + `materialize_file_artifact_indexed` (42) — storing parsed `.nix` imports
and parse artifacts so *warm* runs skip re-parsing. That is the persist cache's
intended job, not a defect, and not gated by the value cost model.

**Revised lever for §3.1.** The plan's stated primary idea — "key the DCG on the
O(1) `value_hash` instead of the full encode" — is **infeasible**: `value_hash()`
is only an O(1) accessor on an already-built `CachedExpressionValue`, and the
hash *is* the BLAKE3 of the encoded payload (`expression_value.rs:336/356-362`,
`DurableBlake3Hash::for_bytes(encode) == value_hash`), so you cannot obtain the
hash without the full recursive encode. The **viable** lever is this plan's own
§3.1 *fallback*: **memoize `force_cache_payload_for_value` by Value identity** so
repeated forces of the same big shared value (rampant in leaf packages) encode
once — parity-safe (same encode result, cached) and memory-bounded (cap against
the 38 MiB budget). The parse/import artifact writes on cold are a real secondary
cost but are expected (they buy the warm-parse speedup); §3.2 write-behind
batching can amortize their open/flock as a follow-up, not a bug fix.

## 10. §3.1 as-built: identity-keyed encode memo — measured NEUTRAL (default-off)

Landed the §3.1 fallback lever: a per-worker, identity-keyed memo of finished
force-cache payloads for heap `List`/`Attrs` aggregates
(`eval_core::force_payload_memo`). A hit skips the recursive re-encode and BLAKE3
of shared substructure. Keyed by `Value::address_identity_bits` — sound only
because Tier-A never moves or reclaims these aggregates within one evaluation
(heap-owner confirmed: permanent lanes grow monotonically; the poppable
worker-closure lane never holds lists/attrs). Cleared at
`advance_persist_eval_cache_run_boundary`; a debug re-encode-compare guard fires
on every hit; the B2 relocation hazard is registered in the payload-identity
audit (`heap/tests/payload_identity.rs`) and the module doc.

**Mechanism proven.** Engagement test
(`observe_payload_memo_serves_repeated_heap_aggregate_encodes`): the second
encode of one heap list is served from the memo (`hits == 1`). All 213
`force_cache` tests plus the engagement test run in debug with the guard active
— transparency holds on every hit.

**Parity GREEN, engaged and default.** zlib + openssl byte `.drv` match across
serial/JIT × cache-on, both `AOS_NIX_OBSERVE_MEMO=1` (engaged) and default
(off). 3078 oracle lib tests + 6 memo/engagement tests green.

**A/B — the memo is roughly noise-level; it is NOT the ~1.2x lever.**
Cold cache-population median (fresh cache dir + process per sample, n=7 unless
noted; darwin, release, `--eval-system x86_64-linux`):

```text
attr           cache-off cold   cache-on cold memoON   cache-on cold memoOFF
pkgs.zlib          78.6 ms           1131 ms                1183 ms
pkgs.openssl       80.7 ms           1150 ms                1171 ms
```

The memo shaves ~2-4% off cold cache-population — inside run-to-run noise
(±5%, outliers to 2.2s). Cache-on cold stays **~14-15x cache-off** with or
without the memo.

**Warm is PRESERVED — 22-26 ms root-cutoff, memo-neutral.** nix-bench emits
separate `benchmarks[]` entries per temperature (`explicit:cold:*` /
`explicit:warm:*`, distinguished by the `temperature` field); the warm entry
reads **23.4 / 23.6 / 26.3 ms** (zlib) — the flagship root-cutoff number,
unchanged, both `memoON` and `memoOFF` (22-26 ms each). The warm path returns
`EvalStats::for_root_cutoff` *without constructing an evaluator*
(`aos-nix native/mod.rs:568-584`), so the observe memo structurally cannot run
on it — warm is memo-independent by construction. (An earlier draft of this
section wrongly reported "warm ≈ cold ≈ 1.15 s / regression"; that was a JSON
extraction bug — reading `benchmarks[0]`, always the *cold* entry, for both
arms. Direct repro confirms the product: two `nix-diff` instantiates sharing one
`AOS_NIX_CACHE` give `root_cutoffs:1` and ~0.25 s total (incl. the ~0.18 s C++
oracle) on the second. No regression.)

**Why so small — decisive.** Finding 2 identified the observe *encode* tax
(BLAKE3 + recursive preimage). This memo removes only the *repeated* encodes of
shared substructure, which is a small fraction of the encode work, itself a
small fraction of the write-dominated cold cost. The ~1050 ms of cache-on cold
overhead is the **synchronous persist write-through** (value/artifact pack
serialization + open/flock/fsync), which the memo does not touch. **§3.2
write-behind batching is the real lever to reach ~1.2x**, exactly as framed:
amortization of the intended writes, not repair.

**Profiling caveat (method).** The increment-0 profile (Finding 2) was
*on-CPU* sampling, which sees the BLAKE3/encode work but NOT the `flock`/`fsync`
off-CPU blocked time of the write-through. The write-through's dominance is
inferred from the wall A/B (cache-on cold vs cache-off cold), not from the
on-CPU profile. The next profiler pass on §3.2 must run **off-CPU** (blocked-time
/ wall-clock sampling) to attribute the open/flock/fsync stalls directly.

**Disposition.** Default-OFF behind `AOS_NIX_OBSERVE_MEMO` (mirrors the
simplifier passes' default-off discipline: a neutral optimization stays off with
its numbers recorded). It is inert in the production cache-less default and in
cache-on unless explicitly opted in. Re-measure and consider default-on once
§3.2 removes the write floor and the encode tax becomes a larger relative share.

## 11. §3.2 increment-0: the cold tax is SYSCALL-bound, in the ARTIFACT path

Before building the write-behind buffer, disambiguated (per §4.0) *where* the
cache-on cold tax goes, with `/usr/bin/time -l` (CPU vs wall) + a cache-tree file
census. Decisive:

**CPU-vs-wall (zlib nix-diff, cache-off vs cache-on cold, n=3, oracle identical
so it cancels in the diff):**

```text
             real     user     sys      cpu(user+sys)
cache-off    0.31 s   0.16 s   0.06 s   0.22 s
cache-on cold 1.60 s  0.42 s   0.91 s   1.33 s
Δ (tax)      1.29 s   0.26 s   0.85 s   1.13 s
```

The tax is **on-CPU** (cpu≈wall, not idle-blocked) and **kernel-dominated:
~0.85 s of the ~1.13 s is SYSTEM time** (syscalls executing), only ~0.26 s is
user (encode/BLAKE3/serialize). This is why §3.1 (a user-space encode memo)
measured neutral and why §3.2 (batch the syscalls) is the lever: the cold cost is
the per-record `open+flock+write+close` churn, not the hashing.

**Located — the PARSE CACHE's 5-files-per-import on-disk layout (verified).**
One zlib cold populate writes **1192 files**, of which **1175 are in `parse/`
and only 15 in `persist/`**. The parse cache stores each import as its own
`parse/<hash>/` dir holding **5 files** — `resolved.bin`, `ir.bin`,
`symbols.bin`, `facts.bin`, `meta.toml` — each written by
`write_cache_file_atomic` (temp-write + `rename`, no fsync) in
`cache/parse/entry.rs:95 write_resolved`. ~234 imports × 5 files ≈ 1175 files ×
(open+write+close+rename) is the syscall churn (`rename` = per-file directory
metadata mutation).

Verified this is the cost, not the persist blob pack, with a controlled A/B
(`AOS_NIX_ROOT_CUTOFF=0`): cold populate (parse WRITES) sys=0.79 s vs warm
parse-HIT (no parse writes, but parse READS all 1175 files during a full eval)
sys=1.17 s — the sys cost tracks the **file count**, not write-vs-read, and does
not collapse when writes are removed. The `persist/` pack (15 files, append-based
with flock+mutex) is a rounding error on cold. My earlier §11 draft and the §9
profile named `materialize_persist_cached_import` / the persist artifact path —
that was the on-CPU *encode* work (the ~0.26 s user), NOT the sys-time file I/O.
The sys is the parse cache.

**This is a COLD-only cost.** Production warm answers from the durable root
cutoff *before constructing an evaluator or consulting the parse cache*
(`native/mod.rs:568-584`), so warm = 23 ms and never touches these 1175 files.
The tax is paid only on the first (cold) eval that populates the caches.

**Refined lever — parse-cache file consolidation, NOT a blob-pack write-behind.**
The plan's §3.2 write-behind-buffer model (append many records to one pack,
flush once) fits the *value* path but NOT the parse cache's dir-per-entry
layout, where there is no shared append target — deferring the writes would not
reduce the file *count*. The lever that cuts the 1175-file syscall churn is to
**consolidate the 5-file artifact set into one bundle file per parse entry**
(`write_resolved` writes one file; `read_artifact_bundle` reads+splits one file;
parse-cache format version bump to invalidate the old 5-file layout). ~5x fewer
files → ~5x less parse-cache sys on both cold-populate and cutoff-off eval.
Parity-critical (the parse cache is a reuse cache; `.drv` must be identical
hit-or-miss) — gated by the byte-parity battery. This is a parse-cache format
change, a deviation from §3.2-as-written; flagged to the lead for a direction
call before building.

## 12. §3.2 as-built: 5→1 bundle LANDED, but cold sys did NOT drop (attribution was wrong)

Built the 5→1 parse-cache bundle (`bundle.bin` per entry via the existing
`ParseArtifactBundle` codec; schema 11→12; single-read warm load). It works and
is clean:
- **File count 1175 → 235** (one `bundle.bin` per import, exactly 5x).
- **Byte-parity GREEN**: zlib + openssl, serial/JIT × cache-on/off (8/8).
- **All tests green**: 3080 oracle lib (+ the known `heap_cheap_memory_advice`
  concurrency flake, passes in isolation); 22 ported parse-cache/persist tests.
- **Durable warm still hits** (`root_cutoffs:1`); the bundle round-trips
  across processes.

**But the cold cache-populate sys did NOT drop.** Measured (zlib, `time -l`):

```text
                          real    user   sys
cold cache-on (1175 files, before)  ~1.6s  0.42s  0.85s
cold cache-on (235 files,  after)   ~1.3s  0.41s  0.75s   <- sys ~flat
cutoff-off warm read (before)       ~1.6s  0.41s  1.17s
cutoff-off warm read (after)        ~1.4s  0.41s  0.83s   <- ~30% better
```

A 5x file reduction bought ~10% cold sys and ~30% warm-read sys — so the parse
cache's file *count* was NOT the dominant cold sys after all. **§11's
"sys tracks file count" attribution was wrong** (the third wrong hypothesis in
this arc: value-path → persist-artifact → parse-file-count). The `time -l` A/B
that motivated §11 (cold-write 0.79 vs warm-read 1.17) mislabeled a per-node
cost as a per-file cost. Controlled knobs ruled out more candidates:
`AOS_NIX_CACHE_VERIFY=0/1` does not move cold sys either.

**What the cold ~0.75s sys actually is: still unpinned, and it needs a real
syscall trace.** It is stable under file-count (5x), verify on/off, and JIT — so
it is something structural in the cache-on eval path touched per node, not per
file. The leading remaining candidate is the per-reconsidered-node
`fs::metadata` stat (plan §2: `lookup_node_metadata`, the one unconditional
per-node disk touch), which would scale with node count (~14k for zlib), not
file count — consistent with the flat response to the 5x file cut. But I have
been wrong three times guessing from indirect signals; **this must be confirmed
with `strace -c` / `dtrace` syscall counts on Linux** (macOS blocks unprivileged
syscall tracing), not another controlled-knob inference.

**Disposition.** The 5→1 bundle LANDS as a footprint + warm-read improvement
(5x fewer inodes matters for a cache holding thousands of packages; warm-read
sys −30%; internally-sectioned format is the extensibility foundation the lead
asked for), NOT as the cold lever it was scoped to be. The cold cache-populate
tax is unchanged and its true driver is unidentified pending a syscall trace.
**Value-path write-behind (§3.2 original) stays deferred-until-measured-need**
(the census shows cold doesn't touch it; warm-materializing runs are the only
candidate beneficiary) — do not rebuild it on momentum.

## 13. Driver IDENTIFIED by strace: the PERSIST cache per-record file storm

The syscall trace §12 called for (run on Linux builder-hil1-87eb5b00, stock
toolchain, `strace -f -c`, cache-on cold zlib minus cache-off control so the
identical oracle cancels) ends the guessing. The cold sys is the **persist
cache**, not the parse cache, doing a per-record file-op storm.

**Syscall count delta (cache-on cold − cache-off):**

```text
statx   1,228 -> 42,774   (+41.5k)
read    1,946 -> 36,077   (+34k)
openat  1,093 -> 27,675   (+26.6k)
close     920 -> 27,501   (+26.6k)
mkdir      ~0 -> 15,211   (+15k, 14,969 = 99% EEXIST)
write     860 ->  9,378   (+8.5k)
flock      ~0 ->  8,539   (+8.5k)
```

Wall is futex-dominated (0.66 s, thread coordination). **Path attribution
(`strace -y`), all in `persist/`, per record:** mkdir `persist/nodes` x7896,
`.locks` x2743, `values` x2083, `files` x1999 (all EEXIST); statx
`persist/nodes` x7895 + `persist/nodes/metadata.index` x7722. The parse cache is
now only 471 mkdir + 235 `bundle.bin` stats — §3.2's bundle DID cut it ~5x; it
was simply never the dominant cache.

Root cause: the persist cache re-ensures its subdir tree (`create_dir_all
persist/{nodes,values,files,.locks}`) and re-stats `persist/nodes` +
`metadata.index` ONCE PER RECORD (~7900 node records for zlib). Two stacked
redundancies. **Fix plan (brought to lead before building):**
1. Hoist the persist subdir ensure to cache-OPEN time — kills ~15k redundant
   EEXIST mkdir, zero behavior change.
2. Memoize the per-record dir + index stat — kills ~15k statx.
3. Buffered per-pack appender (open+flock once, batch, flush at run boundary) —
   the REAL §3.2 write-behind, now correctly aimed at the persist PACK path
   (which is append-based), not the parse cache.

**Lesson: the darwin `time -l` sys/user split cannot attribute; only the Linux
syscall trace resolved it, after three wrong indirect inferences.** Raw
histograms: `~/rfc0007-gate/candb_{on,off}_f.txt` on the builder.

## 14. Decision artifact: cache-enabled vs cache-less (native, post-bundle)

The number that gates the default-cache-root product decision (§8). Native-only
`nix-bench`, `--eval-system x86_64-linux`, median of 3, fresh cache per cycle:

```text
              cache-LESS      cache-ENABLED       ratio
zlib    cold    75.7 ms          995.7 ms       13.2x SLOWER
        warm    76.5 ms           24.0 ms       0.31x (3.2x FASTER)
openssl cold    75.0 ms         1045.6 ms       13.9x SLOWER
        warm    74.3 ms           23.6 ms       0.32x (3.1x FASTER)
```

vs C++ Nix (~185 ms cold): cache-enabled warm 24 ms ~= 7.7x faster; cache-less
cold 75 ms ~= 2.5x faster. (Cache-less warm ~= cold because there is no durable
cache to reuse.)

**Standing recommendation (adopted):** default cache root = **YES for
repeat-eval workflows** — warm 24 ms is ~3x faster than cache-less and ~8x
faster than C++, the flagship number. The one open item is the ~1s first-eval
cold-populate tax (13-14x), whose driver §13 now identifies as the persist
per-record file storm; fixes 1-3 close it. For one-shot evals, cache-off (75 ms)
still wins until that tax is paid down.

## 15. Increment A LANDED + re-strace (persist per-op ensure hoisted)

Removed the 16 redundant per-op `ensure_*_file` (create_dir_all + create-open)
calls from the ratchet-cache index/pack writers (node_metadata, blob_index,
artifact_index, node_trace_log, blob_pack appender), keeping the once-per-open
ensure. Committed 8d77e2dd8. Re-strace on the builder (same method, cache-on
cold zlib), before (§13) vs after:

```text
syscall   before    after     reduction
mkdir     15,211     4,290     -72%
statx     42,774    20,931     -51%
openat    27,675    16,754     -39%
close     27,501    16,580     -40%
flock      8,539     7,524     -12%
futex(s)    0.66      0.27     -59%   (thread coordination — fell with the storm)
```

Total in-syscall time ~0.9s -> ~0.32s (-64%). Post-fix cache-on cold is
wall 0.41s / sys 0.09s (incl. the ~0.18s C++ oracle in the nix-diff). Gates:
ratchet-cache 112 + oracle 3081 + aos-nix 345 tests green; byte-parity
zlib+openssl serial/JIT cache-on/off (8/8); durable warm still root-cutoff hits.
(Also fixed two latent §3.2-bundle test regressions the aos-nix `--lib` suite
surfaced: native hydration tests read the pre-v12 `meta.toml`.)

**Remaining, for Increment B / next:** ~16.7k openat + ~16.6k close are the
per-op append/read RE-OPENS (hold the fd open on each writer -> kills these);
~20.9k statx is dominated by the per-node `metadata.index` `.metadata().len()`
read (cache the index length/handle, or the index content, in memory); ~4.3k
residual mkdir (a create_dir_all still on some path — root_record_io or an
atomic-write temp parent — to hunt). And **futex is still 73% of the traced
time (0.27s)** — once B lands, if it still dominates the cache-on cold delta,
that is the next attribution target (parallel-pool parking / a persist lock),
to be MEASURED not guessed.

### 15.1 Advisory-posture check (Increment A robustness)

Dropping the per-op ensure changes one edge: today a cache dir externally
deleted mid-run silently self-heals (the per-op `create_dir_all` recreates it);
after A, a subsequent append opens the now-missing file and errors. Verified the
advisory contract absorbs this — an append error degrades to a lost cache write,
never an eval error:

- Value/blob materialization: `match persist_cache.materialize_*(...) { Err(e) =>
  { tracing::warn!(...); None } }` (`force_persistence.rs:275-282`); the method
  returns `Option` and its own doc states the operation is advisory (":294").
- Metadata-index append: `record_node_metadata_unlocked -> append_entry` returns
  `Result`, but the only caller is `flush_buffered_node_demands`
  (`run_scope.rs:112`), which every caller wraps in `if let Err(e) { warn }`
  (`cache.rs:103` and `advance_persist_eval_cache_run_boundary`).

So no append error reaches the eval `Result` — same log-and-continue contract the
loss-matrix tested on the network tier. Increment A therefore preserves the
advisory posture; the removed per-op ensure was pure redundancy, not a
self-heal the eval relied on.

## 16. Increment B: hold-fd, scoped to NodeMetadataIndex (pack indexes deferred)

Held the read+append fd open on `NodeMetadataIndex` (c36b5189d) — the dominant
after-A writer (the ~7900 metadata.index + persist/nodes ops). Appends
`O_APPEND` under a `Mutex`, reads `fstat`+seek the same held fd (so same-root
handles still observe each other's appends — a per-handle length cache would
under-count demand across the 16-handle coordination test, deferred to a
shared-per-root increment), compaction reopens after its own rename-over. Gates:
ratchet-cache + oracle tests green (incl. the coordination test), byte-parity
8/8, durable warm hits.

**LANDMINE (recorded so the follow-up starts from the constraint): a writer
whose file can be replaced EXTERNALLY must NOT hold an fd without inode-change
detection.** Replicating hold-fd to `blob_index` / `artifact_index` broke 17
storage-maintenance/repack tests with `RecordHashMismatch`: the repack rebuilds
the values/files pack AND renames a fresh index over the old path from OUTSIDE
the index object (not via its `replace_entries`), so the held fd points at the
unlinked old inode and reads return the stale index → wrong pack offsets. The
per-object compaction-reopen only covers the writer's own rewrite.
`NodeMetadataIndex` is safe precisely because it is only ever rewritten through
its own `replace_entries`. Reverted the pack indexes cleanly (no bug shipped).

**Disposition (lead ruling (b), measure-first):** pack indexes stay at
Increment-A state (per-op open); holding their fd safely needs inode-change
detection (`fstat` st_dev/st_ino per read, reopen on change — which re-adds a
cheap `fstat`) or a repack-flow change to refresh the live handle. Both are
gated on whether the post-B re-strace shows their residual opens (values/files
`index.blob` ~1k stats + their appends) are worth it. The shared-per-root
length statx-kill remains its own measure-gated increment too.

### 16.1 Part-1 re-strace + the cache ratio (builder, c36b5189d, default features)

Strace (cache-on cold zlib) vs after-A, and the whole A+B1 ladder vs the
original storm:

```text
syscall   original   after-A    after-B1(part1)   A+B1 total
openat     27,675    16,754      9,352            -66%
close      27,501    16,580      9,178            -67%
mkdir      15,211     4,290      4,290            -72%
statx      42,774    20,931     20,936            -51% (fstat-on-held-fd kept)
futex(s)     0.66      0.27       0.285
```

Part 1 killed the metadata index's ~7,400 per-op opens (openat/close each -44%);
statx is unchanged by design (NodeMetadataIndex keeps a per-read `fstat` for
same-root coordination).

**Cache-enabled vs cache-less (native-only nix-bench on the Linux builder,
median of 3):**

```text
                cache-LESS   cache-ENABLED   ratio
zlib cold        63.9 ms      312.0 ms       4.9x SLOWER
zlib warm        62.1 ms        6.6 ms       0.10x (9-10x FASTER)
```

**This is the headline: cache-enabled cold is now ~4.9x cache-less, down from the
~13x-class before this campaign** (the pre-A §14 table was 13.2x on darwin;
this is Linux, so the OS baselines differ, but the syscall-storm reductions cut
the cold cache-populate roughly 3x). Warm 6.6 ms is ~10x faster than cache-less
cold and ~28x faster than C++ Nix. The ~1.2x default-cache-root gate is not yet
met (4.9x), and the remaining cache-on-cold cost is the synchronous
write-through (write 9.4k + flock 7.5k), the futex (thread coordination), and
the residual pack-index opens — the candidates for the next measure-gated
increments (§3.2(b) write-behind, the shared-per-root statx-kill, and the
pack-index hold-fd with inode detection).

### 16.2 Harness lesson: strace `-c` %time double-counts blocked threads

The futex attribution (strace `-f -e trace=futex -k`, cache-on cold zlib) showed
only **152 futex calls total**, with stacks in thread-start / the tokio blocking
pool / minor `Mutex::lock_contended`. The "futex = 0.285s = 77% of traced time"
in the `strace -c` summary is **blocked time on parked-idle threads summed across
parallel waiters** — the tokio pool and finished eval workers park while the main
thread does the serial persist writes. It is a *symptom* of the persist-write
duration, not an independent cost; shrinking the write-through shrinks it.

**Lesson: `strace -c` %time sums blocked time across threads, so a parked-idle
futex reads as huge — attribute with `-k` stacks (or off-CPU perf) before
believing it.** Don't chase a futex `%time` as a lever without the stacks.
