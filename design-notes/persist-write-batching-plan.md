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
