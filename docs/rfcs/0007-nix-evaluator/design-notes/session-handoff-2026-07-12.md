# RFC-0007 session handoff — 2026-07-12 (Claude → Codex)

This session ran a multi-agent implementation-and-design campaign on
`worktree-rfc-0007-nix-evaluator` and pauses at a clean implementation
boundary. Everything below is pushed to origin.

## Ground truth (re-anchored this session)

- **Full-corpus byte-parity: GREEN.** `nix-diff --all --mode byte` on
  builder-hil1-87eb5b00 at d33ef0a8f vs pinned C++ Nix 2.24.12:
  **546/546 "drv diff matched", EXIT=0.** JIT-on subset 7/7 byte-matched
  (zlib, openssl, linux, firecracker, edk2, envoy, bazel). Corroborated by a
  15/16 independent native+JIT spot-check (the 16th = IFD build timeout, not
  a divergence).
- Ops lesson: run builder gates detached in **tmux with a builder-local
  log** (`~/rfc0007-gate/gate.log`), never over a held-open ssh — a killed
  reader deadlocks the writer on a full pipe.

## Code landed this session (each parity-gated, pushed)

1. `4c734cac4` ratchet-runtime-ffi: Candidate-B/C native returns decode
   through the receiving heap + first one-word env helper (finished the
   paused engineer's in-flight diff).
2. `7d56277d1` aos: **mimalloc as global allocator** (default feature).
   Load-controlled A/B: −12.4% median native single-pkg, −14.6% wide-warm,
   ~−40..58% wide-cold. Memory: wide-cold 1.83× C++ (under target);
   wide-warm 2.45× (documented exception; on Linux
   `MIMALLOC_PURGE_DELAY=0` is the RSS recovery lever — macOS purge is
   MADV_FREE and does not lower RSS). Known flake since landing:
   `heap_cheap_memory_advice` under full-suite concurrency (passes alone).
3. `4a11ea299` + `ef0d02d95` ratchet-core: **simplifier stage-1 fixpoint
   driver skeleton** (Gentle/Main/Final phases, SimplifyPass trait,
   MAX_ITERS=4, empty pass set = proven byte-identity, wired at the
   lowering→persist seam behind `AOS_NIX_SIMPLIFY`, PASS_SET_VERSION=0
   fingerprint-neutral, zero net dependency change).
4. `c3a02187d` ratchet-oracle: **S0 instrumentation** — front-end
   parse/resolve/lower/annotate timers + prelude-force counters behind
   `AOS_NIX_EVAL_STATS`, parity-neutral off AND on.
5. `60020af07` + `7ef7d26d7` aos: **nix-bench v4 paired-cycle temperature
   semantics** — true cold (fresh evaluator per cycle, base cache posture
   preserved), warm = second run of the same cycle,
   `temperature_semantics` in the regression comparison key, medians,
   doc 15 updated (+ `7c81dea63` canonical 17-attr suite definition,
   `a83568bb8` persist write-cost floor recorded). The fix `7ef7d26d7`
   matters: forcing a cache root silently enables the whole persistence
   stack — per-force write amplification made tak 158s vs ~2s cache-less
   (~10M forces); that number is the memo-economics "static cost floor"
   datum. Production default is cache-less (`AOS_NIX_CACHE` unset).

## Measurements that gate the next campaigns (from S0, recorded on tasks)

- **Parse/lower = 24.6% (zlib) / 22.4% (openjdk) of cold wall** → the
  parallel front-end (task #3 S1–S6) is worth its ceiling.
- **Prelude-force share: zlib 62.9% count / 38.8% inclusive-nanos; openjdk
  85.0% / 44.8%** (floor ~39–45%, ceiling 63–85%, grows with eval size) →
  **heap-snapshot gate PASSES (GO)**.
- **Honest v4 baseline vs C++ Nix 2.24.5** (paired cycles, default
  cache-less config, JIT on, 3 cycles, at 7ef7d26d7; parity green):
  - 17-package suite: **geomean 0.515× ≈ 1.9× faster cold**; true cold
    zlib 97.6ms vs C++ 184.9ms; range 0.41–0.61× across all 17.
  - Compute suite splits: JIT-hot shapes fib/tak/sum-fold **0.035–0.041×
    (~25× faster)**; JIT-gap shapes lambda-interp 8.9×, hash-loop 3.0×,
    string-builder 2.2× SLOWER — the attrset-building-body gap the tier-2
    memos predicted, now visible in the standing baseline.
  - **Warm ≈ cold under the default config** — stock `aos` has no durable
    cache, so a repeat eval re-does everything.
  - **Cache-enabled companion** (9 leaf attrs, `AOS_NIX_CACHE` set, fresh
    cache per cycle): warm = **23–35ms (root-cutoff repeat, ~8× faster
    than C++ and ~49× faster than its own cold)** — but cold pays
    **1.1–1.5s (6.2–7.7× slower than C++)** in synchronous cache-population
    write-through. **Product decision for Codex/lead: a default cache root
    is clearly valuable for repeat evals, but the first-eval write
    amplification must be reduced first** (batched/deferred persist writes
    — the memo docs' phasing anticipated this; the tak datum above sizes
    the per-force floor).
  - Historical note: the pre-v4 "cold" numbers (~90ms-class) turn out to
    have been nearly honest for packages (in-process instantiate carries
    little reusable state between calls); the scare numbers during v4
    bring-up (1.3–1.9s colds, 158s tak) were the forced-cache-root
    write-through, fixed in 7ef7d26d7. Old suite tables (0.44×/0.37×
    geomeans) remain roughly comparable in spirit but are schema-guarded
    from silent comparison.

## The four implementation campaigns, specced and ruled — resume from these

All in `docs/rfcs/0007-nix-evaluator/design-notes/`, each with lead rulings
recorded inline (no open decisions unless marked):

1. **simplifier-implementation-plan.md** (+ §8 decisions) — task #7.
   Frontier: skeleton landed (ef0d02d95). Next: arena set_node primitive →
   REQUIRED currentSystem effect member → golden-IR harness → constant
   folding → case-of-known → inlining → dead-binding-as-value-elision.
   Bump PASS_SET_VERSION when the first pass goes default-on.
2. **candidate-c-cutover-plan.md** (+ §6.1 decisions) — task #12.
   Verdict: big-bang at the carrier, staged everywhere else (S0–S5).
   Rulings: compile-time `candidate_c_value` VARIANT (battery on BOTH
   carriers until the winner is kept); S4 flips with JIT OFF; S3 = second
   one-word stack-map geometry selected by JitValueAbi, NOT an edit of the
   two-word path.
3. **heap-snapshot-implementation-plan.md** (+ §9 decisions) — task #6.
   Gate PASSED (above). Sole blocker: #12 (address-free images via
   compressed indices; rebase-on-load variant REJECTED). Boundary: force a
   designated prelude root set (natural boundary is mostly-unforced thunks).
4. **parallel-frontend-implementation-plan.md** (+ Appendix A) — task #3.
   S0 landed. S1–S6 are the spec; key finding: the package set is wired via
   readDir + computed callPackage paths, so speculation must key on ANY
   path-literal IR node, and readDir-driven prefetch (S6) is first-class.

## Task board (authoritative state in the session task list)

- Done: #1 #2 #4 #10 #11 #13 (+#5's allocator item, #14 pending fv5)
- Handoff: #3 (S1–S6), #5 remainder (fat-LTO A/B, PGO impl, hashing
  multi-buffer/merkle, VFS manifest, store-validity filter), #6 (behind
  #12), #7 (passes), #8 (P7, after #7 makes bodies profitable), #9 (~80
  over-cap file splits, pre-existing red gate), #12 (S0–S5), #14 follow-ups
  if any.

## Known warts / honesty items

- aos-nix `tests/source_file_size.rs` is red on clean HEAD (~80 offenders
  since the cap extended to ratchet-*; task #9). Ignore only that failure.
- `heap_cheap_memory_advice` mimalloc-timing flake (task #5 metadata).
- Old bench history (pre-#14) cold numbers are in-process-warm-contaminated;
  the `temperature_semantics` key prevents silent cross-comparison.
- Tree is not rustfmt-clean and no fmt gate exists; safety-manifest token
  counts require hand-formatting — do not run blanket `cargo fmt`.
- OPS: never `git add -A` in this worktree (build dirs); pathspec-only.

## Appendix: v4 honest baseline tables (2026-07-12, darwin, JIT on, 3 paired cycles)

### Headline — default (cache-less) config
```text
pkgs.zlib                    cold     97.6ms /  184.9ms =  0.528x  warm    96.51ms
pkgs.xz                      cold     94.3ms /  185.9ms =  0.508x  warm    96.32ms
pkgs.bzip2                   cold     95.4ms /  172.8ms =  0.552x  warm    95.58ms
pkgs.openssl                 cold     98.8ms /  241.0ms =  0.410x  warm    98.87ms
pkgs.curl                    cold    106.9ms /  205.0ms =  0.522x  warm   103.62ms
pkgs.sqlite                  cold     98.8ms /  180.7ms =  0.547x  warm    97.28ms
pkgs.jq                      cold    103.0ms /  195.3ms =  0.527x  warm    99.74ms
pkgs.socat                   cold    102.9ms /  196.7ms =  0.523x  warm   103.68ms
pkgs.git                     cold    118.7ms /  194.5ms =  0.610x  warm   115.75ms
stdenv.stdenv                cold     86.3ms /  165.0ms =  0.523x  warm    86.32ms
stdenv.bash                  cold     79.6ms /  179.8ms =  0.443x  warm    79.95ms
stdenv.coreutils             cold     82.2ms /  181.0ms =  0.454x  warm    81.20ms
pkgs.gcc                     cold     85.2ms /  166.8ms =  0.511x  warm    84.92ms
pkgs.glibc                   cold     91.3ms /  208.2ms =  0.439x  warm    89.58ms
pkgs.binutils                cold     88.8ms /  174.0ms =  0.510x  warm    85.87ms
pkgs.rust                    cold    135.7ms /  221.7ms =  0.612x  warm   133.53ms
pkgs.openjdk                 cold    150.3ms /  259.3ms =  0.580x  warm   153.81ms
bench.compute.fib            cold      8.0ms /  207.2ms =  0.039x  warm     7.99ms
bench.compute.tak            cold     19.0ms /  468.3ms =  0.041x  warm    20.33ms
bench.compute.sum-fold       cold     18.8ms /  541.2ms =  0.035x  warm    18.00ms
bench.compute.qsort          cold    882.1ms /  453.2ms =  1.946x  warm   918.74ms
bench.compute.string-builder cold   1068.5ms /  483.1ms =  2.212x  warm  1095.58ms
bench.compute.attr-fixpoint  cold    502.8ms /  277.7ms =  1.811x  warm   493.62ms
bench.compute.lambda-interp  cold   5945.3ms /  668.0ms =  8.900x  warm  5816.85ms
bench.compute.hash-loop      cold   1986.9ms /  658.2ms =  3.019x  warm  1985.22ms
bench.compute.all-any        cold    234.1ms /  217.5ms =  1.076x  warm   233.83ms
GEOMEAN=0.547 n=26
parity_green: True
```

### Companion — cache-enabled (AOS_NIX_CACHE), 9 leaf attrs
```text
pkgs.zlib      cold  1170.2ms (6.86x of C++)  warm   23.72ms  cold/warm  49.3x
pkgs.xz        cold  1214.4ms (6.61x of C++)  warm   24.43ms  cold/warm  49.7x
pkgs.bzip2     cold  1202.2ms (6.63x of C++)  warm   24.75ms  cold/warm  48.6x
pkgs.openssl   cold  1172.5ms (6.20x of C++)  warm   23.97ms  cold/warm  48.9x
pkgs.curl      cold  1394.1ms (7.43x of C++)  warm   35.43ms  cold/warm  39.3x
pkgs.sqlite    cold  1095.8ms (5.75x of C++)  warm   23.24ms  cold/warm  47.1x
pkgs.jq        cold  1269.2ms (6.90x of C++)  warm   25.93ms  cold/warm  49.0x
pkgs.socat     cold  1255.1ms (7.41x of C++)  warm   25.22ms  cold/warm  49.8x
pkgs.git       cold  1509.7ms (7.72x of C++)  warm   25.86ms  cold/warm  58.4x
```
