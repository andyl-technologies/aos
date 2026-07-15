# Instruction-Bloat Attribution: Per-Symbol Profiles + Per-Op Budgets

Status: MEASUREMENT-FIRST. Tooling landed (`AOS_NIX_BENCH_COLD_ONLY`); the
per-op budget tables and the uniform-vs-amplifier verdict are gated on the
builder perf runs designed in §3. Lead runs the commands; this note holds the
methodology, the exact commands, and the analysis framework to fill on return.

## 1. The finding that reopened the game

`perf stat` on the cold toplevel shows the 5x wall gap is **instruction count**,
not stalls, at **equal IPC**:

- C++ Nix: **6.24e9** instructions @ IPC **2.83** for the whole toplevel.
- Us: **99e9** instructions @ IPC **2.51** for the bench process (~**30e9 per
  cold eval**).
- **Op counts match** (counter-diff verified): same number of function calls,
  thunks, values. So we execute **~2000-2500 instructions per op vs C++'s
  ~500**, at essentially equal IPC.

This is why **every cycle-profile was flat** (RFC-0007 perf campaign, no entry
>8.1%): uniform per-op instruction bloat is invisible to cycle sampling — if
every op costs 4-5x its instructions uniformly, no single symbol stands out in a
cycle profile, because cycles track the *stall* structure, not the *instruction*
structure. The right lens is a **retired-instruction** profile and a **per-op
instruction budget**, which this note builds.

The prize: closing a 5x instruction gap at equal IPC is a ~5x wall win — the
entire toplevel-parity target — and unlike the JIT (ruled out for the toplevel
in `jit-fuse-shapes-economics.md`), a per-op instruction reduction attacks the
flat long tail directly, which is exactly where the mass is.

## 2. The two questions, and the metrics that answer them

**Q1 (localization): which code is instruction-dense?** A symbol is
instruction-dense when its share of retired instructions **exceeds** its share of
cycles (`instr% > cycle%`, i.e. low CPI — many cheap instructions); it is
stall-y when `cycle% > instr%`. Ranking symbols by `instr% − cycle%` (or the
ratio) localizes the bloat to specific functions. A cycle profile alone cannot
do this; we need both events and a per-symbol join.

**Q2 (Dylan's — uniform or amplified?): is per-op instruction count uniform
across shapes, or does the toplevel have a shape-specific amplifier?** Compute
`instructions_per_op = clean_cold_instructions / cold_ops` for three contrasting
workloads:

- **`attr-fixpoint`** (`tests/bench/compute.nix`) — the module-ish shape: a
  `fix` + `extends` overlay chain with a quadratic `//` merge, deep-ish env, but
  **no imports, no derivations, no store I/O**.
- **`pkgs.zlib`** — a single real package: moderate env depth, a derivation, some
  imports.
- **toplevel** (`system.build.toplevel`) — deep module fixpoint, huge env, ~459
  imports, derivation machinery.

Decision rule:

- toplevel per-op ≈ zlib per-op ≈ attr-fixpoint per-op → **uniform bloat**;
  attack globally (the per-op interpreter tax lives in the shared force/apply/
  var-resolve/validation layers — see the per-op instruction-tax ledger,
  task #22).
- toplevel per-op is **2-3x** zlib/attr-fixpoint per-op → a **shape amplifier**
  scaling with env depth / select-chain length / import machinery is the target
  (env-depth histograms, task #23). The `attr-fixpoint`-vs-`zlib` contrast
  isolates the fixpoint/env shape from the import/derivation machinery: if
  `attr-fixpoint` per-op ≈ toplevel per-op, the amplifier is the fixpoint/env
  shape itself; if `attr-fixpoint` ≈ zlib (low) while toplevel is high, the
  amplifier is import/derivation/module machinery.

## 3. Run commands (lead executes on the builder)

### 3.0 The clean-cold instrument: `AOS_NIX_BENCH_COLD_ONLY`

`AOS_NIX_BENCH_COLD_ONLY=1 aos nix-bench` (landed this commit) runs **exactly one
isolated native-only cold eval per `-A` attribute** — no C++ oracle, no warm
re-instantiate, no parity gate, no history. So a `perf stat` wrapping the process
counts **one cold eval's** retired instructions (plus fixed process startup),
with **no C++ subprocess** polluting the count. It prints one greppable line per
attr: `aos_nix_cold_only {"attr":…,"drv":…,"wall_ns":…}`. `-A` is required (this
path builds no oracle, so it cannot discover attributes).

`--eval-system` and `--impure-eval` are **global** flags — put them before the
subcommand. All commands assume `x86_64-linux`.

### 3.1 Per-op instruction budget (native, clean cold) — the Q2 table

Run **two** processes per workload; the instruction numerator comes from the
CLEAN run (no `AOS_NIX_EVAL_STATS`, which would add the census's ~742 ns/force
bookkeeping *instructions* to the count), the op denominator from the STATS run
(same deterministic cold eval, so the op counts are identical):

```text
# (a) CLEAN instruction + cycle count for one cold eval:
perf stat -e instructions:u,cycles:u -- \
  env AOS_NIX_BENCH_COLD_ONLY=1 aos --eval-system x86_64-linux --impure-eval \
      nix-bench -A pkgs.zlib

# (b) op counters + force-shape census for the SAME cold eval:
AOS_NIX_EVAL_STATS=1 AOS_NIX_BENCH_COLD_ONLY=1 \
  aos --eval-system x86_64-linux --impure-eval nix-bench -A pkgs.zlib \
  2>&1 | grep -E 'aos_nix_eval_stats|aos_nix_force_shape_census'
```

Repeat both for: `-A attr-fixpoint --file tests/bench/compute.nix`,
`-A pkgs.zlib`, and the toplevel attribute
`-A systems.<system-name>.build.toplevel` (the same attr the census run used;
the harness derives it as `systems.${name}.build.toplevel` over the default
`default.nix`). Also grab two more compute shapes for range: `-A fib` and
`-A lambda-interp` (`--file tests/bench/compute.nix`).

Per-op budget = `instructions (a) / function_calls (b)`. Report `function_calls`
as the primary op (cross-comparable to C++ `nrFunctionCalls`); also compute
against `thunks_forced` and `values_allocated` as secondary denominators, and
per-op against the census `total_forces`.

### 3.2 Per-symbol density profile (native) — the Q1 ranking

Two records per workload (one instructions, one cycles), same cold-only command:

```text
perf record -o zlib.insns.data -e instructions:u -g -- \
  env AOS_NIX_BENCH_COLD_ONLY=1 aos --eval-system x86_64-linux --impure-eval nix-bench -A pkgs.zlib
perf record -o zlib.cycles.data -e cycles:u -g -- \
  env AOS_NIX_BENCH_COLD_ONLY=1 aos --eval-system x86_64-linux --impure-eval nix-bench -A pkgs.zlib

perf report -i zlib.insns.data  --stdio -n --percent-limit 0.5 --sort symbol > zlib.insns.report
perf report -i zlib.cycles.data --stdio -n --percent-limit 0.5 --sort symbol > zlib.cycles.report
```

Send both `.report` files (toplevel + zlib + attr-fixpoint). I join by symbol and
rank by `instr% − cycle%` to produce the instruction-density table. (If a single
grouped record is preferred: `perf record -e '{instructions:u,cycles:u}:S' …`
then `perf report --group`.)

### 3.3 C++ per-op budget (zlib, toplevel) — the comparison

`nix-instantiate` is a separate process, directly comparable to cold-only
(both parse + eval + write the `.drv`):

```text
NIX_SHOW_STATS=1 NIX_SHOW_STATS_PATH=/tmp/cxx-zlib.json \
  perf stat -e instructions:u,cycles:u -- \
  nix-instantiate <default.nix> -A zlib --eval-system x86_64-linux
```

C++ per-op = `instructions / nrFunctionCalls` (from `/tmp/cxx-zlib.json`). Repeat
for the toplevel attr. This anchors our per-op budgets against the ~500
instructions/op target.

## 4. Analysis tables to fill (on data return)

**T1 — Per-op instruction budget (the Q2 verdict).**

| workload | instructions (clean cold) | function_calls | **insns/call** | vs zlib | vs C++ |
|---|---|---|---|---|---|
| attr-fixpoint | | | | | (n/a) |
| fib | | | | | (n/a) |
| lambda-interp | | | | | (n/a) |
| pkgs.zlib | | | | 1.00 | |
| toplevel | | | | | |
| C++ zlib | | | ~500? | | 1.00 |
| C++ toplevel | | | ~500? | | |

Verdict cell: toplevel÷zlib ratio. ≈1 → uniform (attack the shared per-op tax,
task #22); ≥2 → amplifier (attack the env-depth/import shape, task #23), and the
attr-fixpoint row says which amplifier.

**T2 — Instruction-density ranking (the Q1 localization).** Per symbol: `instr%`,
`cycle%`, `instr% − cycle%`, CPI. Top instruction-dense symbols are the global
per-op-tax targets; the toplevel-minus-zlib delta in a symbol's `instr%` localizes
any amplifier to specific code.

**T3 — Cross-workload symbol delta.** For the amplifier hypothesis: symbols whose
`instr%` rises sharply from zlib→toplevel are the amplifier's home (expect
env-walk / select-IC / import-resolve / attrset-merge functions if the amplifier
is real).

## 5. Notes / caveats

- **Do not read the instruction numerator from an `AOS_NIX_EVAL_STATS` run** —
  the census + eval-stats bookkeeping executes real instructions (~742 ns/force
  of work) that inflate the count. Numerator = clean run; denominator (ops) =
  stats run; the cold eval is deterministic so the op counts transfer.
- **Process-startup floor.** cold-only still pays `aos` process startup. Measure
  it once (`perf stat -e instructions:u -- env AOS_NIX_BENCH_COLD_ONLY=1 aos
  --eval-system x86_64-linux --impure-eval nix-bench -A '<trivial attr>'`, e.g. a
  literal-returning attr) and subtract, or note it's small vs ~30e9.
- **DSO-filter fallback (no tooling).** If a full `aos nix-bench` run is used
  instead of cold-only, `perf report --sort dso,symbol` separates our binary's
  instructions from `libexpr`/`nix-instantiate`, so native-vs-C++ can be split
  from one record — but it mixes cold+warm evals, so use cold-only for clean
  per-op *budgets* and reserve the DSO split for a quick native/C++ ratio.
- IPC is already known equal (2.5 vs 2.8); the campaign is about the instruction
  *count*, so the instructions:u event is the load-bearing one. Cycles are
  recorded only to compute per-symbol CPI for the Q1 density split.
